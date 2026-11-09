import path from "node:path";
import { app, clipboard } from "electron";
import { z } from "zod";
import type { ApiLogEntry, DebugInfo, HealthCheck, Result, TunnelStatus } from "../../../shared/core/contract";
import { DEBUG_IPC } from "../../../shared/core/debug-ipc";
import { ApiError, type ApiRequestRecord } from "../api/client";
import { BUILD_TIME, FLAVOR, IDENTITY } from "../flavor";
import type { HandleFn } from "../ipc";
import type { Store } from "../store";
import { codeOf, messageOf, type VpnController } from "../vpn";
import { redact, redactValue } from "./redact";

const MAX_LOG_ENTRIES = 200;

export function registerDebugIpc(
  handle: HandleFn,
  deps: {
    store: Store;
    vpn: VpnController;
    openDevTools: () => void;
    onReset: () => void;
  },
): void {
  const { store, vpn } = deps;
  const log: ApiLogEntry[] = [];
  let nextId = 1;
  let verbose = false;
  let lastPhase: TunnelStatus["phase"] | null = null;

  vpn.api.onRequest = (record: ApiRequestRecord) => {
    const entry: ApiLogEntry = { id: nextId++, at: Date.now(), ...record, route: redact(record.route) };
    log.push(entry);
    if (log.length > MAX_LOG_ENTRIES) log.splice(0, log.length - MAX_LOG_ENTRIES);
    if (verbose) {
      console.log(`[mantel:api] ${entry.method} ${entry.route} → ${entry.status ?? "–"} ${entry.durationMs} ms${entry.code ? ` (${entry.code}${entry.apiCode ? `/${entry.apiCode}` : ""})` : ""}`);
    }
  };

  vpn.on("status", (status: TunnelStatus) => {
    if (!verbose || status.phase === lastPhase) return;
    lastPhase = status.phase;
    console.log(`[mantel:tunnel] ${status.phase} service=${status.serviceState ?? "–"} node=${status.nodeId ?? "–"} firewall=${status.firewallActive}`);
  });

  const info = async (): Promise<DebugInfo> => ({
    flavor: FLAVOR,
    productName: IDENTITY.productName,
    appId: IDENTITY.appUserModelId,
    appVersion: app.getVersion(),
    electron: process.versions.electron ?? "",
    chrome: process.versions.chrome ?? "",
    node: process.versions.node,
    v8: process.versions.v8,
    platform: process.platform,
    arch: process.arch,
    buildTime: BUILD_TIME,
    commit: null,
    packaged: app.isPackaged,
    elevated: await vpn.isElevated(),
    baseUrl: vpn.apiBaseUrl(),
    userData:
      process.platform === "darwin"
        ? `~/Library/Application Support/${path.basename(app.getPath("userData"))}`
        : `%APPDATA%\\${path.basename(app.getPath("userData"))}`,
    ...vpn.platform.debugNames,
    verbose,
    loggedIn: vpn.session().loggedIn,
  });

  handle(DEBUG_IPC.info, 0, () => info());

  handle(DEBUG_IPC.requestLog, 0, () => log.map((entry) => ({ ...entry })));

  handle(DEBUG_IPC.clearRequestLog, 0, () => {
    log.length = 0;
  });

  handle(DEBUG_IPC.healthCheck, 0, async (): Promise<HealthCheck> => {
    const started = performance.now();
    const baseUrl = vpn.apiBaseUrl();
    try {
      const nodes = await vpn.api.nodes();
      return { baseUrl, ok: true, status: 200, latencyMs: Math.round(performance.now() - started), nodes: nodes.length, error: null, checkedAt: Date.now() };
    } catch (error) {
      return {
        baseUrl,
        ok: false,
        status: error instanceof ApiError ? error.status : null,
        latencyMs: Math.round(performance.now() - started),
        nodes: null,
        error: redact(messageOf(error)),
        checkedAt: Date.now(),
      };
    }
  });

  handle(DEBUG_IPC.setVerbose, 1, async (_event, enabled) => {
    const parsed = z.boolean().safeParse(enabled);
    if (parsed.success) {
      verbose = parsed.data;
      lastPhase = null;
      console.log(`[mantel:debug] verbose logging ${verbose ? "on" : "off"}`);
    }
    return info();
  });

  handle(DEBUG_IPC.copyDiagnostics, 0, async (): Promise<Result<string>> => {
    try {
      const preferences = store.getPreferences();
      const wireguard = vpn.wireguard();
      const diagnostics = {
        generatedAt: new Date().toISOString(),
        build: await info(),
        preferences: {
          baseUrl: preferences.baseUrl,
          alwaysOnKillSwitch: preferences.alwaysOnKillSwitch,
          lastNodeId: preferences.lastNodeId,
          language: preferences.language ?? "system",
        },
        wireguard: wireguard ? { source: wireguard.source, directory: wireguard.directory } : null,
        encryptionAvailable: store.encryptionAvailable,
        device: store.getSecrets().device ? { nodeId: store.getSecrets().device?.nodeId, keySource: store.getSecrets().device?.keySource } : null,
        tunnel: vpn.getStatus(),
        requestLog: log,
      };
      const text = redact(JSON.stringify(redactValue(diagnostics), null, 2));
      clipboard.writeText(text);
      return { ok: true, value: text };
    } catch (error) {
      return { ok: false, error: messageOf(error), code: codeOf(error) };
    }
  });

  handle(DEBUG_IPC.resetLocalData, 0, async (): Promise<Result<null>> => {
    await vpn.logout().catch(() => undefined);
    if (store.getPreferences().alwaysOnKillSwitch || vpn.getStatus().firewallActive) {
      try {
        await vpn.emergencyDisableKillSwitch();
      } catch (error) {
        return { ok: false, error: messageOf(error), code: codeOf(error) };
      }
    }
    store.resetLocalData();
    log.length = 0;
    deps.onReset();
    return { ok: true, value: null };
  });

  handle(DEBUG_IPC.openDevTools, 0, () => {
    deps.openDevTools();
  });
}
