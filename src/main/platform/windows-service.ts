import { spawn } from "node:child_process";
import path from "node:path";
import { LocalizedError } from "../../../shared/core/i18n";
import { FLAVOR, IDENTITY } from "../flavor";
import { FIREWALL_GROUP } from "../firewall/rules";
import { readWindowsWifi } from "../net/wifi";
import { tunnelDial } from "../pq/exchange";
import { REAL_CLOCK } from "../pq/flow";
import { singleFlight, waitUntil } from "../poll-schedule";
import type { WireGuardPaths } from "../system/environment";
import { POWERSHELL, run } from "../system/exec";
import { VpnError } from "../vpn-error";
import { serviceRelay } from "../obfs/relay";
import { HelperCommandError, helperClient, HelperUnavailableError, responseSchema, type HelperCall, type HelperResponse } from "./macos/helper-client";
import { HelperWireGuardControl, interfaceStatusOf, pqFailureForUser } from "./macos/index";
import type { ServiceQuery, TunnelPlatform } from "./types";
import type { ServiceState } from "../wireguard/parse";

export const SERVICE_PROTOCOL = 1;
export const SERVICE =
  FLAVOR === "debug"
    ? { name: "MantelServiceDebug", pipe: "\\\\.\\pipe\\mantel-service-debug" }
    : { name: "MantelService", pipe: "\\\\.\\pipe\\mantel-service" };

export type ServicePlatformOptions = {
  repair: () => Promise<void>;
  serviceExe?: string;
  call?: HelperCall;
};

export function verifiedCall(serviceExe: string, direct: HelperCall, header: Record<string, unknown>, timeoutMs = 180_000): HelperCall {
  return (request, payload) => {
    if (!payload) return direct(request);
    return new Promise((resolve, reject) => {
      const line = Buffer.from(`${JSON.stringify({ ...header, ...request, payloadLength: payload.length })}\n`, "utf8");
      const input = Buffer.concat([line, payload]);
      payload.fill(0);
      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(serviceExe, ["service", "call"], { windowsHide: true, shell: false, stdio: ["pipe", "pipe", "pipe"] });
      } catch (error) {
        input.fill(0);
        reject(new HelperUnavailableError(error instanceof Error ? error.message : String(error)));
        return;
      }
      const timer = setTimeout(() => child.kill(), timeoutMs);
      const out: Buffer[] = [];
      child.stdout!.on("data", (chunk: Buffer) => out.push(chunk));
      child.once("error", (error) => {
        clearTimeout(timer);
        reject(new HelperUnavailableError(error.message));
      });
      child.once("close", () => {
        clearTimeout(timer);
        const text = Buffer.concat(out).toString("utf8");
        let parsed: HelperResponse;
        try {
          parsed = responseSchema.parse(JSON.parse(text.slice(0, text.indexOf("\n"))));
        } catch {
          return reject(new HelperUnavailableError("no answer from mantel.exe service call"));
        }
        if (parsed.ok) return resolve(parsed);
        if (parsed.error === "forbidden") return reject(new HelperUnavailableError(parsed.detail ?? "forbidden"));
        reject(new HelperCommandError(parsed.error ?? "system", parsed.detail ?? ""));
      });
      child.stdin!.end(input, () => input.fill(0));
    });
  };
}

function serviceFailure(error: unknown): unknown {
  if (error instanceof HelperUnavailableError) return new VpnError("helperUnavailable", "elevation");
  if (error instanceof HelperCommandError) {
    if (error.code === "wireguard_missing" || error.code === "wireguardMissing") return new VpnError("wireguardMissing", "wireguard_missing");
    return new LocalizedError("helperCommand", { details: `${error.code}: ${error.detail}`.slice(0, 400) });
  }
  return error;
}

async function guarded<T>(task: () => Promise<T>): Promise<T> {
  try {
    return await task();
  } catch (error) {
    throw serviceFailure(error);
  }
}

export function windowsServicePlatform(options: ServicePlatformOptions): TunnelPlatform {
  const header = { v: SERVICE_PROTOCOL, client: "app" };
  const call =
    options.call ??
    verifiedCall(options.serviceExe ?? "", helperClient(SERVICE.pipe, 180_000, header), header);
  let ready = false;
  let checkedAt = 0;
  let paths: WireGuardPaths | null = null;
  let lastStatus: { at: number; response: HelperResponse } | null = null;
  const fresh = () => lastStatus !== null && Date.now() - lastStatus.at < 1500;

  const status = singleFlight(async (): Promise<HelperResponse | null> => {
    try {
      const response = await call({ op: "status" });
      lastStatus = { at: Date.now(), response };
      const wg = response.wireguard;
      paths = wg
        ? {
            directory: wg.directory,
            wireguardExe: path.win32.join(wg.directory, "wireguard.exe"),
            wgExe: path.win32.join(wg.directory, "wg.exe"),
            source: wg.source === "system" ? "system" : "managed",
          }
        : null;
      return response;
    } catch {
      lastStatus = null;
      return null;
    }
  });

  const refresh = async (maxAgeMs = 0): Promise<void> => {
    if (maxAgeMs > 0 && Date.now() - checkedAt < maxAgeMs) return;
    try {
      const hello = await call({ op: "hello" });
      ready = hello.protocol === SERVICE_PROTOCOL && hello.flavor === FLAVOR;
    } catch {
      ready = false;
    }
    if (!ready) paths = null;
    else if (!(maxAgeMs > 0 && fresh())) await status();
    checkedAt = Date.now();
  };

  const queryService = async (): Promise<ServiceQuery> => {
    const response = await status();
    if (!response?.service?.exists) return { exists: false };
    return { exists: true, state: (response.service.state || null) as ServiceState | null };
  };

  return {
    id: "windows",
    deviceLabel: "Windows",
    errors: { missing: "wireguardMissing", elevation: "helperUnavailable", installElevation: "helperUnavailable" },
    installNeedsElevation: false,
    fullTunnelLeakProtection: "wireguard",
    pq: {
      wireguard: () => new HelperWireGuardControl(call),
      dial: tunnelDial,
      clock: REAL_CLOCK,
      sweepSecrets: async () => 0,
    },
    get debugNames() {
      return { tunnelName: IDENTITY.tunnelName, serviceName: `${SERVICE.name} → WireGuardTunnel$${IDENTITY.tunnelName}`, firewallGroup: FIREWALL_GROUP };
    },
    refresh: () => refresh(),
    detect: () => (ready ? paths : null),
    isElevated: async () => {
      await refresh(fresh() ? 30_000 : 3000);
      return ready;
    },
    checkPrerequisites: async () => undefined,
    install: async () => {
      await refresh();
      if (!ready) {
        await options.repair();
        await refresh();
        if (!ready) throw new VpnError("helperUnavailable", "elevation");
      }
      const response = await guarded(() => call({ op: "install-wireguard" }));
      await refresh();
      return response.wireguardVersion ?? "";
    },
    startTunnel: (_paths, tunnel) =>
      guarded(async () => {
        lastStatus = null;
        await call({ op: "up" }, Buffer.from(tunnel.text, "utf8"));
      }),
    stopTunnel: () =>
      guarded(async () => {
        lastStatus = null;
        await call({ op: "down" });
      }),
    removeTunnelConfig: () =>
      guarded(async () => {
        await call({ op: "down" });
      }),
    queryService,
    waitForService: (predicate, timeoutMs) => waitUntil(queryService, predicate, timeoutMs),
    readInterfaceStatus: async () => {
      const response = fresh() ? lastStatus!.response : await status();
      return response ? interfaceStatusOf(response) : null;
    },
    enableKillSwitch: (input) =>
      guarded(async () => {
        await call({
          op: "killswitch-enable",
          killSwitch: {
            hosts: input.hosts.map((host) => ({ address: host.address, tcpPorts: host.tcpPorts, udpPorts: host.udpPorts })),
            allowLan: input.allowLan,
            tunnelAddresses: input.tunnelAddresses,
          },
        });
      }),
    disableKillSwitch: () =>
      guarded(async () => {
        await call({ op: "killswitch-disable" });
      }),
    killSwitchRuleCount: () =>
      guarded(async () => {
        const response = await call({ op: "killswitch-status" });
        return response.killSwitchRules ?? 0;
      }),
    pqFailureForUser,
    wifiSecurity: () => readWindowsWifi(),
    obfsRelay: (fallback) => serviceRelay(call, fallback),
  };
}

const REPAIR_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$p = Start-Process -FilePath $env:MANTEL_SERVICE_EXE -ArgumentList @('service','install','--root',('\"' + $env:MANTEL_ROOT + '\"')) -Verb RunAs -WindowStyle Hidden -Wait -PassThru",
  "exit $p.ExitCode",
].join("\n");

export async function repairService(input: { packaged: boolean; execPath: string; resourcesPath: string }): Promise<void> {
  if (!input.packaged) throw new VpnError("helperUnavailable", "elevation");
  const result = await run(POWERSHELL(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", REPAIR_SCRIPT], {
    timeoutMs: 180_000,
    env: {
      MANTEL_SERVICE_EXE: path.win32.join(input.resourcesPath, "service", "mantel.exe"),
      MANTEL_ROOT: path.win32.dirname(input.execPath),
    },
  });
  if (result.code !== 0) {
    throw new LocalizedError("helperCommand", { details: result.stderr.replace(/\s+/g, " ").trim().slice(0, 300) || `Code ${result.code}` });
  }
}
