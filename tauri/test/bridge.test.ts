import { isIP as nodeIsIP } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { describeApiError } from "../../shared/core/api-errors";
import { errorMessage } from "../../shared/core/i18n";
import { createTauriBridge, describeFailure, type Invoke, type Listen } from "../src/bridge";
import { isIP } from "../src/node-net";
import { startsDrag } from "../src/window-controls";

const PREFERENCES = { baseUrl: "http://localhost:3000", alwaysOnKillSwitch: false, lastNodeId: null, language: "de", theme: "system" };

function fake(answers: Record<string, unknown> = {}) {
  const calls: Array<[string, Record<string, unknown> | undefined]> = [];
  const call: Invoke = async (command, args) => {
    calls.push([command, args]);
    if (command === "preferences") return PREFERENCES;
    const answer = answers[command];
    if (answer instanceof Error) throw (answer as Error & { failure: unknown }).failure;
    return answer;
  };
  const listeners = new Map<string, (payload: unknown) => void>();
  const on: Listen = (event, handler) => {
    listeners.set(event, handler);
    return () => listeners.delete(event);
  };
  return { calls, call, on, listeners };
}

function rejected(failure: unknown) {
  return Object.assign(new Error("failure"), { failure });
}

describe("describeFailure", () => {
  it("translates localized failures in the UI language", () => {
    const result = describeFailure({ kind: "localized", key: "apiUnreachable", params: {}, code: "network" }, "de");
    expect(result).toEqual({ error: errorMessage({ i18n: { key: "apiUnreachable" } }, "de"), code: "network" });
    expect(result.error).not.toBe("apiUnreachable");
  });

  it("describes API errors like client.ts", () => {
    const body = { code: "rate_limited", error: "slow down" };
    const described = describeApiError(429, body);
    const result = describeFailure({ kind: "api", status: 429, body }, "en");
    expect(result.code).toBe(described.code);
    expect(result.error).toBe(typeof described.message === "string" ? described.message : errorMessage({ i18n: described.message }, "en"));
  });

  it("names features the preview does not have yet", () => {
    expect(describeFailure({ kind: "localized", key: "tauriPreview", params: { feature: "connect" }, code: "internal" }, "en").error).toMatch(/Tauri preview/);
    expect(describeFailure({ kind: "localized", key: "__plain", params: { message: "schtasks" }, code: "internal" }, "en").error).toBe("schtasks");
  });
});

describe("createTauriBridge", () => {
  it("offers the debug panel only in debug builds", () => {
    const { call, on } = fake();
    const bridge = createTauriBridge(call, on);
    expect(bridge.debug === undefined).toBe(import.meta.env.MANTEL_FLAVOR !== "debug");
  });

  it("refuses invalid input before anything reaches Rust", async () => {
    const { calls, call, on } = fake();
    const bridge = createTauriBridge(call, on);
    const result = await bridge.login("123", undefined);
    expect(result).toMatchObject({ ok: false, code: "invalid" });
    expect(calls.map(([command]) => command)).not.toContain("login");
    expect(await bridge.selectNode("../x")).toMatchObject({ ok: false, code: "invalid" });
    expect(await bridge.updateSettings({ killSwitch: "yes" } as never)).toMatchObject({ ok: false, code: "invalid" });
  });

  it("logs in with totp null and returns the session", async () => {
    const session = { loggedIn: true, accountId: "acc", paidUntil: "2030-01-01T00:00:00.000Z" };
    const { calls, call, on } = fake({ login: session });
    const result = await createTauriBridge(call, on).login("1234567890123456");
    expect(result).toEqual({ ok: true, value: session });
    expect(calls).toContainEqual(["login", { code: "1234567890123456", totp: null }]);
  });

  it("logs in with and without two-factor authentication", async () => {
    const session = { loggedIn: true, accountId: "acc", paidUntil: "2030-01-01T00:00:00.000Z" };
    const calls: Array<Record<string, unknown> | undefined> = [];
    const call: Invoke = async (command, args) => {
      if (command === "preferences") return PREFERENCES;
      calls.push(args);
      if (args?.code === "2222222222222222" && args.totp === null) throw { kind: "api", status: 401, body: { code: "totp_required" } };
      return session;
    };
    const bridge = createTauriBridge(call, () => () => undefined);
    expect(await bridge.login("1111111111111111", undefined)).toEqual({ ok: true, value: session });
    expect(await bridge.login("2222222222222222", undefined)).toMatchObject({ ok: false, code: "totp_required" });
    expect(await bridge.login("2222222222222222", "123 456")).toEqual({ ok: true, value: session });
    expect(calls).toEqual([
      { code: "1111111111111111", totp: null },
      { code: "2222222222222222", totp: null },
      { code: "2222222222222222", totp: "123 456" },
    ]);
  });

  it("turns a rejected command into a localized Result", async () => {
    const { call, on } = fake({ account: rejected({ kind: "api", status: 401, body: { code: "unauthorized" } }) });
    const result = await createTauriBridge(call, on).account();
    expect(result).toMatchObject({ ok: false, code: "unauthorized" });
    if (!result.ok) expect(result.error.length).toBeGreaterThan(0);
  });

  it("checks answers with the API schemas and keeps obfuscation tokens out", async () => {
    const account = {
      id: "acc",
      paidUntil: "2030-01-01T00:00:00.000Z",
      settings: { killSwitch: true, lanAccess: false, ipv6: false, dns: { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false } },
      devices: [{ id: "d1", name: "Laptop", nodeId: "hk-2", ipv4: "10.8.0.2", createdOn: "2026-01-01", obfsToken: "secret-token" }],
    };
    const { call, on } = fake({ account });
    const result = await createTauriBridge(call, on).account();
    expect(result.ok).toBe(true);
    if (result.ok) expect(JSON.stringify(result.value)).not.toContain("secret-token");

    const broken = fake({ nodes: [{ id: "x" }] });
    expect(await createTauriBridge(broken.call, broken.on).nodes()).toMatchObject({ ok: false, code: "server" });
  });

  it("connects through Rust and answers the tunnel status", async () => {
    const status = { phase: "connected", nodeId: "ch-zrh" };
    const { calls, call, on } = fake({ connect: status, rotate_device_key: { createdAt: 5 } });
    const bridge = createTauriBridge(call, on);
    expect(await bridge.connect("ch-zrh")).toEqual({ ok: true, value: status });
    expect(calls).toContainEqual(["connect", { nodeId: "ch-zrh" }]);
    expect(await bridge.connect("../x")).toMatchObject({ ok: false, code: "invalid" });
    expect(await bridge.rotateDeviceKey?.()).toEqual({ ok: true, value: { createdAt: 5 } });
  });

  it("passes null answers through (no device, no proxies yet)", async () => {
    const { call, on } = fake({ tor: null, proxies: null, port_forwarding: null });
    const bridge = createTauriBridge(call, on);
    expect(await bridge.tor?.()).toEqual({ ok: true, value: null });
    expect(await bridge.proxies?.()).toEqual({ ok: true, value: null });
    expect(await bridge.portForwarding?.()).toEqual({ ok: true, value: null });
  });

  it("reports the OS locale and forwards events", async () => {
    const { call, on, listeners } = fake({ environment: { platform: "win32", elevated: false } });
    const bridge = createTauriBridge(call, on, ["de-AT", "en"]);
    expect(await bridge.environment()).toMatchObject({ platform: "win32", systemLanguage: "de", systemLocale: "de-AT" });
    const windows = fake({ environment: { platform: "win32", systemLocales: ["en-GB", "de-DE"] } });
    const fromWindows = await createTauriBridge(windows.call, windows.on, ["en-US"]).environment();
    expect(fromWindows).toMatchObject({ systemLanguage: "en", systemLocale: "en-GB" });
    expect(fromWindows).not.toHaveProperty("systemLocales");
    const listener = vi.fn();
    const stop = bridge.onTunnelStatus(listener);
    listeners.get("tunnel-status")?.({ phase: "connected" });
    expect(listener).toHaveBeenCalledWith({ phase: "connected" });
    stop();
    expect(listeners.has("tunnel-status")).toBe(false);
  });

  it("only opens Telegram links as the server builds them", async () => {
    const { calls, call, on } = fake({ open_telegram_proxy: null });
    const bridge = createTauriBridge(call, on);
    expect(await bridge.openTelegramProxy?.("https://evil.example")).toMatchObject({ ok: false, code: "invalid" });
    expect(calls.map(([command]) => command)).not.toContain("open_telegram_proxy");
  });
});

describe("node-net stand-in", () => {
  it("answers like node:net isIP", () => {
    const samples = [
      "1.2.3.4", "255.255.255.255", "256.1.1.1", "01.2.3.4", "1.2.3", "::", "::1", "fe80::1%eth0", "fe80::1%", "2001:db8::8a2e:370:7334",
      "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1::2::3", "::ffff:192.0.2.1", "::ffff:999.0.2.1", "gggg::1", ":1", "1:", "hk-2.example", "",
      "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4",
    ];
    for (const sample of samples) expect([sample, isIP(sample)]).toEqual([sample, nodeIsIP(sample)]);
  });
});

describe("window controls", () => {
  it("drags only from the title bar, never from its buttons", () => {
    const element = (inDrag: boolean, clickable: boolean) =>
      ({
        closest: (selector: string) => (selector === ".app-drag" ? (inDrag ? {} : null) : clickable ? {} : null),
      }) as unknown as Element;
    expect(startsDrag(element(true, false))).toBe(true);
    expect(startsDrag(element(true, true))).toBe(false);
    expect(startsDrag(element(false, false))).toBe(false);
    expect(startsDrag(null)).toBe(false);
  });
});
