import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { STALE_HANDSHAKE_MS, type Account, type TunnelStatus, type VpnNode } from "../shared/core/contract";
import { DICTIONARIES } from "../shared/core/i18n";
import {
  DEAD_TUNNEL_MS,
  LOCK_CLOCK_MARGIN_MS,
  REVOCATION_CHECK_MS,
  STALE_CHECK_MS,
  checkAccount,
  checkDue,
  checkError,
  revocationVerdict,
} from "../shared/core/revocation";

const NOW = Date.parse("2026-10-24T12:00:00.000Z");

const status = (patch: Partial<TunnelStatus>): Pick<TunnelStatus, "phase" | "lastHandshakeAt" | "connectedAt"> => ({
  phase: "connected",
  connectedAt: NOW - 3_600_000,
  lastHandshakeAt: NOW - 10_000,
  ...patch,
});

describe("shared rules", () => {
  const account = { devices: [{ id: "dev1", name: "x", nodeId: "fra", ipv4: "10.8.0.2", createdOn: "2026-10-01" }], graceUntil: "2026-11-01T00:00:00.000Z" };

  it("classifies the account answer: listed, removed, locked (with a clock margin)", () => {
    expect(checkAccount(account, "dev1", NOW)).toBe("present");
    expect(checkAccount(account, "dev2", NOW)).toBe("removed");
    expect(checkAccount({ ...account, devices: [] }, "dev1", NOW)).toBe("removed");
    const grace = Date.parse("2026-10-24T11:00:00.000Z");
    const ended = { ...account, graceUntil: new Date(grace).toISOString() };
    expect(checkAccount(ended, "dev1", grace + LOCK_CLOCK_MARGIN_MS - 1)).toBe("present");
    expect(checkAccount(ended, "dev1", grace + LOCK_CLOCK_MARGIN_MS + 1)).toBe("locked");
    expect(checkAccount({ ...account, graceUntil: undefined }, "dev1", NOW)).toBe("present");
  });

  it("only a 401 is definitive among errors", () => {
    expect(checkError({ sessionEnded: true })).toBe("session_ended");
    expect(checkError({ sessionEnded: false, status: 503 })).toBe("unknown");
    expect(checkError(new TypeError("fetch failed"))).toBe("unknown");
    expect(checkError(null)).toBe("unknown");
  });

  it("checks every 5 minutes, every 30 s while stale, never without a settled tunnel", () => {
    expect(checkDue({ status: { phase: "connected" }, lastCheckAt: null, now: NOW })).toBe(true);
    expect(checkDue({ status: { phase: "connected" }, lastCheckAt: NOW - REVOCATION_CHECK_MS + 1, now: NOW })).toBe(false);
    expect(checkDue({ status: { phase: "connected" }, lastCheckAt: NOW - REVOCATION_CHECK_MS, now: NOW })).toBe(true);
    expect(checkDue({ status: { phase: "stale" }, lastCheckAt: NOW - STALE_CHECK_MS, now: NOW })).toBe(true);
    expect(checkDue({ status: { phase: "stale" }, lastCheckAt: NOW - STALE_CHECK_MS + 1, now: NOW })).toBe(false);
    for (const phase of ["disconnected", "connecting", "disconnecting"] as const) {
      expect(checkDue({ status: { phase }, lastCheckAt: null, now: NOW })).toBe(false);
    }
  });

  it("verdicts: removed/locked always end it, network errors only a dead tunnel without leak protection", () => {
    const verdict = (check: Parameters<typeof revocationVerdict>[0]["check"], patch: Partial<TunnelStatus> = {}, leakProtected = false) =>
      revocationVerdict({ check, status: status(patch), now: NOW, leakProtected });
    expect(verdict("present")).toBeNull();
    expect(verdict("removed")).toBe("device_removed");
    expect(verdict("removed", {}, true)).toBe("device_removed");
    expect(verdict("locked")).toBe("account_locked");
    expect(verdict("unknown")).toBeNull();
    expect(verdict("unknown", { phase: "stale", lastHandshakeAt: NOW - STALE_HANDSHAKE_MS - 1 })).toBeNull();
    expect(verdict("unknown", { phase: "stale", lastHandshakeAt: NOW - DEAD_TUNNEL_MS + 1 })).toBeNull();
    expect(verdict("unknown", { phase: "stale", lastHandshakeAt: NOW - DEAD_TUNNEL_MS })).toBe("tunnel_dead");
    expect(verdict("unknown", { phase: "stale", lastHandshakeAt: NOW - DEAD_TUNNEL_MS }, true)).toBeNull();
    expect(verdict("unknown", { phase: "stale", lastHandshakeAt: null, connectedAt: NOW - DEAD_TUNNEL_MS })).toBe("tunnel_dead");
    expect(verdict("session_ended")).toBeNull();
    expect(verdict("session_ended", { phase: "stale", lastHandshakeAt: NOW - STALE_HANDSHAKE_MS - 1 })).toBe("session_ended");
    expect(verdict("removed", { phase: "connecting" })).toBeNull();
    expect(verdict("removed", { phase: "disconnected" })).toBeNull();
  });
});

const system = vi.hoisted(() => ({
  installs: 0,
  uninstalls: 0,
  service: { exists: false, state: null as string | null },
  handshakeAt: null as number | null,
  firewallOff: 0,
}));

vi.mock("electron", () => ({
  safeStorage: { isEncryptionAvailable: () => false, encryptString: (text: string) => Buffer.from(text), decryptString: (data: Buffer) => data.toString() },
}));
vi.mock("../src/main/system/environment", () => ({
  detectWireGuard: () => ({ directory: "C:\\WG", wireguardExe: "C:\\WG\\wireguard.exe", wgExe: "C:\\WG\\wg.exe", source: "system" }),
  isElevated: async () => true,
  programDataDirectory: () => "C:\\ProgramData\\Mantel-Test",
}));
vi.mock("../src/main/system/acl", () => ({
  assertLocked: async () => undefined,
  writeLockedFile: async (_directory: string, name: string) => `C:\\ProgramData\\Mantel-Test\\${name}`,
}));
vi.mock("../src/main/firewall/apply", () => ({
  enableFirewallKillSwitch: async () => undefined,
  disableFirewallKillSwitch: async () => {
    system.firewallOff++;
  },
  firewallRuleCount: async () => 0,
}));
vi.mock("../src/main/wireguard/service", () => ({
  TUNNEL_NAME: "mantel-test",
  installTunnel: async () => {
    system.installs++;
    system.service = { exists: true, state: "RUNNING" };
  },
  uninstallTunnel: async () => {
    system.uninstalls++;
    system.service = { exists: false, state: null };
  },
  queryService: async () => system.service,
  waitForService: async () => system.service,
  readInterfaceStatus: async () => ({
    publicKey: "",
    peers: [{ publicKey: "x", endpoint: "198.51.100.7:51820", latestHandshakeAt: system.handshakeAt, rxBytes: 1, txBytes: 2 }],
  }),
}));

const { VpnController } = await import("../src/main/vpn");
const { Store } = await import("../src/main/store");
const { ApiError } = await import("../src/main/api/client");

const TEXT = DICTIONARIES.en.errors;
const NODE: VpnNode = { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true };
const S = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
const K_PRIVATE = "pSR7d2h8H6wS0RjX9z/ftpIAVDAsuu/flQQStRtweZ0=";

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "mantel-revocation-"));
  Object.assign(system, { installs: 0, uninstalls: 0, service: { exists: false, state: null }, handshakeAt: null, firewallOff: 0 });
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
});
afterEach(() => {
  vi.useRealTimers();
  rmSync(directory, { recursive: true, force: true });
});

async function connected(options: { killSwitch?: boolean; alwaysOn?: boolean } = {}) {
  const store = new Store(directory);
  store.load();
  if (options.alwaysOn) store.setPreferences({ ...store.getPreferences(), alwaysOnKillSwitch: true });
  store.setSecrets({ token: "t".repeat(32), accountId: "acc1", paidUntil: "2030-01-01T00:00:00.000Z", device: null });
  const vpn = new VpnController(store, { sweepSecrets: async () => undefined });
  const server = {
    devices: [] as Account["devices"],
    failure: null as unknown,
    failOnce: [] as unknown[],
    accountCalls: 0,
  };
  const account = async (): Promise<Account> => {
    server.accountCalls++;
    const once = server.failOnce.shift();
    if (once) throw once;
    if (server.failure) throw server.failure;
    return {
      id: "acc1",
      paidUntil: "2030-01-01T00:00:00.000Z",
      graceUntil: "2030-01-08T00:00:00.000Z",
      settings: { killSwitch: options.killSwitch ?? true, lanAccess: false, ipv6: false, dns: { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false } },
      devices: server.devices,
    };
  };
  Object.assign(vpn.api, {
    account,
    nodes: async () => [NODE],
    registerDevice: async () => {
      const device = { id: `dev${server.devices.length + 1}`, name: "Windows AB12", nodeId: "fra", ipv4: "10.8.0.2", createdOn: "2026-10-22" };
      server.devices = [...server.devices, device];
      return { device, config: { address: ["10.8.0.2/32"], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] }, privateKey: K_PRIVATE };
    },
    deleteDevice: async () => undefined,
  });
  const ended = vi.fn();
  vpn.on("session-ended", ended);
  system.handshakeAt = Date.now();
  await vpn.connect("fra");
  expect(vpn.getStatus().phase).toBe("connected");
  const statuses: TunnelStatus[] = [];
  vpn.on("status", (next: TunnelStatus) => statuses.push(next));
  const advance = async (ms: number, handshakeAgo: number | null = 0) => {
    vi.setSystemTime(Date.now() + ms);
    if (handshakeAgo !== null) system.handshakeAt = Date.now() - handshakeAgo;
    await vpn.refreshStatus();
  };
  return { store, vpn, server, statuses, advance, ended };
}

const networkError = () => new ApiError("Server nicht erreichbar", "network", null);

describe("Windows: device removed", () => {
  it("disconnects with the reason and registers a new device on the next connect", async () => {
    const { vpn, store, server } = await connected();
    server.devices = [];
    expect(await vpn.checkRevocation()).toBe("device_removed");
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", revoked: "device_removed", error: TEXT.deviceRemoved });
    expect(system.uninstalls).toBe(1);
    expect(store.getSecrets().device).toBeNull();
    await vpn.refreshStatus();
    expect(vpn.getStatus().revoked).toBe("device_removed");
    await vpn.connect("fra");
    expect(vpn.getStatus()).toMatchObject({ phase: "connected", error: null });
    expect(vpn.getStatus().revoked).toBeUndefined();
    expect(server.devices.map((device) => device.id)).toEqual(["dev1"]);
  });

  it("notices it in the account refresh of the UI, and checks by itself every 5 minutes", async () => {
    const { vpn, server, advance } = await connected();
    const calls = server.accountCalls;
    await advance(REVOCATION_CHECK_MS - 1_000);
    expect(server.accountCalls).toBe(calls);
    server.devices = [];
    await vpn.account();
    await vi.waitFor(() => expect(vpn.getStatus().revoked).toBe("device_removed"));
    expect(server.accountCalls).toBe(calls + 1);
  });
});

describe("Windows: network errors and dead tunnels", () => {
  it("a network error never disconnects a working or merely stale tunnel", async () => {
    const { vpn, server, advance } = await connected({ killSwitch: false });
    server.failure = networkError();
    expect(await vpn.checkRevocation()).toBeNull();
    await advance(STALE_HANDSHAKE_MS + 1_000, STALE_HANDSHAKE_MS + 1_000);
    expect(vpn.getStatus().phase).toBe("stale");
    expect(await vpn.checkRevocation()).toBeNull();
    expect(system.uninstalls).toBe(0);
  });

  it("without kill switch: ends a tunnel dead for 10 minutes, then asks again outside of it", async () => {
    const { vpn, server } = await connected({ killSwitch: false });
    server.failOnce = [networkError()];
    server.devices = [];
    vi.setSystemTime(Date.now() + DEAD_TUNNEL_MS + 1_000);
    system.handshakeAt = Date.now() - DEAD_TUNNEL_MS - 1_000;
    await vpn.refreshStatus();
    await vi.waitFor(() => expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", revoked: "device_removed", error: TEXT.deviceRemoved }));
    expect(system.uninstalls).toBe(1);
  });

  it("without kill switch and still no answer: disconnected as a dead tunnel", async () => {
    const { vpn, server } = await connected({ killSwitch: false });
    server.failure = networkError();
    vi.setSystemTime(Date.now() + DEAD_TUNNEL_MS + 1_000);
    system.handshakeAt = Date.now() - DEAD_TUNNEL_MS - 1_000;
    await vpn.refreshStatus();
    await vi.waitFor(() => expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", revoked: "tunnel_dead", error: TEXT.tunnelDead }));
  });

  it("kill switch without the permanent one: a dead tunnel stays (no leak), shown as interrupted", async () => {
    const { vpn, server } = await connected({ killSwitch: true });
    server.failure = networkError();
    vi.setSystemTime(Date.now() + DEAD_TUNNEL_MS + 60_000);
    system.handshakeAt = Date.now() - DEAD_TUNNEL_MS - 60_000;
    await vpn.refreshStatus();
    expect(await vpn.checkRevocation()).toBeNull();
    expect(vpn.getStatus().phase).toBe("stale");
    expect(system.uninstalls).toBe(0);
  });

  it("permanent kill switch: ending the dead tunnel leaks nothing (rules stay), so it is ended", async () => {
    const { vpn, server } = await connected({ killSwitch: true, alwaysOn: true });
    server.failure = networkError();
    vi.setSystemTime(Date.now() + DEAD_TUNNEL_MS + 1_000);
    system.handshakeAt = Date.now() - DEAD_TUNNEL_MS - 1_000;
    await vpn.refreshStatus();
    await vi.waitFor(() => expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", revoked: "tunnel_dead" }));
    expect(system.firewallOff).toBe(0);
    expect(vpn.getStatus().leakProtection).toBe("firewall");
  });
});

describe("Windows: session", () => {
  it("401 with a working tunnel: logged out, tunnel stays; stale afterwards: ended", async () => {
    const { vpn, store, server, ended } = await connected();
    server.failure = new ApiError("Sitzung abgelaufen", "unauthorized", 401, { apiCode: "unauthorized" });
    expect(await vpn.checkRevocation()).toBeNull();
    expect(ended).toHaveBeenCalledTimes(1);
    expect(store.getSecrets().token).toBeNull();
    expect(vpn.getStatus().phase).toBe("connected");
    vi.setSystemTime(Date.now() + STALE_HANDSHAKE_MS + 5_000);
    system.handshakeAt = Date.now() - STALE_HANDSHAKE_MS - 5_000;
    await vpn.refreshStatus();
    await vi.waitFor(() => expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", revoked: "session_ended" }));
  });

  it("logged out with a running tunnel: disconnect works without a session", async () => {
    const { vpn, store } = await connected();
    store.setSecrets({ ...store.getSecrets(), token: null });
    await vpn.disconnect();
    expect(vpn.getStatus().phase).toBe("disconnected");
    expect(system.uninstalls).toBe(1);
  });

  it("logout takes the tunnel down", async () => {
    const { vpn } = await connected();
    await vpn.logout();
    expect(system.uninstalls).toBe(1);
    expect(vpn.session().loggedIn).toBe(false);
  });
});
