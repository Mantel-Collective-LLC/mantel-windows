import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Account, TunnelPhase, VpnNode } from "../shared/core/contract";
import { KEY_ROTATION_MS, keyCreatedAt, keyRotationDue, rotateWithPending } from "../shared/core/device-key";

const system = vi.hoisted(() => ({ installs: 0, uninstalls: 0, firewallOn: 0, firewallOff: 0, service: { exists: false, state: null as string | null } }));

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
  enableFirewallKillSwitch: async () => {
    system.firewallOn++;
  },
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
  readInterfaceStatus: async () => ({ publicKey: "", peers: [] }),
}));

const { VpnController } = await import("../src/main/vpn");
const { Store } = await import("../src/main/store");
const { ApiError } = await import("../src/main/api/client");

const DAY = 86_400_000;
const S = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
const OLD_PRIVATE = "pSR7d2h8H6wS0RjX9z/ftpIAVDAsuu/flQQStRtweZ0=";
const OLD_PUBLIC = "pLLGZN3M20E9HOfCw9BTwB1UWPNJLHZEkJS0Bi4uKxw=";
const config = { address: ["10.8.0.2/32"], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] };
const registered = { id: "dev1", name: "Windows AB12", nodeId: "fra", ipv4: "10.8.0.2", createdOn: "2026-01-01T00:00:00.000Z" };
const account: Account = {
  id: "acc1",
  paidUntil: "2030-01-01T00:00:00.000Z",
  settings: { killSwitch: false, lanAccess: false, ipv6: false, dns: { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false } },
  devices: [registered],
};
const fra: VpnNode = { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true };

describe("30-day rule", () => {
  it("uses the local stamp, else the server's rotation day, else the creation day", () => {
    expect(keyCreatedAt(1234, { createdOn: "2026-01-01" })).toBe(1234);
    expect(keyCreatedAt(undefined, { keyRotatedOn: "2026-02-01", createdOn: "2026-01-01" })).toBe(Date.parse("2026-02-01"));
    expect(keyCreatedAt(null, { createdOn: "2026-01-01T00:00:00.000Z" })).toBe(Date.parse("2026-01-01"));
    expect(keyCreatedAt(undefined, undefined)).toBeNull();
    expect(keyCreatedAt(undefined, { createdOn: "kaputt" })).toBeNull();
  });

  it("is due from 30 days on, never for an unknown age", () => {
    const now = Date.parse("2026-03-01T00:00:00.000Z");
    expect(keyRotationDue(now - KEY_ROTATION_MS + 1, now)).toBe(false);
    expect(keyRotationDue(now - KEY_ROTATION_MS, now)).toBe(true);
    expect(keyRotationDue(now - 400 * DAY, now)).toBe(true);
    expect(keyRotationDue(null, now)).toBe(false);
  });
});

describe("rotateWithPending", () => {
  const pair = { publicKey: "new", privateKey: "secret" };

  it("stores the pair before sending and reuses a pending one", async () => {
    const stored: unknown[] = [];
    const send = vi.fn(async (publicKey: string) => publicKey);
    const first = await rotateWithPending({ pending: null, generate: () => pair, storePending: (value) => void stored.push(value), send, answered: () => true });
    expect(first).toEqual({ pair, response: "new" });
    expect(stored).toEqual([pair]);
    const again = await rotateWithPending({ pending: pair, generate: () => ({ publicKey: "other", privateKey: "x" }), storePending: (value) => void stored.push(value), send, answered: () => true });
    expect(again.pair).toBe(pair);
    expect(stored).toHaveLength(1);
  });

  it("keeps the pending pair without an answer, drops it on a server answer", async () => {
    const stored: unknown[] = [];
    const lost = rotateWithPending({ pending: null, generate: () => pair, storePending: (value) => void stored.push(value), send: () => Promise.reject(new Error("offline")), answered: () => false });
    await expect(lost).rejects.toThrow("offline");
    expect(stored).toEqual([pair]);
    const refused = rotateWithPending({ pending: pair, generate: () => pair, storePending: (value) => void stored.push(value), send: () => Promise.reject(new Error("503")), answered: () => true });
    await expect(refused).rejects.toThrow("503");
    expect(stored).toEqual([pair, null]);
  });
});

describe("VpnController", () => {
  let directory: string;

  beforeEach(() => {
    directory = mkdtempSync(path.join(tmpdir(), "mantel-key-rotation-"));
    Object.assign(system, { installs: 0, uninstalls: 0, firewallOn: 0, firewallOff: 0, service: { exists: false, state: null } });
  });
  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  function setup(keyAgeDays: number | null, killSwitch = false) {
    const store = new Store(directory);
    store.load();
    const device = {
      id: "dev1",
      nodeId: "fra",
      publicKey: OLD_PUBLIC,
      privateKey: OLD_PRIVATE,
      keySource: "local" as const,
      config,
      ...(keyAgeDays === null ? {} : { keyCreatedAt: Date.now() - keyAgeDays * DAY }),
    };
    store.setSecrets({ token: "t".repeat(32), accountId: "acc1", paidUntil: account.paidUntil, device });
    const vpn = new VpnController(store);
    const rotateDeviceKey = vi.fn(async (_id: string, _publicKey: string) => ({
      device: { ...registered, keyRotatedOn: "2026-11-04" },
      config,
    }));
    const registerDevice = vi.fn();
    const settings = { ...account.settings, killSwitch };
    const nodes = vi.fn(async () => [fra]);
    Object.assign(vpn.api, { account: async () => ({ ...account, settings }), nodes, rotateDeviceKey, registerDevice, deleteDevice: async () => undefined });
    const phases: TunnelPhase[] = [];
    vpn.on("status", (status: { phase: TunnelPhase }) => phases.push(status.phase));
    return { store, vpn, rotateDeviceKey, registerDevice, nodes, phases };
  }

  it("connect renews a key older than 30 days first, silently, same device", async () => {
    const { store, vpn, rotateDeviceKey, registerDevice } = setup(31);
    await vpn.connect("fra");
    expect(rotateDeviceKey).toHaveBeenCalledTimes(1);
    const [id, publicKey] = rotateDeviceKey.mock.calls[0]!;
    expect(id).toBe("dev1");
    const device = store.getSecrets().device!;
    expect(device.publicKey).toBe(publicKey);
    expect(device.publicKey).not.toBe(OLD_PUBLIC);
    expect(device.privateKey).not.toBe(OLD_PRIVATE);
    expect(device.pendingKey).toBeUndefined();
    expect(Date.now() - device.keyCreatedAt!).toBeLessThan(5000);
    expect(registerDevice).not.toHaveBeenCalled();
    expect(vpn.getStatus().error).toBeNull();
  });

  it("connect leaves a young key alone; an old device without stamp uses the server's creation day", async () => {
    const young = setup(3);
    await young.vpn.connect("fra");
    expect(young.rotateDeviceKey).not.toHaveBeenCalled();
    rmSync(directory, { recursive: true, force: true });
    directory = mkdtempSync(path.join(tmpdir(), "mantel-key-rotation-"));
    const unstamped = setup(null);
    await unstamped.vpn.connect("fra");
    expect(unstamped.rotateDeviceKey).toHaveBeenCalledTimes(1);
  });

  it("no answer: connects with the old key, keeps the pending pair and repeats exactly it next time", async () => {
    const { store, vpn, rotateDeviceKey } = setup(40);
    rotateDeviceKey.mockRejectedValueOnce(new ApiError({ key: "apiUnreachable" }, "network", null));
    await vpn.connect("fra");
    const afterFailure = store.getSecrets().device!;
    expect(afterFailure.publicKey).toBe(OLD_PUBLIC);
    expect(afterFailure.pendingKey?.publicKey).toBe(rotateDeviceKey.mock.calls[0]![1]);
    await vpn.disconnect();
    await vpn.connect("fra");
    expect(rotateDeviceKey.mock.calls[1]![1]).toBe(afterFailure.pendingKey!.publicKey);
    expect(store.getSecrets().device).toMatchObject({ publicKey: afterFailure.pendingKey!.publicKey, privateKey: afterFailure.pendingKey!.privateKey });
    expect(store.getSecrets().device!.pendingKey).toBeUndefined();
  });

  it("server refuses (node unreachable): old key stays, no pending pair", async () => {
    const { store, vpn, rotateDeviceKey } = setup(40);
    rotateDeviceKey.mockRejectedValueOnce(new ApiError("node", "server", 503, { apiCode: "node_unavailable" }));
    await vpn.connect("fra");
    expect(store.getSecrets().device).toMatchObject({ publicKey: OLD_PUBLIC, privateKey: OLD_PRIVATE });
    expect(store.getSecrets().device!.pendingKey).toBeUndefined();
  });

  it("manual rotation while connected: disconnects, renews, reconnects with the new key", async () => {
    const { store, vpn, rotateDeviceKey } = setup(2);
    await vpn.connect("fra");
    expect(system.installs).toBe(1);
    const info = await vpn.rotateDeviceKey();
    expect(rotateDeviceKey).toHaveBeenCalledTimes(1);
    expect(info!.createdAt).toBe(store.getSecrets().device!.keyCreatedAt);
    expect(system.uninstalls).toBeGreaterThanOrEqual(1);
    expect(system.installs).toBe(2);
    expect(vpn.getStatus().phase).not.toBe("disconnected");
    expect(store.getSecrets().device!.publicKey).toBe(rotateDeviceKey.mock.calls[0]![1]);
  });

  it("manual rotation failure is reported, the old key stays and the tunnel comes back", async () => {
    const { store, vpn, rotateDeviceKey } = setup(2);
    await vpn.connect("fra");
    rotateDeviceKey.mockRejectedValueOnce(new ApiError("limit", "server", 429, { apiCode: "rate_limited" }));
    await expect(vpn.rotateDeviceKey()).rejects.toBeInstanceOf(ApiError);
    expect(store.getSecrets().device!.publicKey).toBe(OLD_PUBLIC);
    expect(system.installs).toBe(2);
  });

  it("kill switch on: manual rotation keeps the firewall rules the whole time (never disconnected)", async () => {
    const { vpn, rotateDeviceKey, phases } = setup(2, true);
    await vpn.connect("fra");
    expect(system.firewallOn).toBe(1);
    phases.length = 0;
    await vpn.rotateDeviceKey();
    expect(rotateDeviceKey).toHaveBeenCalledTimes(1);
    expect(system.uninstalls).toBe(1);
    expect(system.firewallOff).toBe(0);
    expect(phases).not.toContain("disconnected");
    expect(phases).not.toContain("disconnecting");
    expect(vpn.getStatus()).toMatchObject({ phase: "connecting", firewallActive: true, error: null });
    expect(system.installs).toBe(2);
  });

  it("kill switch on: rotation done but the restart fails → rules stay, tunnel shown as interrupted", async () => {
    const { vpn, nodes } = setup(2, true);
    await vpn.connect("fra");
    nodes.mockRejectedValueOnce(new ApiError({ key: "apiUnreachable" }, "network", null));
    await vpn.rotateDeviceKey();
    expect(system.firewallOff).toBe(0);
    expect(vpn.getStatus()).toMatchObject({ phase: "stale", firewallActive: true });
  });

  it("deviceKey: local stamp, fallback to the server's day, null without device", async () => {
    const { vpn } = setup(5);
    expect((await vpn.deviceKey())!.createdAt).toBeLessThan(Date.now() - 4 * DAY);
    rmSync(directory, { recursive: true, force: true });
    directory = mkdtempSync(path.join(tmpdir(), "mantel-key-rotation-"));
    const unstamped = setup(null);
    expect(await unstamped.vpn.deviceKey()).toEqual({ createdAt: Date.parse(registered.createdOn) });
    unstamped.store.setSecrets({ ...unstamped.store.getSecrets(), device: null });
    expect(await unstamped.vpn.deviceKey()).toBeNull();
  });
});
