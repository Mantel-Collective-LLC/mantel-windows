import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Account, TunnelStatus, VpnNode } from "../shared/core/contract";
import type { WireGuardControl } from "../src/main/pq/uapi";
import { WgExeError } from "../src/main/pq/wgexe";
import { errorFrame, FakeNode, FakeWireGuard, virtualClock } from "./pq-helpers";

const wireguardPaths: string[] = [];

const system = vi.hoisted(() => ({
  configs: [] as string[],
  installs: 0,
  uninstalls: 0,
  service: { exists: false, state: null as string | null },
  interfaceKey: "",
  firewallOn: 0,
  firewallOff: 0,
  sweeps: 0,
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
  writeLockedFile: async (_directory: string, name: string, content: string) => {
    system.configs.push(content);
    return `C:\\ProgramData\\Mantel-Test\\${name}`;
  },
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
  readInterfaceStatus: async () => ({
    publicKey: system.interfaceKey,
    peers: [{ publicKey: "x", endpoint: "198.51.100.7:51820", latestHandshakeAt: Date.now(), rxBytes: 1, txBytes: 2 }],
  }),
}));

const { VpnController, codeOf } = await import("../src/main/vpn");
const { Store } = await import("../src/main/store");

const S = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
const K_PRIVATE = "pSR7d2h8H6wS0RjX9z/ftpIAVDAsuu/flQQStRtweZ0=";
const K = "pLLGZN3M20E9HOfCw9BTwB1UWPNJLHZEkJS0Bi4uKxw=";
const X = "10.8.0.2";

const account: Account = {
  id: "acc1",
  paidUntil: "2030-01-01T00:00:00.000Z",
  settings: { killSwitch: true, lanAccess: false, ipv6: false, dns: { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false } },
  devices: [],
};

function node(postQuantum?: boolean): VpnNode {
  return { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true, ...(postQuantum === undefined ? {} : { postQuantum }) };
}

let directory: string;
let fakeNode: FakeNode;

beforeEach(async () => {
  directory = mkdtempSync(path.join(tmpdir(), "mantel-pq-vpn-"));
  Object.assign(system, { configs: [], installs: 0, uninstalls: 0, service: { exists: false, state: null }, interfaceKey: "", firewallOn: 0, firewallOff: 0, sweeps: 0 });
  fakeNode = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X });
  await fakeNode.start();
});

afterEach(async () => {
  await fakeNode.stop();
  rmSync(directory, { recursive: true, force: true });
});

function setup(options: { postQuantum?: boolean; node?: VpnNode; handshake?: boolean; control?: WireGuardControl } = {}) {
  const store = new Store(directory);
  store.load();
  if (options.postQuantum !== undefined) store.setPreferences({ ...store.getPreferences(), postQuantum: options.postQuantum });
  store.setSecrets({ token: "t".repeat(32), accountId: "acc1", paidUntil: account.paidUntil, device: null });
  const clock = virtualClock();
  const wireguard = new FakeWireGuard(S, options.handshake === false ? () => null : () => clock.now());
  const dials: string[] = [];
  const vpn = new VpnController(store, {
    wireguard: (paths) => {
      wireguardPaths.push(paths.wgExe);
      return options.control ?? wireguard;
    },
    dial: (ipv4) => {
      dials.push(ipv4);
      return fakeNode.dial;
    },
    clock,
    sweepSecrets: async () => {
      system.sweeps++;
    },
  });
  const nodes = [options.node ?? node(true)];
  const registerDevice = vi.fn(async () => ({
    device: { id: "dev1", name: "Windows AB12", nodeId: "fra", ipv4: X, createdOn: "2026-10-22T00:00:00.000Z" },
    config: { address: [`${X}/32`], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] },
    privateKey: K_PRIVATE,
  }));
  Object.assign(vpn.api, {
    account: async () => ({ ...account, devices: [] }),
    nodes: async () => nodes,
    registerDevice,
    deleteDevice: async () => undefined,
  });
  const statuses: TunnelStatus[] = [];
  vpn.on("status", (status: TunnelStatus) => statuses.push(status));
  return { store, vpn, wireguard, statuses, registerDevice, dials, clock };
}

describe("setting „Quantenresistenter Tunnel“", () => {
  it("is off by default and stored per device", () => {
    const { store, vpn } = setup();
    expect(store.getPreferences().postQuantum).toBe(false);
    expect(vpn.setPostQuantum(true).postQuantum).toBe(true);
    const reloaded = new Store(directory);
    reloaded.load();
    expect(reloaded.getPreferences().postQuantum).toBe(true);
  });

  it("off: classical tunnel as before (Endpoint in the file, no PQ exchange)", async () => {
    const { vpn, wireguard, statuses } = setup({ node: node(false) });
    const status = await vpn.connect("fra");
    expect(system.configs[0]).toMatch(/^Endpoint = 198\.51\.100\.7:51820$/m);
    expect(wireguard.transactions).toHaveLength(0);
    expect(fakeNode.hellos).toHaveLength(0);
    expect(status.quantum).toBe("off");
    expect(statuses.every((entry) => entry.quantum !== "negotiating")).toBe(true);
  });
});

describe("connect with the setting on", () => {
  it("refuses a location without PQ capability before any tunnel (pq_unsupported)", async () => {
    for (const capability of [false, undefined]) {
      const { vpn, registerDevice } = setup({ postQuantum: true, node: node(capability) });
      const error = await vpn.connect("fra").catch((caught: unknown) => caught);
      expect(codeOf(error)).toBe("pq_unsupported");
      expect((error as Error).message).toContain("unterstützt den quantenresistenten Tunnel noch nicht");
      expect(system.installs).toBe(0);
      expect(system.firewallOn).toBe(0);
      expect(registerDevice).not.toHaveBeenCalled();
      expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", quantum: "off" });
    }
  });

  it("installs an inert config, upgrades, and reports quantum active only after STATUS 2", async () => {
    const { vpn, store, wireguard, statuses, dials } = setup({ postQuantum: true });
    system.interfaceKey = "session-key-E";
    const status = await vpn.connect("fra");
    expect(system.configs[0]).not.toMatch(/^Endpoint/m);
    expect(dials[0]).toBe(X);
    expect(wireguard.transactions).toHaveLength(2);
    const psk = wireguard.transactions[1]?.find((entry) => entry.key === "preshared_key")?.value;
    expect(psk).toBe(fakeNode.psks[0]!.toString("hex"));
    const negotiating = statuses.filter((entry) => entry.quantum === "negotiating");
    expect(negotiating.length).toBeGreaterThan(0);
    expect(negotiating.every((entry) => entry.phase === "connecting")).toBe(true);
    expect(status.quantum).toBe("active");
    expect(status.phase).toBe("connected");
    expect(store.getRuntime()).toMatchObject({ postQuantum: true, pqSessionKey: fakeNode.hellos[0]!.sessionKey.toString("base64") });
    expect(JSON.stringify(store.getRuntime())).not.toContain(fakeNode.psks[0]!.toString("base64"));
  });

  it("fails closed after 3 attempts: tunnel removed, pq_failed, no classical fallback", async () => {
    fakeNode = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X, onHello: () => errorFrame(7) });
    await fakeNode.start();
    const { vpn, wireguard } = setup({ postQuantum: true });
    const error = await vpn.connect("fra").catch((caught: unknown) => caught);
    expect(codeOf(error)).toBe("pq_failed");
    expect(fakeNode.hellos).toHaveLength(3);
    expect(system.uninstalls).toBeGreaterThanOrEqual(1);
    expect(system.service.exists).toBe(false);
    expect(wireguard.transactions.some((tx) => tx.some((entry) => entry.key === "allowed_ip" && entry.value !== "10.8.255.1/32"))).toBe(false);
    expect(wireguard.transactions[0]?.[0]).toEqual({ key: "private_key", value: Buffer.from(K_PRIVATE, "base64").toString("hex") });
    expect(wireguard.last().map((entry) => entry.key)).toEqual(["public_key", "remove"]);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", quantum: "off" });
    expect(vpn.getStatus().error).toContain("No connection without quantum protection");
    expect(system.sweeps).toBeGreaterThanOrEqual(1);
  });

  it("uses wg.exe of the detected WireGuard installation", async () => {
    wireguardPaths.length = 0;
    const { vpn } = setup({ postQuantum: true });
    system.interfaceKey = "E";
    await vpn.connect("fra");
    expect(wireguardPaths).toEqual([String.raw`C:\WG\wg.exe`]);
  });

  it.each([
    ["missing", "wireguard_missing", "WireGuard"],
    ["access", "elevation", "administrator"],
  ] as const)("wg.exe %s: understandable error, tunnel removed, no exchange", async (failure, code, text) => {
    const control: WireGuardControl = {
      set: async () => {
        throw new WgExeError(failure, "test");
      },
      get: async () => ({ listenPort: null, peers: [] }),
    };
    const { vpn } = setup({ postQuantum: true, control });
    const error = await vpn.connect("fra").catch((caught: unknown) => caught);
    expect(codeOf(error)).toBe(code);
    expect(fakeNode.hellos).toHaveLength(0);
    expect(system.service.exists).toBe(false);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", quantum: "off" });
    expect(vpn.getStatus().error?.toLowerCase()).toContain(text.toLowerCase());
  });

  it("pq_not_active when the session never handshakes; tunnel removed", async () => {
    const { vpn } = setup({ postQuantum: true, handshake: false });
    const error = await vpn.connect("fra").catch((caught: unknown) => caught);
    expect(codeOf(error)).toBe("pq_not_active");
    expect(system.service.exists).toBe(false);
  });
});

describe("toggle and restart", () => {
  it("toggling while connected reconnects with the new setting; while disconnected it only stores it", async () => {
    const { vpn, store } = setup({ postQuantum: false });
    expect(vpn.setPostQuantum(true).postQuantum).toBe(true);
    expect(system.installs).toBe(0);
    store.setPreferences({ ...store.getPreferences(), postQuantum: false });

    system.interfaceKey = "E";
    await vpn.connect("fra");
    expect(vpn.getStatus().quantum).toBe("off");
    const connect = vi.spyOn(vpn, "connect");
    vpn.setPostQuantum(true);
    expect(connect).toHaveBeenCalledWith("fra");
    await connect.mock.results[0]?.value;
    expect(vpn.getStatus().quantum).toBe("active");
    expect(fakeNode.hellos).toHaveLength(1);

    vpn.setPostQuantum(false);
    await connect.mock.results[1]?.value;
    expect(vpn.getStatus().quantum).toBe("off");
    expect(system.configs.at(-1)).toMatch(/^Endpoint/m);
  });

  it("a service restarted with the device key K is reconnected once, then reported", async () => {
    const { vpn, store } = setup({ postQuantum: true });
    system.interfaceKey = "E";
    await vpn.connect("fra");
    expect(vpn.getStatus().quantum).toBe("active");

    const connect = vi.spyOn(vpn, "connect").mockImplementation(async () => vpn.getStatus());
    system.interfaceKey = K;
    await vpn.refreshStatus();
    expect(connect).toHaveBeenCalledTimes(1);
    await vpn.refreshStatus();
    expect(connect).toHaveBeenCalledTimes(1);
    expect(vpn.getStatus()).toMatchObject({ phase: "stale", quantum: "off" });
    expect(vpn.getStatus().error).toContain("did not become active");
    expect(store.getRuntime().postQuantum).toBe(true);
  });

  it("app start with a running PQ tunnel checks STATUS and reconnects if the node forgot the session", async () => {
    const first = setup({ postQuantum: true });
    system.interfaceKey = "E";
    await first.vpn.connect("fra");
    fakeNode.hellos = [];
    const restarted = setup({ postQuantum: true });
    const reconnect = vi.spyOn(restarted.vpn, "connect").mockImplementation(async () => restarted.vpn.getStatus());
    await fakeNode.stop();
    fakeNode = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X, onStatus: (key) => Buffer.from([0x4d, 0x54, 0x50, 0x51, 1, 4, 0, 33, 0, ...key]) });
    await fakeNode.start();
    await restarted.vpn.refreshStatus();
    await vi.waitFor(() => expect(reconnect).toHaveBeenCalledWith("fra"));
  });
});
