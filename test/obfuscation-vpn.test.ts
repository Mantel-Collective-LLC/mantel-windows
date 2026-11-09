import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountSettings, VpnNode } from "../shared/core/contract";
import type { Relay, RelayConfig } from "../src/main/obfs/relay";
import { FakeNode, FakeWireGuard, virtualClock } from "./pq-helpers";

const system = vi.hoisted(() => ({
  configs: [] as string[],
  installs: 0,
  service: { exists: false, state: null as string | null },
  udpBlocked: false,
  firewallRules: [] as unknown[],
  firewallOff: 0,
  interfaceKey: "",
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
  enableFirewallKillSwitch: async (rules: unknown[]) => {
    system.firewallRules = rules;
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
    system.service = { exists: false, state: null };
  },
  queryService: async () => system.service,
  waitForService: async () => system.service,
  readInterfaceStatus: async () => {
    const config = system.configs.at(-1) ?? "";
    const plain = !/^Endpoint = 127\.0\.0\.1:/m.test(config);
    const handshake = plain && system.udpBlocked ? null : Date.now();
    return { publicKey: system.interfaceKey, peers: [{ publicKey: "x", endpoint: null, latestHandshakeAt: handshake, rxBytes: 0, txBytes: 0 }] };
  },
}));

const { VpnController, codeOf } = await import("../src/main/vpn");
const { Store } = await import("../src/main/store");

const S = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
const K_PRIVATE = "pSR7d2h8H6wS0RjX9z/ftpIAVDAsuu/flQQStRtweZ0=";
const K = "pLLGZN3M20E9HOfCw9BTwB1UWPNJLHZEkJS0Bi4uKxw=";
const X = "10.8.0.2";
const PIN = "q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJq80=";
const DNS_OFF = { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false };
const OFFER = { version: 1, port: 443, pin: PIN };

function node(id: string, host: string, extra: Partial<VpnNode> = {}): VpnNode {
  return { id, city: id.toUpperCase(), country: "DE", endpointHost: host, endpointPort: 51820, online: true, obfuscation: OFFER, ...extra };
}

type FakeRelay = Relay & { config: RelayConfig; stopped: boolean; exit: () => void; setFailure: (failure: "rejected" | "pin" | null) => void };

let directory: string;
let fakeNode: FakeNode | null = null;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "mantel-obfs-"));
  Object.assign(system, { configs: [], installs: 0, service: { exists: false, state: null }, udpBlocked: false, firewallRules: [], firewallOff: 0, interfaceKey: "" });
});
afterEach(async () => {
  await fakeNode?.stop();
  fakeNode = null;
  rmSync(directory, { recursive: true, force: true });
});

function setup(options: { mode?: "auto" | "off" | "on"; nodes?: VpnNode[]; token?: string | null; settings?: Partial<AccountSettings>; postQuantum?: boolean; relayGate?: Promise<void>; attach?: () => Promise<Relay | null> } = {}) {
  const store = new Store(directory);
  store.load();
  store.setPreferences({ ...store.getPreferences(), obfuscation: options.mode ?? "auto", postQuantum: options.postQuantum ?? false });
  store.setSecrets({ token: "t".repeat(32), accountId: "acc1", paidUntil: "2030-01-01T00:00:00.000Z", device: null });
  const relays: FakeRelay[] = [];
  let port = 41000;
  const network = { current: "wlan=192.168.1.20/24" };
  const clock = virtualClock();
  const wireguard = new FakeWireGuard(S, () => clock.now());
  const vpn = new VpnController(
    store,
    {
      sweepSecrets: async () => undefined,
      clock,
      wireguard: () => wireguard,
      dial: () => async () => {
        if (!fakeNode) throw new Error("no PQ node in this test");
        const endpoint = wireguard.transactions.flat().filter((entry) => entry.key === "endpoint").at(-1)?.value ?? "";
        if (system.udpBlocked && !endpoint.startsWith("127.0.0.1:")) throw new Error("connect timeout");
        return fakeNode.dial();
      },
    },
    undefined,
    {
      start: async (config) => {
        await options.relayGate;
        let stopped = false;
        let failure: "rejected" | "pin" | null = null;
        const listeners: Array<() => void> = [];
        const relay: FakeRelay = {
          config,
          port: port++,
          state: () => (failure ? "retrying" : "connected"),
          failure: () => failure,
          onExit: (listener) => listeners.push(listener),
          stop: () => {
            stopped = true;
          },
          get stopped() {
            return stopped;
          },
          exit: () => listeners.forEach((listener) => listener()),
          setFailure: (next) => {
            failure = next;
          },
        };
        relays.push(relay);
        return relay;
      },
      network: () => network.current,
      attach: options.attach,
    },
  );
  const settings: AccountSettings = { killSwitch: true, lanAccess: false, ipv6: false, dns: DNS_OFF, ...options.settings };
  const nodes = options.nodes ?? [node("fra", "198.51.100.7"), node("ams", "198.51.100.8")];
  let devices: Array<{ id: string; name: string; nodeId: string; ipv4: string; createdOn: string; obfsToken?: string }> = [];
  const token = options.token === undefined ? "obfs-token-1" : options.token;
  Object.assign(vpn.api, {
    account: async () => ({ id: "acc1", paidUntil: "2030-01-01T00:00:00.000Z", settings: { ...settings }, devices }),
    nodes: async () => nodes,
    registerDevice: async (input: { nodeId: string }) => {
      const target = nodes.find((entry) => entry.id === input.nodeId) ?? nodes[0]!;
      const device = { id: `dev${devices.length + 1}`, name: "Windows AB12", nodeId: target.id, ipv4: X, createdOn: "2026-11-05", ...(token ? { obfsToken: token } : {}) };
      devices = [...devices, device];
      const endpoint = `${target.endpointHost}:${target.endpointPort}`;
      return { device, config: { address: [`${X}/32`], dns: ["10.8.0.1"], serverPublicKey: S, endpoint, allowedIps: ["0.0.0.0/0"] }, privateKey: K_PRIVATE };
    },
    rotateDeviceKey: async (id: string) => {
      const device = { ...devices.find((entry) => entry.id === id)!, obfsToken: "obfs-token-2" };
      devices = devices.map((entry) => (entry.id === id ? device : entry));
      return { device, config: { address: [`${X}/32`], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] } };
    },
    deleteDevice: async () => undefined,
  });
  return { store, vpn, relays, network, wireguard };
}

const lastConfig = () => system.configs.at(-1) ?? "";
const allowedIps = (config: string) => /^AllowedIPs = (.*)$/m.exec(config)?.[1]?.split(", ") ?? [];

describe("Verschleierung: Auto", () => {
  it("is the default and stays plain UDP while the handshake comes", async () => {
    const store = new Store(directory);
    store.load();
    expect(store.getPreferences().obfuscation).toBe("auto");
    const { vpn, relays } = setup();
    const status = await vpn.connect("fra");
    expect(relays).toHaveLength(0);
    expect(lastConfig()).toMatch(/^Endpoint = 198\.51\.100\.7:51820$/m);
    expect(status).toMatchObject({ phase: "connected", obfuscated: false, leakProtection: "wireguard" });
  });

  it("no handshake over UDP: the same tunnel again through TLS, remembered for this network only", async () => {
    system.udpBlocked = true;
    const { vpn, relays, network, store } = setup();
    const status = await vpn.connect("fra");
    expect(relays).toHaveLength(1);
    expect(relays[0]!.config).toEqual({ server: "198.51.100.7:443", pin: PIN, token: "obfs-token-1" });
    expect(lastConfig()).toMatch(/^Endpoint = 127\.0\.0\.1:41000$/m);
    expect(status).toMatchObject({ phase: "connected", obfuscated: true, leakProtection: "firewall", firewallActive: true });
    expect(store.getRuntime()).toMatchObject({ obfuscated: true, endpoint: "198.51.100.7:51820" });

    const before = system.configs.length;
    await vpn.connect("ams");
    expect(system.configs.length - before).toBe(1);
    expect(lastConfig()).toMatch(/^Endpoint = 127\.0\.0\.1:41001$/m);
    expect(relays[0]!.stopped).toBe(true);
    expect(relays[1]!.stopped).toBe(false);

    system.udpBlocked = false;
    network.current = "ethernet=10.0.0.5/24";
    const plain = await vpn.connect("fra");
    expect(plain.obfuscated).toBe(false);
    expect(lastConfig()).toMatch(/^Endpoint = 198\.51\.100\.7:51820$/m);
    expect(relays[1]!.stopped).toBe(true);
    expect(JSON.stringify(store.getPreferences())).not.toContain("wlan");
  });

  it("without an offer or token it never switches, the tunnel stays plain", async () => {
    system.udpBlocked = true;
    for (const variant of [{ nodes: [node("fra", "198.51.100.7", { obfuscation: undefined })] }, { token: null }]) {
      const { vpn, relays } = setup(variant);
      const status = await vpn.connect("fra");
      expect(relays).toHaveLength(0);
      expect(status.obfuscated).toBe(false);
    }
  });
});

describe("Verschleierung: An / Aus", () => {
  it("An: always TLS, fail closed without offer or token (no tunnel, no UDP fallback)", async () => {
    const { vpn, relays } = setup({ mode: "on" });
    expect((await vpn.connect("fra")).obfuscated).toBe(true);
    expect(relays).toHaveLength(1);
    await vpn.disconnect();
    expect(relays[0]!.stopped).toBe(true);
    expect(vpn.getStatus().obfuscated).toBe(false);

    for (const variant of [{ nodes: [node("fra", "198.51.100.7", { obfuscation: undefined })] }, { token: null }]) {
      system.configs = [];
      const { vpn: strict, relays: none } = setup({ mode: "on", ...variant });
      const error = await strict.connect("fra").catch((caught: unknown) => caught);
      expect(codeOf(error)).toBe("invalid");
      expect((error as Error).message).toContain("bietet die Verschleierung noch nicht an");
      expect(none).toHaveLength(0);
      expect(system.configs).toHaveLength(0);
      expect(strict.getStatus()).toMatchObject({ phase: "disconnected", obfuscated: false });
    }
  });

  it("Aus: never, also when UDP is blocked", async () => {
    system.udpBlocked = true;
    const { vpn, relays } = setup({ mode: "off" });
    await vpn.connect("fra");
    expect(relays).toHaveLength(0);
  });

  it("changing the setting while connected reconnects with it", async () => {
    const { vpn, relays } = setup({ mode: "off" });
    await vpn.connect("fra");
    expect(vpn.setObfuscation("on").obfuscation).toBe("on");
    await vi.waitFor(() => expect(vpn.getStatus().obfuscated).toBe(true));
    expect(relays).toHaveLength(1);
  });
});

describe("obfuscated tunnel: routing and leak protection", () => {
  it("the node bypasses the tunnel, no /0 (WireGuard's own block would stop the relay), firewall lets only TCP 443 to it", async () => {
    const { vpn } = setup({ mode: "on" });
    await vpn.connect("fra");
    const routes = allowedIps(lastConfig());
    expect(routes).not.toContain("0.0.0.0/0");
    expect(routes).not.toContain("::/0");
    expect(routes).toEqual(expect.arrayContaining(["::/1", "8000::/1", "198.51.100.6/32", "198.51.100.8/29"]));
    expect(routes.some((route) => route.startsWith("198.51.100.7"))).toBe(false);
    expect(lastConfig()).toMatch(/^PersistentKeepalive = 25$/m);
    const rules = system.firewallRules as Array<{ key: string; protocol: string; remoteAddress: string[]; remotePort: string[] }>;
    const tcp = rules.find((rule) => rule.protocol === "TCP" && rule.remoteAddress.includes("198.51.100.7"));
    expect(tcp?.remotePort).toEqual(["1-442", "444-65535"]);
  });

  it("a relay that dies is replaced once by reconnecting; a refused token is shown while it retries", async () => {
    const { vpn, relays } = setup({ mode: "on" });
    await vpn.connect("fra");
    relays[0]!.setFailure("rejected");
    await vpn.refreshStatus();
    expect(vpn.getStatus().error).toContain("refuses the obfuscated connection");
    relays[0]!.exit();
    await vi.waitFor(() => expect(relays).toHaveLength(2));
    await vi.waitFor(() => expect(vpn.getStatus()).toMatchObject({ phase: "connected", obfuscated: true, error: null }));
  });

  it("app restart with an obfuscated tunnel (relay gone): reconnects instead of a dead tunnel", async () => {
    const first = setup({ mode: "on" });
    await first.vpn.connect("fra");
    const { vpn, relays } = setup({ mode: "on" });
    await vpn.refreshStatus();
    await vi.waitFor(() => expect(relays).toHaveLength(1));
    await vi.waitFor(() => expect(vpn.getStatus().obfuscated).toBe(true));
  });

  it("app restart while the Mantel Service still holds the relay: taken over, no reconnect, quitting keeps it", async () => {
    const first = setup({ mode: "on" });
    await first.vpn.connect("fra");
    expect(first.vpn.relayEndsWithApp()).toBe(true);
    const held: Relay = { port: 41000, detached: true, state: () => "connected", failure: () => null, onExit: () => undefined, stop: vi.fn() };
    const { vpn, relays } = setup({ mode: "on", attach: async () => held });
    await vpn.refreshStatus();
    expect(relays).toHaveLength(0);
    expect(vpn.getStatus()).toMatchObject({ obfuscated: true, error: null });
    expect(vpn.relayEndsWithApp()).toBe(false);
    await vpn.disconnect();
    expect(held.stop).toHaveBeenCalled();
  });

  it("key rotation takes the new token for the new relay", async () => {
    const { vpn, relays, store } = setup({ mode: "on" });
    await vpn.connect("fra");
    await vpn.rotateDeviceKey();
    await vi.waitFor(() => expect(relays).toHaveLength(2));
    expect(relays[0]!.stopped).toBe(true);
    expect(relays[1]!.config.token).toBe("obfs-token-2");
    expect(store.getSecrets().device?.obfsToken).toBe("obfs-token-2");
  });

  it("„Trennen“ while an obfuscated connect is still starting cancels it and stops its relay", async () => {
    let open = () => undefined as void;
    const relayGate = new Promise<void>((resolve) => (open = resolve));
    const { vpn, relays } = setup({ mode: "on", relayGate });
    const connecting = vpn.connect("fra").catch((error: unknown) => error);
    await vi.waitFor(() => expect(vpn.getStatus().phase).toBe("connecting"));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const disconnecting = vpn.disconnect();
    open();
    expect(codeOf(await connecting)).toBe("invalid");
    await disconnecting;
    expect(relays).toHaveLength(1);
    expect(relays[0]!.stopped).toBe(true);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", obfuscated: false });
  });

  it("the renderer never gets the token (account without obfsToken)", async () => {
    const { vpn } = setup({ mode: "on" });
    await vpn.connect("fra");
    expect(JSON.stringify(await vpn.account())).not.toContain("obfs-token");
  });
});

describe("obfuscated tunnel with the quantum-resistant tunnel", () => {
  it("PQ phases keep the relay as endpoint (never the node's UDP port) and the bypassing AllowedIPs", async () => {
    fakeNode = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X });
    await fakeNode.start();
    system.interfaceKey = "session-key-E";
    const { vpn, wireguard } = setup({ mode: "on", postQuantum: true, nodes: [node("fra", "198.51.100.7", { postQuantum: true })] });
    const status = await vpn.connect("fra");
    expect(status).toMatchObject({ quantum: "active", obfuscated: true });
    const endpoints = wireguard.transactions.flatMap((entries) => entries.filter((entry) => entry.key === "endpoint").map((entry) => entry.value));
    expect(endpoints).toEqual(["127.0.0.1:41000", "127.0.0.1:41000"]);
    const phase2 = wireguard.transactions[1]!.filter((entry) => entry.key === "allowed_ip").map((entry) => entry.value);
    expect(phase2).not.toContain("0.0.0.0/0");
    expect(phase2.some((route) => route.startsWith("198.51.100.7"))).toBe(false);
  });

  it("Auto: a PQ exchange that never gets through the plain tunnel is retried through TLS", async () => {
    fakeNode = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X });
    await fakeNode.start();
    system.interfaceKey = "session-key-E";
    system.udpBlocked = true;
    const { vpn, relays } = setup({ postQuantum: true, nodes: [node("fra", "198.51.100.7", { postQuantum: true })] });
    const status = await vpn.connect("fra");
    expect(relays).toHaveLength(1);
    expect(status).toMatchObject({ quantum: "active", obfuscated: true });
  });
});
