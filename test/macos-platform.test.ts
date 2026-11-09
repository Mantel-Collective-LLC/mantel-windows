import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Account, VpnNode } from "../shared/core/contract";
import { FakeNode, virtualClock } from "./pq-helpers";

vi.mock("electron", () => ({
  safeStorage: { isEncryptionAvailable: () => false, encryptString: (text: string) => Buffer.from(text), decryptString: (data: Buffer) => data.toString() },
}));

const { VpnController, codeOf } = await import("../src/main/vpn");
const { Store } = await import("../src/main/store");
const { macosPlatform, HelperWireGuardControl } = await import("../src/main/platform/macos");
const { helperClient, HelperUnavailableError, HelperCommandError } = await import("../src/main/platform/macos/helper-client");
const { installArguments } = await import("../src/main/platform/macos/install");
const { withPlatformLeakProtection } = await import("../src/main/platform/types");
const { buildTunnelConfig } = await import("../src/main/wireguard/config");

type HelperRequest = Parameters<ReturnType<typeof helperClient>>[0];

const S = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
const K_PRIVATE = "pSR7d2h8H6wS0RjX9z/ftpIAVDAsuu/flQQStRtweZ0=";
const K = "pLLGZN3M20E9HOfCw9BTwB1UWPNJLHZEkJS0Bi4uKxw=";
const X = "10.8.0.2";
const VERSION = "2026.9.9";

const account: Account = {
  id: "acc1",
  paidUntil: "2030-01-01T00:00:00.000Z",
  settings: { killSwitch: true, lanAccess: false, ipv6: false, dns: { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false } },
  devices: [],
};

const NODE: VpnNode = { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true, postQuantum: true };

class FakeHelper {
  log: { op: string; request: HelperRequest; payload: string | null }[] = [];
  installed = true;
  version = VERSION;
  running = false;
  interfaceKey = "";
  handshakeMs = 0;
  killSwitch: unknown = null;
  failWgSet: Error | null = null;
  transactions: string[][] = [];

  call = async (request: HelperRequest, payload?: Buffer) => {
    if (!this.installed) throw new HelperUnavailableError("ENOENT");
    const text = payload ? payload.toString("utf8") : null;
    payload?.fill(0);
    this.log.push({ op: request.op, request, payload: text });
    switch (request.op) {
      case "hello":
        return { ok: true, version: this.version, protocol: 1, flavor: "prod" };
      case "up":
        this.running = true;
        this.interfaceKey = K;
        this.handshakeMs = Date.now();
        return { ok: true, interface: "utun7" };
      case "down":
        this.running = false;
        return { ok: true };
      case "status":
        return {
          ok: true,
          tunnel: {
            running: this.running,
            interface: this.running ? "utun7" : undefined,
            publicKey: this.running ? this.interfaceKey : undefined,
            peers: this.running ? [{ publicKey: S, endpoint: "198.51.100.7:51820", lastHandshakeMs: this.handshakeMs, rxBytes: 5, txBytes: 6 }] : [],
          },
          killSwitch: this.killSwitch !== null,
          killSwitchRules: this.killSwitch ? 12 : 0,
        };
      case "wg-set": {
        if (this.failWgSet) throw this.failWgSet;
        const lines = (text ?? "").split("\n").filter((line) => line.length > 0 && line !== "set=1");
        this.transactions.push(lines);
        if (lines.some((line) => line.startsWith("private_key="))) {
          this.handshakeMs = Date.now() + 1000;
          if (this.transactions.length > 1) this.interfaceKey = "session-key-E";
        }
        return { ok: true };
      }
      case "killswitch-enable":
        this.killSwitch = request.killSwitch;
        return { ok: true };
      case "killswitch-disable":
        this.killSwitch = null;
        return { ok: true };
      case "killswitch-status":
        return { ok: true, killSwitch: this.killSwitch !== null, killSwitchRules: this.killSwitch ? 12 : 0 };
    }
    throw new HelperCommandError("invalid", "unknown op");
  };

  ops(): string[] {
    return this.log.map((entry) => entry.op).filter((op) => op !== "hello" && op !== "status");
  }
}

let directory: string;
let fakeNode: FakeNode;
let helper: FakeHelper;

beforeEach(async () => {
  directory = mkdtempSync(path.join(tmpdir(), "mantel-macos-"));
  helper = new FakeHelper();
  fakeNode = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X });
  await fakeNode.start();
});

afterEach(async () => {
  await fakeNode.stop();
  rmSync(directory, { recursive: true, force: true });
});

function setup(options: { postQuantum?: boolean; settings?: Partial<Account["settings"]> } = {}) {
  const store = new Store(directory);
  store.load();
  if (options.postQuantum) store.setPreferences({ ...store.getPreferences(), postQuantum: true });
  store.setSecrets({ token: "t".repeat(32), accountId: "acc1", paidUntil: account.paidUntil, device: null });
  const platform = macosPlatform({ helperBinary: "/Applications/Mantel.app/Contents/Resources/helper/mantel-helper", appVersion: VERSION, installPrompt: () => "x", call: helper.call });
  const vpn = new VpnController(store, { dial: () => fakeNode.dial, clock: virtualClock() }, platform);
  const registerDevice = vi.fn(async (input: { name: string }) => ({
    device: { id: "dev1", name: input.name, nodeId: "fra", ipv4: X, createdOn: "2026-10-25T00:00:00.000Z" },
    config: { address: [`${X}/32`], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] },
    privateKey: K_PRIVATE,
  }));
  Object.assign(vpn.api, {
    account: async () => ({ ...account, settings: { ...account.settings, ...options.settings }, devices: [] }),
    nodes: async () => [NODE],
    registerDevice,
    deleteDevice: async () => undefined,
  });
  return { vpn, store, registerDevice };
}

describe("macOS: VpnController with the helper", () => {
  it("full tunnel with kill switch: pf rules before the tunnel, leak protection by pf, device named macOS", async () => {
    const { vpn, registerDevice } = setup();
    const status = await vpn.connect("fra");
    expect(helper.ops()).toEqual(["killswitch-enable", "up"]);
    const up = helper.log.find((entry) => entry.op === "up")!;
    expect(up.request).toEqual({ op: "up", endpoint: "198.51.100.7:51820" });
    expect(up.payload).toMatch(/^PrivateKey = /m);
    expect(up.payload).toMatch(/^Endpoint = 198\.51\.100\.7:51820$/m);
    expect(up.payload).toMatch(/^AllowedIPs = 0\.0\.0\.0\/0, ::\/0$/m);
    expect(helper.killSwitch).toMatchObject({ allowLan: false, hosts: expect.arrayContaining([{ address: "198.51.100.7", tcpPorts: [], udpPorts: [51820] }]) });
    expect(status).toMatchObject({ phase: "connected", leakProtection: "firewall", firewallActive: true });
    expect(registerDevice.mock.calls[0]?.[0].name).toMatch(/^macOS [0-9A-F]{4}$/);

    await vpn.disconnect();
    expect(helper.ops()).toEqual(["killswitch-enable", "up", "down", "killswitch-disable"]);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", firewallActive: false });
  });

  it("version check asks for the Mac release (platform=macos), not the Windows one", async () => {
    const { vpn } = setup();
    const appVersion = vi.fn(async (platform: string) => ({
      platform: platform as "macos",
      latest: "2026.0.3",
      minimum: "2026.0.3",
      downloadUrl: "/download",
      notes: null,
      sha256: null,
    }));
    Object.assign(vpn.api, { appVersion });
    await vpn.checkAppVersion();
    expect(vpn.platform.id).toBe("macos");
    expect(appVersion).toHaveBeenCalledWith("macos");
  });

  it("without kill switch no pf rules", async () => {
    const { vpn } = setup({ settings: { killSwitch: false } });
    const status = await vpn.connect("fra");
    expect(helper.ops()).toEqual(["up"]);
    expect(status.leakProtection).toBe("none");
  });

  it("helper not set up: refused with the helper message before anything happens", async () => {
    helper.installed = false;
    const { vpn, registerDevice } = setup();
    const error = await vpn.connect("fra").catch((caught: unknown) => caught);
    expect(codeOf(error)).toBe("wireguard_missing");
    expect((error as Error).message).toMatch(/helper|hilfsdienst/i);
    expect(registerDevice).not.toHaveBeenCalled();
    expect(await vpn.isElevated()).toBe(false);
  });

  it("helper of another version counts as not set up", async () => {
    helper.version = "2026.0.1";
    const { vpn } = setup();
    await vpn.refreshPlatform();
    expect(vpn.wireguard()).toBeNull();
    helper.version = VERSION;
    await vpn.refreshPlatform();
    expect(vpn.wireguard()?.wireguardExe).toBe("/Library/PrivilegedHelperTools/net.mantel.helper");
  });

  it("PQ: inert config, both phases through wg-set, quantum active", async () => {
    const { vpn } = setup({ postQuantum: true });
    const status = await vpn.connect("fra");
    const up = helper.log.find((entry) => entry.op === "up")!;
    expect(up.payload).not.toMatch(/^Endpoint/m);
    expect(up.request).toEqual({ op: "up", endpoint: "198.51.100.7:51820" });
    expect(helper.transactions).toHaveLength(2);
    expect(helper.transactions[0]).toContain("allowed_ip=10.8.255.1/32");
    expect(helper.transactions[0]?.[0]).toBe(`private_key=${Buffer.from(K_PRIVATE, "base64").toString("hex")}`);
    expect(helper.transactions[1]).toContain(`preshared_key=${fakeNode.psks[0]!.toString("hex")}`);
    expect(status).toMatchObject({ phase: "connected", quantum: "active" });
  });

  it("PQ with the helper gone mid-way: helper message, tunnel removed", async () => {
    helper.failWgSet = new HelperUnavailableError("ECONNREFUSED");
    const { vpn } = setup({ postQuantum: true });
    const error = await vpn.connect("fra").catch((caught: unknown) => caught);
    expect(codeOf(error)).toBe("elevation");
    expect((error as Error).message).toMatch(/helper|hilfsdienst/i);
    expect(fakeNode.hellos).toHaveLength(0);
    expect(helper.running).toBe(false);
  });

  it("kill switch rule count comes from the helper", async () => {
    const { vpn } = setup();
    await vpn.detectFirewall();
    expect(vpn.getStatus().firewallActive).toBe(false);
    await vpn.setAlwaysOn(true).catch(() => undefined);
    helper.killSwitch = { hosts: [], allowLan: false };
    await vpn.detectFirewall();
    expect(vpn.getStatus().firewallActive).toBe(true);
  });
});

describe("macOS: pieces", () => {
  it("leak protection: Windows keeps the full-tunnel config as is, macOS needs pf for it", () => {
    const tunnel = buildTunnelConfig({
      privateKey: K_PRIVATE,
      server: { address: [`${X}/32`], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] },
      endpoint: { host: "198.51.100.7", port: 51820 },
      settings: { killSwitch: true, lanAccess: false, ipv6: false },
    });
    expect(withPlatformLeakProtection(tunnel, "wireguard")).toBe(tunnel);
    expect(withPlatformLeakProtection(tunnel, "firewall")).toMatchObject({ leakProtection: "firewall", firewallRequired: true, allowedIps: tunnel.allowedIps });
  });

  it("HelperWireGuardControl sends UAPI with hex keys and maps the peer list", async () => {
    const control = new HelperWireGuardControl(helper.call);
    await helper.call({ op: "up", endpoint: "198.51.100.7:51820" }, Buffer.from("x"));
    await control.set([
      ["public_key", Buffer.from(S, "base64")],
      ["endpoint", "198.51.100.7:51820"],
    ]);
    const wgSet = helper.log.find((entry) => entry.op === "wg-set")!;
    expect(wgSet.payload).toBe(`set=1\npublic_key=${Buffer.from(S, "base64").toString("hex")}\nendpoint=198.51.100.7:51820\n\n`);
    helper.handshakeMs = 1_700_000_000_000;
    const device = await control.get();
    expect(device.peers[0]).toMatchObject({ publicKey: S, lastHandshakeAt: 1_700_000_000_000, rxBytes: 5, txBytes: 6 });
  });

  it("osascript setup: every value is its own argv item, quoted by AppleScript", () => {
    const args = installArguments({ helperBinary: "/Volumes/Mantel 1/Mantel.app/Contents/Resources/helper/mantel-helper", flavor: "prod", uid: 501, prompt: "Mantel möchte …" });
    expect(args.slice(-4)).toEqual(["/Volumes/Mantel 1/Mantel.app/Contents/Resources/helper/mantel-helper", "prod", "501", "Mantel möchte …"]);
    expect(args.filter((arg) => arg === "-e")).toHaveLength(3);
    expect(args.join(" ")).toContain("quoted form of (item 1 of argv)");
    expect(() => installArguments({ helperBinary: "relative/helper", flavor: "prod", uid: 501, prompt: "" })).toThrow();
    expect(() => installArguments({ helperBinary: "/x", flavor: "prod", uid: 0, prompt: "" })).toThrow();
  });
});

describe("macOS: helper client over a socket", () => {
  let server: Server | null = null;
  const socketPath = () =>
    process.platform === "win32" ? `\\\\.\\pipe\\mantel-helper-test-${process.pid}-${Date.now()}` : path.join(directory, "helper.sock");

  afterEach(async () => {
    await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
    server = null;
  });

  async function serve(answer: (header: Record<string, unknown>, payload: Buffer) => string): Promise<string> {
    const target = socketPath();
    server = createServer((socket) => {
      let data = Buffer.alloc(0);
      socket.on("data", (chunk: Buffer) => {
        data = Buffer.concat([data, chunk]);
        const end = data.indexOf(0x0a);
        if (end < 0) return;
        const header = JSON.parse(data.subarray(0, end).toString("utf8")) as Record<string, unknown>;
        const length = typeof header.payloadLength === "number" ? header.payloadLength : 0;
        if (data.length < end + 1 + length) return;
        socket.end(`${answer(header, data.subarray(end + 1, end + 1 + length))}\n`);
      });
    });
    await new Promise<void>((resolve) => server!.listen(target, resolve));
    return target;
  }

  it("sends header + raw payload, zeroes the payload, parses the answer", async () => {
    let seen: { header: Record<string, unknown>; payload: string } | null = null;
    const target = await serve((header, payload) => {
      seen = { header, payload: payload.toString("utf8") };
      return JSON.stringify({ ok: true, interface: "utun3" });
    });
    const payload = Buffer.from("[Interface]\nPrivateKey = secret\n");
    const response = await helperClient(target)({ op: "up", endpoint: "198.51.100.7:51820" }, payload);
    expect(response.interface).toBe("utun3");
    expect(seen).toEqual({ header: { op: "up", endpoint: "198.51.100.7:51820", payloadLength: 32 }, payload: "[Interface]\nPrivateKey = secret\n" });
    expect(payload.every((byte) => byte === 0)).toBe(true);
  });

  it("maps refusals and a missing helper", async () => {
    const forbidden = await serve(() => JSON.stringify({ ok: false, error: "forbidden" }));
    await expect(helperClient(forbidden)({ op: "hello" })).rejects.toBeInstanceOf(HelperUnavailableError);
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    const failing = await serve(() => JSON.stringify({ ok: false, error: "pf_anchor_missing", detail: "custom pf.conf" }));
    await expect(helperClient(failing)({ op: "killswitch-disable" })).rejects.toMatchObject({ code: "pf_anchor_missing" });
    await expect(helperClient(`${failing}-missing`)({ op: "hello" })).rejects.toBeInstanceOf(HelperUnavailableError);
  });
});
