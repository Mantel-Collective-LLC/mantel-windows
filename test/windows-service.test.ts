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
const { windowsServicePlatform, SERVICE_PROTOCOL } = await import("../src/main/platform/windows-service");
const { helperClient, HelperUnavailableError, HelperCommandError } = await import("../src/main/platform/macos/helper-client");

type Request = Parameters<ReturnType<typeof helperClient>>[0];

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
const NODE: VpnNode = { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true };

class FakeService {
  log: { op: string; request: Request; payload: string | null }[] = [];
  running = false;
  wireguard = true;
  installed = true;
  rules: unknown = null;

  call = async (request: Request, payload?: Buffer) => {
    if (!this.installed) throw new HelperUnavailableError("ENOENT");
    const text = payload ? payload.toString("utf8") : null;
    payload?.fill(0);
    this.log.push({ op: request.op, request, payload: text });
    switch (request.op) {
      case "hello":
        return { ok: true, version: "2026.0.8", protocol: 1, flavor: "prod" };
      case "status":
        return {
          ok: true,
          ...(this.wireguard ? { wireguard: { directory: "C:\\ProgramData\\Mantel\\wireguard", source: "managed" } } : {}),
          service: this.running ? { exists: true, state: "RUNNING" } : { exists: false },
          tunnel: {
            running: this.running,
            publicKey: this.running ? K : undefined,
            peers: this.running ? [{ publicKey: S, endpoint: "198.51.100.7:51820", lastHandshakeMs: Date.now(), rxBytes: 5, txBytes: 6 }] : [],
          },
          killSwitch: this.rules !== null,
          killSwitchRules: this.rules ? 8 : 0,
        };
      case "up":
        if (!this.wireguard) throw new HelperCommandError("wireguard_missing", "WireGuard is not set up");
        this.running = true;
        return { ok: true };
      case "down":
        this.running = false;
        return { ok: true };
      case "install-wireguard":
        this.wireguard = true;
        return { ok: true, wireguardVersion: "0.5.3" };
      case "killswitch-enable":
        this.rules = request.killSwitch;
        return { ok: true };
      case "killswitch-disable":
        this.rules = null;
        return { ok: true };
      case "killswitch-status":
        return { ok: true, killSwitch: this.rules !== null, killSwitchRules: this.rules ? 8 : 0 };
    }
    throw new HelperCommandError("invalid", "unknown op");
  };

  ops(): string[] {
    return this.log.map((entry) => entry.op).filter((op) => op !== "hello" && op !== "status");
  }
}

let directory: string;
let fakeNode: FakeNode;
let service: FakeService;

beforeEach(async () => {
  directory = mkdtempSync(path.join(tmpdir(), "mantel-winsvc-"));
  service = new FakeService();
  fakeNode = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X });
  await fakeNode.start();
});

afterEach(async () => {
  await fakeNode.stop();
  rmSync(directory, { recursive: true, force: true });
});

function setup(settings: Partial<Account["settings"]> = {}, repair: () => Promise<void> = async () => undefined) {
  const store = new Store(directory);
  store.load();
  store.setSecrets({ token: "t".repeat(32), accountId: "acc1", paidUntil: account.paidUntil, device: null });
  const platform = windowsServicePlatform({ repair, call: service.call });
  const vpn = new VpnController(store, { dial: () => fakeNode.dial, clock: virtualClock() }, platform);
  Object.assign(vpn.api, {
    account: async () => ({ ...account, settings: { ...account.settings, ...settings }, devices: [] }),
    nodes: async () => [NODE],
    registerDevice: async (input: { name: string }) => ({
      device: { id: "dev1", name: input.name, nodeId: "fra", ipv4: X, createdOn: "2026-10-25T00:00:00.000Z" },
      config: { address: [`${X}/32`], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] },
      privateKey: K_PRIVATE,
    }),
    deleteDevice: async () => undefined,
  });
  return { vpn };
}

describe("Windows: VpnController with the Mantel Service", () => {
  it("kill switch with LAN: firewall rules (with the tunnel address) before the tunnel, all through the service", async () => {
    const { vpn } = setup({ lanAccess: true });
    await vpn.refreshPlatform();
    const status = await vpn.connect("fra");
    expect(service.ops()).toEqual(["killswitch-enable", "up"]);
    expect(service.rules).toMatchObject({ allowLan: true, tunnelAddresses: [`${X}/32`] });
    expect(service.log.find((entry) => entry.op === "up")!.payload).toMatch(/^PrivateKey = /m);
    expect(status).toMatchObject({ phase: "connected", firewallActive: true });
    await vpn.disconnect();
    expect(service.ops()).toEqual(["killswitch-enable", "up", "down", "down", "killswitch-disable"]);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", firewallActive: false });
  });

  it("service gone: the app counts as not ready, connecting is refused with the service message", async () => {
    service.installed = false;
    const { vpn } = setup();
    await vpn.refreshPlatform();
    expect(await vpn.isElevated()).toBe(false);
    expect(vpn.wireguard()).toBeNull();
    const error = await vpn.connect("fra").catch((caught: unknown) => caught);
    expect(codeOf(error)).toBe("wireguard_missing");
  });

  it("repair: runs the UAC repair when the service does not answer, then sets WireGuard up through it", async () => {
    service.installed = false;
    service.wireguard = false;
    const repair = vi.fn(async (): Promise<void> => {
      service.installed = true;
    });
    const { vpn } = setup({}, repair);
    expect(await vpn.installWireGuard()).toBe("0.5.3");
    expect(repair).toHaveBeenCalledTimes(1);
    expect(service.ops()).toEqual(["install-wireguard"]);
    expect(vpn.wireguard()?.directory).toBe("C:\\ProgramData\\Mantel\\wireguard");
  });

  it("repair declined: the service message, nothing else is tried", async () => {
    service.installed = false;
    const { vpn } = setup({}, vi.fn(async () => undefined));
    const error = await vpn.installWireGuard().catch((caught: unknown) => caught);
    expect((error as Error).message).toMatch(/hilfsdienst|helper/i);
    expect(service.log).toEqual([]);
  });
});

describe("Windows: requests to the service", () => {
  const count = (op: string) => service.log.filter((entry) => entry.op === op).length;

  it("concurrent status reads share one request; a poll's fresh answer spares the hello", async () => {
    const platform = windowsServicePlatform({ repair: async () => undefined, call: service.call });
    await platform.refresh!();
    service.log = [];
    await Promise.all([platform.queryService(), platform.queryService(), platform.readInterfaceStatus(null as never)]);
    expect(count("status")).toBe(1);
    expect(await platform.isElevated()).toBe(true);
    expect(service.log.map((entry) => entry.op)).toEqual(["status"]);
  });

  it("poll pace: every second in view, every 15 s in the tray, at once when the window comes back", async () => {
    vi.useFakeTimers();
    try {
      const { vpn } = setup();
      await vpn.refreshPlatform();
      vpn.startPolling();
      await vi.advanceTimersByTimeAsync(120_000);
      service.log = [];
      await vi.advanceTimersByTimeAsync(60_000);
      expect(count("status")).toBe(4);
      vpn.setWindowVisible(true);
      await vi.advanceTimersByTimeAsync(0);
      expect(count("status")).toBe(5);
      service.log = [];
      await vi.advanceTimersByTimeAsync(60_000);
      expect(count("status")).toBeGreaterThanOrEqual(58);
      expect(count("status")).toBeLessThanOrEqual(61);
      vpn.setWindowVisible(false);
      service.log = [];
      await vi.advanceTimersByTimeAsync(60_000);
      expect(count("status")).toBe(4);
      vpn.stopPolling();
      service.log = [];
      await vi.advanceTimersByTimeAsync(60_000);
      expect(service.log).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("Windows service framing", () => {
  let server: Server | null = null;
  afterEach(() => server?.close());

  it("every request carries the protocol version and the client; the payload follows the header", async () => {
    const address = process.platform === "win32" ? `\\\\.\\pipe\\mantel-vitest-${process.pid}` : path.join(directory, "svc.sock");
    const seen: Buffer[] = [];
    server = createServer((socket) => {
      socket.on("data", (chunk) => {
        seen.push(chunk);
        if (Buffer.concat(seen).includes("\n[Interface]")) socket.end(`${JSON.stringify({ ok: true })}\n`);
      });
    });
    await new Promise<void>((resolve) => server!.listen(address, resolve));
    const call = helperClient(address, 5000, { v: SERVICE_PROTOCOL, client: "app" });
    const payload = Buffer.from("[Interface]\nPrivateKey = x\n");
    const length = payload.length;
    await call({ op: "up" }, payload);
    const text = Buffer.concat(seen).toString("utf8");
    const header = JSON.parse(text.slice(0, text.indexOf("\n")));
    expect(header).toEqual({ v: 1, client: "app", op: "up", payloadLength: length });
    expect(payload.every((byte) => byte === 0)).toBe(true);
  });
});

describe("Windows: secrets only through the verifying mantel.exe", () => {
  it("payload requests never touch the direct pipe; a missing/refusing mantel.exe means unavailable and the key is wiped", async () => {
    const { verifiedCall } = await import("../src/main/platform/windows-service");
    const direct = vi.fn(async () => ({ ok: true }));
    const call = verifiedCall(path.join(directory, "missing-mantel.exe"), direct, { v: 1, client: "app" });
    const payload = Buffer.from("[Interface]\nPrivateKey = secret\n");
    const error = await call({ op: "up" }, payload).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(HelperUnavailableError);
    expect(direct).not.toHaveBeenCalled();
    expect(payload.every((byte) => byte === 0)).toBe(true);
    await call({ op: "status" });
    expect(direct).toHaveBeenCalledTimes(1);
  });
});
