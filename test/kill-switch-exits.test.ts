import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Account, AccountSettings, VpnNode } from "../shared/core/contract";
import { blockReason } from "../shared/ui/src/lib/protection";

const system = vi.hoisted(() => ({
  installs: 0,
  uninstalls: 0,
  service: { exists: false, state: null as string | null },
  firewallOn: 0,
  firewallOff: 0,
  wireguard: true,
  elevated: true,
  uninstallFails: false,
}));

vi.mock("electron", () => ({
  safeStorage: { isEncryptionAvailable: () => false, encryptString: (text: string) => Buffer.from(text), decryptString: (data: Buffer) => data.toString() },
}));
vi.mock("../src/main/system/environment", () => ({
  detectWireGuard: () =>
    system.wireguard ? { directory: "C:\\WG", wireguardExe: "C:\\WG\\wireguard.exe", wgExe: "C:\\WG\\wg.exe", source: "system" } : null,
  isElevated: async () => system.elevated,
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
    if (system.uninstallFails) throw new Error("uninstall failed");
    system.uninstalls++;
    system.service = { exists: false, state: null };
  },
  queryService: async () => system.service,
  waitForService: async () => system.service,
  readInterfaceStatus: async () => ({
    publicKey: "",
    peers: [{ publicKey: "x", endpoint: "198.51.100.7:51820", latestHandshakeAt: Date.now(), rxBytes: 1, txBytes: 2 }],
  }),
}));

const { VpnController } = await import("../src/main/vpn");
const { Store } = await import("../src/main/store");
const { autostartTaskXml, connectAtLogin, quitPlan, windowsLauncher, AUTOSTART_FLAG } = await import("../src/main/lifecycle");

const FRA: VpnNode = { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true };
const S = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
const K_PRIVATE = "pSR7d2h8H6wS0RjX9z/ftpIAVDAsuu/flQQStRtweZ0=";
const DNS_OFF = { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false };

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "mantel-exits-"));
  Object.assign(system, {
    installs: 0,
    uninstalls: 0,
    service: { exists: false, state: null },
    firewallOn: 0,
    firewallOff: 0,
    wireguard: true,
    elevated: true,
    uninstallFails: false,
  });
});
afterEach(() => rmSync(directory, { recursive: true, force: true }));

function controller() {
  const store = new Store(directory);
  store.load();
  store.setSecrets({ token: "t".repeat(32), accountId: "acc1", paidUntil: "2030-01-01T00:00:00.000Z", device: null });
  const vpn = new VpnController(store, { sweepSecrets: async () => undefined });
  const settings: AccountSettings = { killSwitch: true, lanAccess: false, ipv6: false, dns: DNS_OFF };
  let devices: Account["devices"] = [];
  const api = {
    account: async (): Promise<Account> => ({ id: "acc1", paidUntil: "2030-01-01T00:00:00.000Z", settings: { ...settings }, devices }),
    nodes: async () => [FRA],
    registerDevice: async () => {
      const device = { id: `dev${devices.length + 1}`, name: "Windows AB12", nodeId: "fra", ipv4: "10.8.0.2", createdOn: "2026-11-05" };
      devices = [...devices, device];
      return {
        device,
        config: { address: ["10.8.0.2/32"], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] },
        privateKey: K_PRIVATE,
      };
    },
    deleteDevice: async () => undefined,
    rotateDeviceKey: async (id: string) => ({
      device: { id, name: "Windows AB12", nodeId: "fra", ipv4: "10.8.0.2", createdOn: "2026-11-05" },
      config: { address: ["10.8.0.2/32"], dns: ["10.8.0.1"], serverPublicKey: S, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0"] },
    }),
  };
  Object.assign(vpn.api, api);
  return { store, vpn, api };
}

describe("disconnect is always a way out of the kill switch", () => {
  it("lifts the rules even when the tunnel cannot be stopped (and still reports the error)", async () => {
    const { vpn } = controller();
    await vpn.connect("fra");
    system.uninstallFails = true;
    await expect(vpn.disconnect()).rejects.toThrow("uninstall failed");
    expect(system.firewallOff).toBe(1);
    expect(vpn.getStatus().firewallActive).toBe(false);
  });

  it("lifts the rules when WireGuard was removed behind Mantel's back", async () => {
    const { vpn } = controller();
    await vpn.connect("fra");
    system.wireguard = false;
    await vpn.disconnect();
    expect(system.firewallOff).toBe(1);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", firewallActive: false });
  });

  it("logging out lifts them although the tunnel could not be removed", async () => {
    const { vpn, store } = controller();
    await vpn.connect("fra");
    system.uninstallFails = true;
    await expect(vpn.logout()).rejects.toThrow();
    expect(system.firewallOff).toBe(1);
    expect(store.getSecrets().token).toBeNull();
  });

  it("switching the permanent kill switch off needs neither admin rights nor WireGuard", async () => {
    const { vpn, store } = controller();
    await vpn.setAlwaysOn(true);
    system.elevated = false;
    system.wireguard = false;
    await vpn.setAlwaysOn(false);
    expect(store.getPreferences().alwaysOnKillSwitch).toBe(false);
    expect(system.firewallOff).toBe(1);
  });
});

describe("a running connect can be cancelled", () => {
  it("'Trennen' while connecting stops the attempt at its next step, nothing stays behind", async () => {
    const { vpn, api } = controller();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const account = api.account;
    Object.assign(vpn.api, {
      account: async () => {
        await gate;
        return account();
      },
    });
    const phases: string[] = [];
    vpn.on("status", (status: { phase: string }) => phases.push(status.phase));
    const connecting = vpn.connect("fra");
    await vi.waitFor(() => expect(vpn.getStatus().phase).toBe("connecting"));
    const disconnecting = vpn.disconnect();
    expect(vpn.getStatus().phase).toBe("disconnecting");
    release();
    await expect(connecting).rejects.toMatchObject({ i18n: { key: "connectCancelled" } });
    await disconnecting;
    expect(system.installs).toBe(0);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", firewallActive: false });
  });

  it("'Trennen' during a key rotation: no reconnect afterwards", async () => {
    const { vpn } = controller();
    await vpn.connect("fra");
    expect(system.installs).toBe(1);
    const rotation = vpn.rotateDeviceKey();
    const disconnecting = vpn.disconnect();
    await rotation;
    await disconnecting;
    expect(system.installs).toBe(1);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", firewallActive: false });
  });
});

describe("way-out banner (lib/protection.ts blockReason)", () => {
  const base = { android: false, firewallActive: true, alwaysOnKillSwitch: false, systemLockdown: null };
  it("names why the internet is blocked without a working tunnel", () => {
    expect(blockReason({ ...base, phase: "stale" })).toBe("lost");
    expect(blockReason({ ...base, phase: "disconnected", alwaysOnKillSwitch: true })).toBe("alwaysOn");
    expect(blockReason({ ...base, phase: "disconnected" })).toBe("leftover");
    expect(blockReason({ ...base, android: true, phase: "disconnected", systemLockdown: true })).toBe("android");
  });
  it("stays away while connected, connecting or without rules", () => {
    expect(blockReason({ ...base, phase: "connected" })).toBeNull();
    expect(blockReason({ ...base, phase: "connecting" })).toBeNull();
    expect(blockReason({ ...base, firewallActive: false, phase: "stale" })).toBeNull();
    expect(blockReason({ ...base, android: true, phase: "disconnected", systemLockdown: false })).toBeNull();
  });
});

describe("start at login (Windows task)", () => {
  it("starts the installed exe (not elevated) at this user's logon, without the 72 h limit or battery stop", () => {
    const xml = autostartTaskXml({ exe: "C:\\Program Files\\Mantel\\Mantel.exe", user: "PC\\luke & co", description: "Mantel" });
    expect(xml).toContain("<Command>\"C:\\Program Files\\Mantel\\Mantel.exe\"</Command>");
    expect(xml).toContain(`<Arguments>${AUTOSTART_FLAG}</Arguments>`);
    expect(xml).toContain("<RunLevel>LeastPrivilege</RunLevel>");
    expect(xml).toContain("<LogonType>InteractiveToken</LogonType>");
    expect(xml).toContain("<LogonTrigger><Enabled>true</Enabled><UserId>PC\\luke &amp; co</UserId>");
    expect(xml).toContain("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>");
    expect(xml).toContain("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>");
    expect(xml).toContain("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>");
  });

  it("registers through PowerShell (XML in the environment) and removes with schtasks, per variant", async () => {
    const calls: Array<{ file: string; args: readonly string[]; env?: Record<string, string> }> = [];
    let exists = false;
    const runner = async (file: string, args: readonly string[], options?: { env?: Record<string, string> }) => {
      calls.push({ file, args, env: options?.env });
      if (args.includes("/Query")) return { code: exists ? 0 : 1, stdout: "", stderr: "" };
      if (args.includes("/Delete")) exists = false;
      else exists = true;
      return { code: 0, stdout: "ok", stderr: "" };
    };
    const launcher = windowsLauncher({
      packaged: true,
      exe: "C:\\Program Files\\Mantel Debug\\MantelDebug.exe",
      taskName: "Mantel Debug Autostart",
      description: "d",
      user: () => "PC\\luke",
      runner,
    });
    expect(await launcher.isEnabled()).toBe(false);
    await launcher.setEnabled(true);
    const register = calls.find((call) => call.file.toLowerCase().endsWith("powershell.exe"))!;
    expect(register.env?.MANTEL_TASK).toBe("Mantel Debug Autostart");
    expect(register.env?.MANTEL_TASK_XML).toContain("MantelDebug.exe");
    expect(await launcher.isEnabled()).toBe(true);
    await launcher.setEnabled(false);
    expect(calls.some((call) => call.args.join(" ") === "/Delete /TN Mantel Debug Autostart /F")).toBe(true);
    expect(await launcher.isEnabled()).toBe(false);
  });

  it("is not offered when started from source", () => {
    expect(windowsLauncher({ packaged: false, exe: "electron.exe", taskName: "x", description: "d" }).supported).toBe(false);
  });

  it("connects after the start, retrying while the network comes up, and never twice", async () => {
    let attempts = 0;
    const network = Object.assign(new Error("offline"), { network: true });
    const connected = await connectAtLogin({
      ready: () => ({ loggedIn: true, nodeId: "fra", tunnelActive: false }),
      connect: async () => {
        attempts++;
        if (attempts < 3) throw network;
      },
      retryable: (error) => (error as { network?: boolean }).network === true,
      sleep: async () => undefined,
    });
    expect(connected).toBe(true);
    expect(attempts).toBe(3);

    const connect = vi.fn(async () => undefined);
    expect(await connectAtLogin({ ready: () => ({ loggedIn: true, nodeId: "fra", tunnelActive: true }), connect, retryable: () => true })).toBe(false);
    expect(await connectAtLogin({ ready: () => ({ loggedIn: false, nodeId: "fra", tunnelActive: false }), connect, retryable: () => true })).toBe(false);
    expect(connect).not.toHaveBeenCalled();
    const failing = vi.fn(async () => {
      throw new Error("expired");
    });
    expect(await connectAtLogin({ ready: () => ({ loggedIn: true, nodeId: "fra", tunnelActive: false }), connect: failing, retryable: () => false })).toBe(false);
    expect(failing).toHaveBeenCalledTimes(1);
  });
});

describe("quitting", () => {
  it("uses a remembered choice only for a working connection", () => {
    expect(quitPlan("disconnected", "keep")).toBe("quit");
    expect(quitPlan("connected", undefined)).toBe("ask");
    expect(quitPlan("connected", "ask")).toBe("ask");
    expect(quitPlan("connected", "keep")).toBe("keep");
    expect(quitPlan("connected", "disconnect")).toBe("disconnect");
    expect(quitPlan("stale", "keep")).toBe("ask");
    expect(quitPlan("connecting", "keep")).toBe("ask");
    expect(quitPlan("connected", "keep", true)).toBe("ask");
    expect(quitPlan("connected", "disconnect", true)).toBe("disconnect");
  });
});
