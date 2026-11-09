import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Account, AccountSettings, TunnelPhase, VpnNode, WifiSecurity } from "../shared/core/contract";
import { DICTIONARIES } from "../shared/core/i18n";
import { shouldAutoConnect, showOpenWifiWarning } from "../shared/core/wifi";
import { protectionSummary } from "../shared/ui/src/lib/protection";
import { parseAirportProfile, parseNetshInterfaces } from "../src/main/net/wifi";

const system = vi.hoisted(() => ({
  installs: 0,
  uninstalls: 0,
  service: { exists: false, state: null as string | null },
  firewallOn: 0,
  firewallOff: 0,
  wifi: "none" as string,
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
    publicKey: "",
    peers: [{ publicKey: "x", endpoint: "198.51.100.7:51820", latestHandshakeAt: Date.now(), rxBytes: 1, txBytes: 2 }],
  }),
}));
vi.mock("../src/main/net/wifi", async (original) => ({
  ...(await original<typeof import("../src/main/net/wifi")>()),
  readWindowsWifi: async () => system.wifi,
}));

const { VpnController } = await import("../src/main/vpn");
const { Store } = await import("../src/main/store");

const TEXT = DICTIONARIES.en.errors;
const FRA: VpnNode = { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true };
const AMS: VpnNode = { id: "ams", city: "Amsterdam", country: "NL", endpointHost: "198.51.100.8", endpointPort: 51820, online: true };
const S = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
const K_PRIVATE = "pSR7d2h8H6wS0RjX9z/ftpIAVDAsuu/flQQStRtweZ0=";
const DNS_OFF = { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false };

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "mantel-leak-"));
  Object.assign(system, { installs: 0, uninstalls: 0, service: { exists: false, state: null }, firewallOn: 0, firewallOff: 0, wifi: "none" });
});
afterEach(() => rmSync(directory, { recursive: true, force: true }));

function controller(options: { killSwitch?: boolean } = {}) {
  const store = new Store(directory);
  store.load();
  store.setSecrets({ token: "t".repeat(32), accountId: "acc1", paidUntil: "2030-01-01T00:00:00.000Z", device: null });
  const vpn = new VpnController(store, { sweepSecrets: async () => undefined });
  const settings: AccountSettings = { killSwitch: options.killSwitch ?? true, lanAccess: false, ipv6: false, dns: DNS_OFF };
  const nodes = [FRA, AMS];
  let devices: Account["devices"] = [];
  Object.assign(vpn.api, {
    account: async (): Promise<Account> => ({ id: "acc1", paidUntil: "2030-01-01T00:00:00.000Z", settings: { ...settings }, devices }),
    nodes: async () => nodes,
    updateSettings: async (patch: Partial<AccountSettings>) => ({ ...Object.assign(settings, patch) }),
    registerDevice: async (input: { nodeId: string }) => {
      const node = nodes.find((entry) => entry.id === input.nodeId) ?? FRA;
      const device = { id: `dev${devices.length + 1}`, name: "Windows AB12", nodeId: node.id, ipv4: "10.8.0.2", createdOn: "2026-11-04" };
      devices = [...devices, device];
      const endpoint = `${node.endpointHost}:${node.endpointPort}`;
      return { device, config: { address: ["10.8.0.2/32"], dns: ["10.8.0.1"], serverPublicKey: S, endpoint, allowedIps: ["0.0.0.0/0"] }, privateKey: K_PRIVATE };
    },
    deleteDevice: async () => undefined,
  });
  return { store, vpn, nodes, settings };
}

describe("kill switch around the tunnel (Windows)", () => {
  it("a full tunnel with kill switch also gets the firewall rules, kept for the tunnel's lifetime", async () => {
    const { vpn, store } = controller();
    await vpn.connect("fra");
    expect(vpn.getStatus()).toMatchObject({ phase: "connected", leakProtection: "wireguard", firewallActive: true });
    expect(system.firewallOn).toBe(1);
    expect(store.getRuntime().firewallForTunnel).toBe(true);
    await vpn.connect("ams");
    expect(system.firewallOn).toBe(2);
    expect(system.firewallOff).toBe(0);
    await vpn.disconnect();
    expect(system.firewallOff).toBe(1);
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", firewallActive: false });
  });

  it("a crashed or removed tunnel service stays blocked and is shown as lost until the user disconnects", async () => {
    const { vpn } = controller();
    await vpn.connect("fra");
    system.service = { exists: false, state: null };
    await vpn.refreshStatus();
    expect(vpn.getStatus()).toMatchObject({ phase: "stale", firewallActive: true, error: TEXT.tunnelLostBlocked });
    expect(system.firewallOff).toBe(0);
    await vpn.disconnect();
    expect(system.firewallOff).toBe(1);
    expect(vpn.getStatus().phase).toBe("disconnected");
  });

  it("a failed location switch removes the tunnel but keeps the rules (no leak, no half tunnel)", async () => {
    const { vpn, nodes } = controller();
    await vpn.connect("fra");
    nodes[1] = { ...AMS, online: false };
    await expect(vpn.connect("ams")).rejects.toThrow();
    expect(system.uninstalls).toBe(1);
    expect(system.firewallOff).toBe(0);
    expect(vpn.getStatus()).toMatchObject({ phase: "stale", firewallActive: true });
    await vpn.refreshStatus();
    expect(vpn.getStatus().phase).toBe("stale");
  });

  it("a failed first connect leaves nothing behind", async () => {
    const { vpn, nodes } = controller();
    nodes[0] = { ...FRA, online: false };
    await expect(vpn.connect("fra")).rejects.toThrow();
    expect(vpn.getStatus()).toMatchObject({ phase: "disconnected", firewallActive: false });
    expect(system.firewallOn).toBe(0);
  });

  it("without kill switch there are no rules; switching it off removes them once the new tunnel runs", async () => {
    const { vpn } = controller({ killSwitch: false });
    await vpn.connect("fra");
    expect(vpn.getStatus()).toMatchObject({ phase: "connected", leakProtection: "none", firewallActive: false });
    expect(system.firewallOn).toBe(0);

    const protectedTunnel = controller();
    await protectedTunnel.vpn.connect("fra");
    await protectedTunnel.vpn.updateSettings({ killSwitch: false });
    await vi.waitFor(() => expect(system.firewallOff).toBe(1));
    expect(protectedTunnel.vpn.getStatus()).toMatchObject({ phase: "connected", firewallActive: false, leakProtection: "none" });
  });
});

describe("open Wi-Fi: auto-connect (main process)", () => {
  it("connects once when an open Wi-Fi appears, only with the setting on", async () => {
    const { vpn, store } = controller({ killSwitch: false });
    store.setPreferences({ ...store.getPreferences(), lastNodeId: "fra" });
    system.wifi = "open";
    await vpn.checkOpenWifi();
    expect(system.installs).toBe(0);

    vpn.setAutoConnectOpenWifi(true);
    expect(store.getPreferences().autoConnectOpenWifi).toBe(true);
    await vpn.checkOpenWifi();
    expect(vpn.getStatus().phase).toBe("connected");
    await vpn.disconnect();
    await vpn.checkOpenWifi();
    expect(vpn.getStatus().phase).toBe("disconnected");
    system.wifi = "secured";
    await vpn.checkOpenWifi();
    system.wifi = "open";
    await vpn.checkOpenWifi();
    expect(vpn.getStatus().phase).toBe("connected");
    expect(system.installs).toBe(2);
  });
});

describe("open Wi-Fi: rules and parsers", () => {
  it("decides warning and auto-connect", () => {
    expect(showOpenWifiWarning("open", "disconnected")).toBe(true);
    expect(showOpenWifiWarning("open", "connected")).toBe(false);
    expect(showOpenWifiWarning("secured", "disconnected")).toBe(false);
    expect(showOpenWifiWarning(null, "disconnected")).toBe(false);
    const base = { previous: "none" as WifiSecurity | null, current: "open" as WifiSecurity, enabled: true, phase: "disconnected" as TunnelPhase, hasLocation: true };
    expect(shouldAutoConnect(base)).toBe(true);
    expect(shouldAutoConnect({ ...base, previous: null })).toBe(true);
    expect(shouldAutoConnect({ ...base, previous: "open" })).toBe(false);
    expect(shouldAutoConnect({ ...base, enabled: false })).toBe(false);
    expect(shouldAutoConnect({ ...base, hasLocation: false })).toBe(false);
    expect(shouldAutoConnect({ ...base, phase: "connected" })).toBe(false);
    expect(shouldAutoConnect({ ...base, current: "unknown" })).toBe(false);
  });

  const netsh = (auth: string, cipher: string, labels = ["Authentication", "Cipher"]) =>
    [
      "There is 1 interface on the system:",
      "",
      "    Name                   : Wi-Fi",
      "    State                  : connected",
      "    SSID                   : Cafe Free",
      `    ${labels[0]}         : ${auth}`,
      `    ${labels[1]}                 : ${cipher}`,
      "",
    ].join("\r\n");

  it("reads netsh in English and German (OEM umlaut), never anything but the security", () => {
    expect(parseNetshInterfaces(netsh("Open", "None"))).toBe("open");
    expect(parseNetshInterfaces(netsh("WPA2-Personal", "CCMP"))).toBe("secured");
    expect(parseNetshInterfaces(netsh("OWE", "CCMP"))).toBe("secured");
    expect(parseNetshInterfaces(netsh("Open", "WEP"))).toBe("secured");
    expect(parseNetshInterfaces(netsh("Offen", "Keine", ["Authentifizierung", "Verschl\uFFFDsselung"]))).toBe("open");
    expect(parseNetshInterfaces(netsh("WPA3-Personal", "GCMP-256", ["Authentifizierung", "Verschlüsselung"]))).toBe("secured");
    expect(parseNetshInterfaces("There is 1 interface on the system:\r\n\r\n    Name : Wi-Fi\r\n    State : disconnected\r\n")).toBe("none");
    expect(parseNetshInterfaces("")).toBe("none");
    expect(parseNetshInterfaces(netsh("WPA2-Personal", "CCMP") + netsh("Open", "None"))).toBe("open");
  });

  it("reads the macOS Wi-Fi profile", () => {
    const profile = (mode?: string) =>
      JSON.stringify({
        SPAirPortDataType: [
          { spairport_airport_interfaces: [{ _name: "en0", ...(mode === undefined ? {} : { spairport_current_network_information: { _name: "<redacted>", spairport_security_mode: mode } }) }] },
        ],
      });
    expect(parseAirportProfile(profile("spairport_security_mode_none"))).toBe("open");
    expect(parseAirportProfile(profile("spairport_security_mode_wpa2_personal"))).toBe("secured");
    expect(parseAirportProfile(profile())).toBe("none");
    expect(parseAirportProfile("not json")).toBe("unknown");
  });
});

describe("protection overview", () => {
  const settings = { killSwitch: true, ipv6: false };

  it("desktop: kill switch, DNS and IPv6 by tunnel state", () => {
    expect(protectionSummary({ android: false, settings, phase: "connected", blocking: true })).toEqual({
      killSwitch: { level: "on", state: "killSwitchOn" },
      dns: { level: "on", state: "dnsTunnel" },
      ipv6: { level: "on", state: "ipv6Blocked" },
    });
    expect(protectionSummary({ android: false, settings: { killSwitch: false, ipv6: true }, phase: "connected", blocking: false })).toEqual({
      killSwitch: { level: "warn", state: "killSwitchOff" },
      dns: { level: "warn", state: "dnsMayLeak" },
      ipv6: { level: "on", state: "ipv6Tunnel" },
    });
    expect(protectionSummary({ android: false, settings, phase: "disconnected", blocking: false }).dns).toEqual({ level: "idle", state: "idle" });
    expect(protectionSummary({ android: false, settings, phase: "disconnected", blocking: true }).ipv6).toEqual({ level: "on", state: "blocked" });
  });

  it("Android: the kill switch is only complete with the system lockdown", () => {
    expect(protectionSummary({ android: true, settings, phase: "connected", blocking: true }).killSwitch).toEqual({ level: "on", state: "killSwitchAndroid" });
    expect(protectionSummary({ android: true, settings, phase: "connected", blocking: false }).killSwitch).toEqual({ level: "warn", state: "killSwitchAppOnly" });
    expect(protectionSummary({ android: true, settings: { ...settings, killSwitch: false }, phase: "connected", blocking: false }).dns).toEqual({ level: "on", state: "dnsTunnel" });
  });

  it("every state has a text in both languages", () => {
    for (const language of ["de", "en"] as const) {
      const states = DICTIONARIES[language].settings.protection.states;
      for (const key of ["killSwitchOn", "killSwitchAndroid", "killSwitchAppOnly", "killSwitchOff", "dnsTunnel", "dnsMayLeak", "blocked", "ipv6Tunnel", "ipv6Blocked", "idle"] as const) {
        expect(states[key]).toBeTruthy();
      }
    }
  });
});
