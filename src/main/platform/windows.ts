import { rm } from "node:fs/promises";
import path from "node:path";
import { disableFirewallKillSwitch, enableFirewallKillSwitch, firewallRuleCount } from "../firewall/apply";
import { buildKillSwitchRules, FIREWALL_GROUP } from "../firewall/rules";
import { readWindowsWifi } from "../net/wifi";
import { tunnelDial } from "../pq/exchange";
import { REAL_CLOCK } from "../pq/flow";
import { execWgRunner, lockedSecretFiles, sweepSecretFiles, WgExeControl, wgFailureOf } from "../pq/wgexe";
import { assertLocked, writeLockedFile } from "../system/acl";
import { detectWireGuard, isElevated, programDataDirectory } from "../system/environment";
import { VpnError } from "../vpn-error";
import { installManagedWireGuard } from "../wireguard/bootstrap";
import {
  installTunnel,
  queryService,
  readInterfaceStatus,
  SERVICE_NAME,
  TUNNEL_NAME,
  uninstallTunnel,
  waitForService,
} from "../wireguard/service";
import type { PqDependencies, TunnelPlatform } from "./types";

const pqSecretDirectory = (): string => path.win32.join(programDataDirectory(), "pq");

const configFile = (): string => `${TUNNEL_NAME}.conf`;

const WINDOWS_PQ: PqDependencies = {
  wireguard: (paths) =>
    new WgExeControl({ tunnel: TUNNEL_NAME, runner: execWgRunner(paths.wgExe), secrets: lockedSecretFiles(pqSecretDirectory()) }),
  dial: tunnelDial,
  clock: REAL_CLOCK,
  sweepSecrets: () => sweepSecretFiles(pqSecretDirectory()),
};

function pqFailureForUser(error: unknown): unknown {
  const failure = wgFailureOf(error);
  if (failure?.failure === "missing") return new VpnError("wireguardMissing", "wireguard_missing");
  if (failure?.failure === "access") return new VpnError("tunnelNeedsAdmin", "elevation");
  return error;
}

export function windowsPlatform(): TunnelPlatform {
  return {
    id: "windows",
    deviceLabel: "Windows",
    errors: { missing: "wireguardMissing", elevation: "tunnelNeedsAdmin", installElevation: "installNeedsAdmin" },
    installNeedsElevation: true,
    fullTunnelLeakProtection: "wireguard",
    pq: WINDOWS_PQ,
    get debugNames() {
      return { tunnelName: TUNNEL_NAME, serviceName: SERVICE_NAME, firewallGroup: FIREWALL_GROUP };
    },
    detect: () => detectWireGuard(),
    isElevated: () => isElevated(),
    checkPrerequisites: async (paths) => {
      if (paths.source === "managed") await assertLocked(paths.directory);
    },
    install: (onStep) => installManagedWireGuard(onStep),
    startTunnel: async (paths, tunnel) => {
      const configPath = await writeLockedFile(programDataDirectory(), configFile(), tunnel.text, { setOwner: true });
      await installTunnel(paths, configPath);
    },
    stopTunnel: (paths) => uninstallTunnel(paths),
    removeTunnelConfig: async () => {
      await rm(path.win32.join(programDataDirectory(), configFile()), { force: true });
    },
    queryService: () => queryService(),
    waitForService: (predicate, timeoutMs) => waitForService(predicate, timeoutMs),
    readInterfaceStatus: (paths) => readInterfaceStatus(paths),
    enableKillSwitch: (input) => enableFirewallKillSwitch(buildKillSwitchRules(input)),
    disableKillSwitch: () => disableFirewallKillSwitch(),
    killSwitchRuleCount: () => firewallRuleCount(),
    pqFailureForUser,
    wifiSecurity: () => readWindowsWifi(),
  };
}
