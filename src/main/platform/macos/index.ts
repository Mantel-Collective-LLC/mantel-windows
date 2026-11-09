import { LocalizedError } from "../../../../shared/core/i18n";
import { FLAVOR, IDENTITY } from "../../flavor";
import { tunnelDial } from "../../pq/exchange";
import { REAL_CLOCK } from "../../pq/flow";
import { encodeSet, type UapiDevice, type WireGuardControl } from "../../pq/uapi";
import type { WireGuardPaths } from "../../system/environment";
import { VpnError } from "../../vpn-error";
import { readMacWifi } from "../../net/wifi";
import { formatEndpoint } from "../../wireguard/config";
import type { InterfaceStatus } from "../../wireguard/parse";
import { singleFlight, waitUntil } from "../../poll-schedule";
import type { ServiceQuery, TunnelPlatform } from "../types";
import {
  HELPER_PROTOCOL,
  HelperCommandError,
  helperClient,
  HelperUnavailableError,
  type HelperCall,
  type HelperResponse,
} from "./helper-client";
import { installHelper } from "./install";

export const MAC_HELPER =
  FLAVOR === "debug"
    ? {
        label: "net.mantel.helper.debug",
        socket: "/var/run/net.mantel.helper.debug.sock",
        anchor: "com.apple/com.mantel.debug",
      }
    : {
        label: "net.mantel.helper",
        socket: "/var/run/net.mantel.helper.sock",
        anchor: "com.apple/com.mantel",
      };

export const HELPER_INSTALL_PATH = `/Library/PrivilegedHelperTools/${MAC_HELPER.label}`;

export type MacPlatformOptions = {
  helperBinary: string;
  appVersion: string;
  installPrompt: () => string;
  call?: HelperCall;
  uid?: number;
};

function helperFailure(error: unknown): unknown {
  if (error instanceof HelperUnavailableError) return new VpnError("helperUnavailable", "elevation");
  if (error instanceof HelperCommandError) {
    if (error.code === "pf_anchor_missing") return new VpnError("helperPfAnchor", "internal");
    if (error.code === "not_running") return new VpnError("tunnelStartFailed", "internal");
    return new LocalizedError("helperCommand", { details: `${error.code}: ${error.detail}`.slice(0, 400) });
  }
  return error;
}

async function guarded<T>(task: () => Promise<T>): Promise<T> {
  try {
    return await task();
  } catch (error) {
    throw helperFailure(error);
  }
}

export class HelperWireGuardControl implements WireGuardControl {
  constructor(private readonly call: HelperCall) {}

  async set(entries: Parameters<WireGuardControl["set"]>[0]): Promise<void> {
    await this.call({ op: "wg-set" }, encodeSet(entries));
  }

  async get(): Promise<UapiDevice> {
    const response = await this.call({ op: "status" });
    const peers = response.tunnel?.running ? response.tunnel.peers : [];
    return {
      listenPort: null,
      peers: peers.map((peer) => ({
        publicKey: peer.publicKey,
        endpoint: peer.endpoint ?? null,
        allowedIps: [],
        lastHandshakeAt: peer.lastHandshakeMs > 0 ? peer.lastHandshakeMs : null,
        rxBytes: peer.rxBytes,
        txBytes: peer.txBytes,
        persistentKeepalive: 0,
        hasPresharedKey: false,
      })),
    };
  }
}

export function interfaceStatusOf(response: HelperResponse): InterfaceStatus | null {
  const tunnel = response.tunnel;
  if (!tunnel?.running) return null;
  return {
    publicKey: tunnel.publicKey ?? "",
    peers: tunnel.peers.map((peer) => ({
      publicKey: peer.publicKey,
      endpoint: peer.endpoint ?? null,
      latestHandshakeAt: peer.lastHandshakeMs > 0 ? peer.lastHandshakeMs : null,
      rxBytes: peer.rxBytes,
      txBytes: peer.txBytes,
    })),
  };
}

export function macosPlatform(options: MacPlatformOptions): TunnelPlatform {
  const call = options.call ?? helperClient(MAC_HELPER.socket);
  let ready = false;
  let checkedAt = 0;
  let lastStatus: { at: number; response: HelperResponse } | null = null;
  const fresh = () => lastStatus !== null && Date.now() - lastStatus.at < 1500;
  const paths: WireGuardPaths = {
    directory: "/Library/PrivilegedHelperTools",
    wireguardExe: HELPER_INSTALL_PATH,
    wgExe: HELPER_INSTALL_PATH,
    source: "managed",
  };

  const refresh = async (maxAgeMs = 0): Promise<void> => {
    if (maxAgeMs > 0 && Date.now() - checkedAt < maxAgeMs) return;
    try {
      const hello = await call({ op: "hello" });
      ready = hello.protocol === HELPER_PROTOCOL && hello.version === options.appVersion && hello.flavor === FLAVOR;
    } catch {
      ready = false;
    }
    checkedAt = Date.now();
  };

  const status = singleFlight(async (): Promise<HelperResponse | null> => {
    try {
      const response = await call({ op: "status" });
      lastStatus = { at: Date.now(), response };
      return response;
    } catch {
      lastStatus = null;
      return null;
    }
  });

  const queryService = async (): Promise<ServiceQuery> => {
    const response = await status();
    return response?.tunnel?.running ? { exists: true, state: "RUNNING" } : { exists: false };
  };

  return {
    id: "macos",
    deviceLabel: "macOS",
    errors: { missing: "helperMissing", elevation: "helperUnavailable", installElevation: "helperUnavailable" },
    installNeedsElevation: false,
    fullTunnelLeakProtection: "firewall",
    pq: {
      wireguard: () => new HelperWireGuardControl(call),
      dial: tunnelDial,
      clock: REAL_CLOCK,
      sweepSecrets: async () => 0,
    },
    debugNames: { tunnelName: IDENTITY.tunnelName, serviceName: MAC_HELPER.label, firewallGroup: `pf ${MAC_HELPER.anchor}` },
    refresh: () => refresh(),
    detect: () => (ready ? paths : null),
    isElevated: async () => {
      await refresh(fresh() ? 30_000 : 3000);
      return ready;
    },
    checkPrerequisites: async () => undefined,
    install: async () => {
      await installHelper({
        helperBinary: options.helperBinary,
        flavor: FLAVOR,
        uid: options.uid ?? process.getuid?.() ?? -1,
        prompt: options.installPrompt(),
      });
      await refresh();
      if (!ready) throw new VpnError("helperInstallFailed", "internal", { details: "no answer after the setup" });
      return options.appVersion;
    },
    startTunnel: (_paths, tunnel, endpoint) =>
      guarded(async () => {
        lastStatus = null;
        await call({ op: "up", endpoint: formatEndpoint(endpoint) }, Buffer.from(tunnel.text, "utf8"));
      }),
    stopTunnel: () =>
      guarded(async () => {
        lastStatus = null;
        await call({ op: "down" });
      }),
    removeTunnelConfig: async () => undefined,
    queryService,
    waitForService: (predicate, timeoutMs) => waitUntil(queryService, predicate, timeoutMs),
    readInterfaceStatus: async () => {
      const response = fresh() ? lastStatus!.response : await status();
      return response ? interfaceStatusOf(response) : null;
    },
    enableKillSwitch: (input) =>
      guarded(async () => {
        await call({
          op: "killswitch-enable",
          killSwitch: {
            hosts: input.hosts.map((host) => ({ address: host.address, tcpPorts: host.tcpPorts, udpPorts: host.udpPorts })),
            allowLan: input.allowLan,
          },
        });
      }),
    disableKillSwitch: () =>
      guarded(async () => {
        await call({ op: "killswitch-disable" });
      }),
    killSwitchRuleCount: () =>
      guarded(async () => {
        const response = await call({ op: "killswitch-status" });
        return response.killSwitch ? Math.max(1, response.killSwitchRules ?? 1) : 0;
      }),
    pqFailureForUser,
    wifiSecurity: () => readMacWifi(),
  };
}

export function pqFailureForUser(error: unknown): unknown {
  let current: unknown = error;
  for (let depth = 0; current && depth < 6; depth++) {
    if (current instanceof HelperUnavailableError) return helperFailure(current);
    current = current instanceof Error ? current.cause : undefined;
  }
  return error;
}
