import type { WifiSecurity } from "../../../shared/core/contract";
import type { ErrorKey } from "../../../shared/core/i18n";
import type { KillSwitchInput } from "../firewall/rules";
import type { Dial } from "../pq/exchange";
import type { Clock } from "../pq/flow";
import type { WireGuardControl } from "../pq/uapi";
import type { WireGuardPaths } from "../system/environment";
import type { Endpoint, TunnelConfig } from "../wireguard/config";
import type { InterfaceStatus, ServiceState } from "../wireguard/parse";
import type { BootstrapStep } from "../wireguard/bootstrap";
import type { ServiceRelay, StartRelay } from "../obfs/relay";

export type ServiceQuery = { exists: false } | { exists: true; state: ServiceState | null };

export type PqDependencies = {
  wireguard: (paths: WireGuardPaths) => WireGuardControl;
  dial: (tunnelIpv4: string) => Dial;
  clock: Clock;
  sweepSecrets: () => Promise<unknown>;
};

export type TunnelPlatform = {
  readonly id: "windows" | "macos";
  readonly deviceLabel: string;
  readonly errors: { missing: ErrorKey; elevation: ErrorKey; installElevation: ErrorKey };
  readonly installNeedsElevation: boolean;
  readonly fullTunnelLeakProtection: "wireguard" | "firewall";
  readonly pq: PqDependencies;
  readonly debugNames: { tunnelName: string; serviceName: string; firewallGroup: string };

  refresh?: () => Promise<void>;
  detect: () => WireGuardPaths | null;
  isElevated: () => Promise<boolean>;
  checkPrerequisites: (paths: WireGuardPaths) => Promise<void>;
  install: (onStep?: (step: BootstrapStep) => void) => Promise<string>;

  startTunnel: (paths: WireGuardPaths, tunnel: TunnelConfig, endpoint: Endpoint) => Promise<void>;
  stopTunnel: (paths: WireGuardPaths) => Promise<void>;
  removeTunnelConfig: () => Promise<void>;
  queryService: () => Promise<ServiceQuery>;
  waitForService: (predicate: (query: ServiceQuery) => boolean, timeoutMs: number) => Promise<ServiceQuery>;
  readInterfaceStatus: (paths: WireGuardPaths) => Promise<InterfaceStatus | null>;

  enableKillSwitch: (input: KillSwitchInput) => Promise<void>;
  disableKillSwitch: () => Promise<void>;
  killSwitchRuleCount: () => Promise<number>;

  pqFailureForUser: (error: unknown) => unknown;

  wifiSecurity?: () => Promise<WifiSecurity>;
  obfsRelay?: (fallback: StartRelay) => ServiceRelay;
};

export function withPlatformLeakProtection(tunnel: TunnelConfig, mode: TunnelPlatform["fullTunnelLeakProtection"]): TunnelConfig {
  if (mode === "wireguard" || tunnel.leakProtection !== "wireguard") return tunnel;
  return { ...tunnel, leakProtection: "firewall", firewallRequired: true };
}
