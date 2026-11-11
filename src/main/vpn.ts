import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import { isIPv4 } from "node:net";
import {
  type Account,
  type AccountSettings,
  type Device,
  type DeviceKeyInfo,
  type LoginOverview,
  type ErrorCode,
  type ObfuscationMode,
  type PortForwardingState,
  type Preferences,
  type QuantumState,
  type SessionInfo,
  type SettingsPatch,
  type TorState,
  torStateFor,
  type TunnelPhase,
  type TunnelStatus,
  type VpnNode,
  type WifiSecurity,
} from "../../shared/core/contract";
import { shouldAutoConnect } from "../../shared/core/wifi";
import type { ProxyCreate, ProxyPatch, ProxyWithPassword, ServerProxy } from "../../shared/core/proxy";
import { version as packageVersion } from "../../package.json";
import { evaluateUpdate, type AppVersionInfo } from "../../shared/core/app-version";
import { keyCreatedAt, keyRotationDue, rotateWithPending } from "../../shared/core/device-key";
import { MAX_PING_TARGETS, pingableNodes, type LatencyMeasurement } from "../../shared/core/latency";
import { LocalizedError, localizedOf, type ErrorKey, type Params } from "../../shared/core/i18n";
import {
  checkAccount,
  checkDue,
  checkError,
  revocationVerdict,
  tunnelSettled,
  type DeviceCheck,
  type RevocationReason,
} from "../../shared/core/revocation";
import { ApiClient, ApiError, type PortForwardAction } from "./api/client";
import type { ApiAccount } from "./api/schemas";
import { API_BASE_URL, IS_DEBUG } from "./flavor";
import { collectHostAllowances, nodeEndpointsOf, sameEndpoints } from "./firewall/hosts";
import { measureTargets, type PingTarget } from "./latency";
import { isIpLiteral, stripPrefix } from "./net/ip";
import { currentNetwork } from "./net/network-id";
import { HostResolver, normalizeHost } from "./net/resolve";
import { NO_RELAY, type Relay, type StartRelay } from "./obfs/relay";
import type { WireGuardPaths } from "./system/environment";
import { EMPTY_RUNTIME, type RuntimeState, type Store, type StoredDevice } from "./store";
import { buildTunnelConfig, formatEndpoint, parseEndpoint, type Endpoint } from "./wireguard/config";
import { nextPollDelay } from "./poll-schedule";
import { BootstrapError, type BootstrapStep } from "./wireguard/bootstrap";
import { generateKeyPair, publicKeyFromPrivate } from "./wireguard/keys";
import { activeLanguage, localizeError } from "./i18n";
import { phaseFor } from "./wireguard/phase";
import { PqAttemptError, PqError } from "./pq/errors";
import { runPqUpgrade, sessionStillActive } from "./pq/flow";
import { windowsPlatform } from "./platform/windows";
import { withPlatformLeakProtection, type PqDependencies, type TunnelPlatform } from "./platform/types";
import { VpnError } from "./vpn-error";

export { VpnError } from "./vpn-error";
export type { PqDependencies } from "./platform/types";

export function withNodeKey<T extends { config: { serverPublicKey: string } }>(device: T, node: { serverPublicKey?: string }): T {
  if (!node.serverPublicKey || node.serverPublicKey === device.config.serverPublicKey) return device;
  return { ...device, config: { ...device.config, serverPublicKey: node.serverPublicKey } };
}

export type ObfsDependencies = {
  start: StartRelay;
  network: (tunnelAddresses: readonly string[]) => string;
  probeMs: number;
  confirmMs: number;
  attach?: () => Promise<Relay | null>;
};

const DEFAULT_OBFS: ObfsDependencies = { start: NO_RELAY, network: currentNetwork, probeMs: 6000, confirmMs: 10_000 };

const UDP_BLOCKED = new Error("no handshake over UDP");

function pqTunnelSilent(error: unknown): boolean {
  return error instanceof PqError && error.code === "pq_failed" && error.cause instanceof PqAttemptError && error.cause.failure === "transport";
}

function initialStatus(): TunnelStatus {
  return {
    phase: "disconnected",
    nodeId: null,
    connectedAt: null,
    lastHandshakeAt: null,
    rxBytes: 0,
    txBytes: 0,
    endpoint: null,
    addresses: [],
    dns: [],
    leakProtection: "none",
    firewallActive: false,
    serviceState: null,
    error: null,
    checkedAt: Date.now(),
    quantum: "off",
    obfuscated: false,
  };
}

function deviceName(label: string): string {
  return `${label} ${randomBytes(2).toString("hex").toUpperCase()}`;
}

const REVOCATION_KEYS: Record<RevocationReason, ErrorKey> = {
  device_removed: "deviceRemoved",
  account_locked: "accountLockedTunnel",
  session_ended: "sessionEndedTunnel",
  tunnel_dead: "tunnelDead",
};

function apiUnreachableInLockdown(host: string): VpnError {
  return new VpnError("apiUnreachableInLockdown", "network", { host });
}

export class VpnController extends EventEmitter {
  private status: TunnelStatus = initialStatus();
  private queue: Promise<unknown> = Promise.resolve();
  private polling = false;
  private pollTimer: NodeJS.Timeout | null = null;
  private pollActive = false;
  private windowVisible = false;
  private pollStep = 0;
  private pollPhase: TunnelPhase | null = null;
  private operation: "connecting" | "disconnecting" | null = null;
  private updateRequired = false;
  private lastSettings: AccountSettings | null = null;
  private lastNodes: readonly VpnNode[] = [];
  private measuringLatency = false;
  private applyingFirewall = false;
  private refreshQueued = false;
  readonly api: ApiClient;
  private readonly hosts: HostResolver;
  private pendingRegistration: { token: string; accountId: string; paidUntil: string } | null = null;
  private readonly pq: PqDependencies;
  readonly platform: TunnelPlatform;
  private quantumVerified = false;
  private quantumRecoveryTried = false;
  private lastRevocationCheck: number | null = null;
  private revocationRunning = false;
  private tunnelGeneration = 0;
  private disconnectRequests = 0;
  private lastWifi: WifiSecurity | null = null;
  private wifiTimer: NodeJS.Timeout | null = null;
  private readonly obfs: ObfsDependencies;
  private relay: Relay | null = null;
  private obfsNetwork: string | null = null;
  private obfsRecoveryTried = false;
  private obfsTokens = new Map<string, string>();

  constructor(
    private readonly store: Store,
    pq: Partial<PqDependencies> = {},
    platform: TunnelPlatform = windowsPlatform(),
    obfs: Partial<ObfsDependencies> = {},
  ) {
    super();
    this.platform = platform;
    this.pq = { ...platform.pq, ...pq };
    this.obfs = { ...DEFAULT_OBFS, ...obfs };
    this.hosts = new HostResolver({
      cache: {
        read: (host) => this.store.getCachedAddresses(host),
        write: (host, addresses) => this.store.setCachedAddresses(host, addresses),
      },
      dnsBlocked: () => this.dnsBlocked(),
      onChange: () => this.firewallInputsChanged(),
    });
    this.api = new ApiClient(
      () => this.apiBaseUrl(),
      () => this.store.getSecrets().token,
      (host) => this.hosts.require(host),
      activeLanguage,
      { debug: IS_DEBUG },
    );
  }

  apiBaseUrl(): string {
    return API_BASE_URL;
  }

  private dnsBlocked(): boolean {
    const rules = this.status.firewallActive || this.store.getPreferences().alwaysOnKillSwitch;
    return rules && this.status.phase !== "connected";
  }

  private firewallInputsChanged(): void {
    if (this.applyingFirewall || this.refreshQueued || !this.status.firewallActive) return;
    this.refreshQueued = true;
    void this.reapplyFirewall()
      .catch((error: unknown) => this.publish({ error: messageOf(error) }))
      .finally(() => {
        this.refreshQueued = false;
      });
  }

  private rememberNodes(nodes: readonly VpnNode[], options: { refreshRules: boolean }): void {
    const next = nodeEndpointsOf(nodes);
    const changed = !sameEndpoints(next, this.store.getNodeEndpoints());
    if (changed) this.store.setNodeEndpoints(next);
    if (!this.dnsBlocked()) {
      for (const endpoint of next) {
        if (!isIpLiteral(endpoint.host)) void this.hosts.resolve(endpoint.host).catch(() => undefined);
      }
    }
    if (changed && options.refreshRules) this.firewallInputsChanged();
  }

  private serialize<T>(task: () => Promise<T>): Promise<T> {
    const next = this.queue.then(task, task);
    this.queue = next.catch(() => undefined);
    return next;
  }

  getStatus(): TunnelStatus {
    return this.status;
  }

  private publish(patch: Partial<TunnelStatus>): void {
    this.status = { ...this.status, ...patch, checkedAt: Date.now() };
    this.emit("status", this.status);
  }

  wireguard(): WireGuardPaths | null {
    return this.platform.detect();
  }

  async refreshPlatform(): Promise<void> {
    await this.platform.refresh?.();
  }

  isElevated(): Promise<boolean> {
    return this.platform.isElevated();
  }

  private async requireTunnelPrerequisites(): Promise<WireGuardPaths> {
    if (this.platform.refresh) await this.platform.refresh();
    const paths = this.wireguard();
    if (!paths) throw new VpnError(this.platform.errors.missing, "wireguard_missing");
    if (!(await this.platform.isElevated())) throw new VpnError(this.platform.errors.elevation, "elevation");
    await this.platform.checkPrerequisites(paths);
    return paths;
  }

  installWireGuard(onStep?: (step: BootstrapStep) => void): Promise<string> {
    return this.serialize(async () => {
      if (this.platform.installNeedsElevation && !(await this.platform.isElevated())) {
        throw new VpnError(this.platform.errors.installElevation, "elevation");
      }
      try {
        return await this.platform.install(onStep);
      } catch (error) {
        if (error instanceof BootstrapError) {
          throw new VpnError(error.i18n.key, error.kind === "network" ? "network" : "internal", error.i18n.params);
        }
        throw error;
      }
    });
  }

  private handleApiError(error: unknown): never {
    this.endSessionOn(error);
    throw error;
  }

  readonly logoutHooks: Array<() => Promise<void>> = [];

  noteApiError(error: unknown): void {
    this.endSessionOn(error);
  }

  private endSessionOn(error: unknown): void {
    if (error instanceof ApiError && error.sessionEnded) {
      const secrets = this.store.getSecrets();
      if (secrets.token === null) return;
      this.store.setSecrets({ ...secrets, token: null });
      this.emit("session-ended");
    }
  }

  session(): SessionInfo {
    const secrets = this.store.getSecrets();
    return {
      loggedIn: secrets.token !== null,
      accountId: secrets.token ? secrets.accountId : null,
      paidUntil: secrets.token ? secrets.paidUntil : null,
    };
  }

  login(code: string, totp?: string): Promise<SessionInfo> {
    return this.serialize(async () => {
      const response = await this.api.login(code, totp);
      this.pendingRegistration = null;
      await this.adoptSession({ token: response.token, accountId: response.account.id, paidUntil: response.account.paidUntil });
      return this.session();
    });
  }

  register(referralCode?: string): Promise<{ code: string; referralDays: number | null }> {
    return this.serialize(async () => {
      const response = await this.api.register(referralCode);
      this.pendingRegistration = { token: response.token, accountId: response.account.id, paidUntil: response.account.paidUntil };
      return { code: response.code, referralDays: response.referralDays ?? null };
    });
  }

  confirmRegistration(): Promise<SessionInfo> {
    return this.serialize(async () => {
      const pending = this.pendingRegistration;
      if (!pending) throw new VpnError("registrationMissing", "invalid");
      this.pendingRegistration = null;
      await this.adoptSession(pending);
      return this.session();
    });
  }

  private async adoptSession(next: { token: string; accountId: string; paidUntil: string }): Promise<void> {
    const previous = this.store.getSecrets();
    const sameAccount = previous.accountId === next.accountId;
    if (!sameAccount && previous.device) await this.teardownTunnel();
    this.store.setSecrets({
      token: next.token,
      accountId: next.accountId,
      paidUntil: next.paidUntil,
      device: sameAccount ? previous.device : null,
      ticketKey: sameAccount ? previous.ticketKey : null,
    });
  }

  logout(): Promise<void> {
    this.disconnectRequests += 1;
    return this.serialize(async () => {
      this.tunnelGeneration += 1;
      this.pendingRegistration = null;
      const secrets = this.store.getSecrets();
      const failures: unknown[] = [];
      await this.teardownTunnel().catch((error: unknown) => failures.push(error));
      if (secrets.token && secrets.device) {
        await this.api.deleteDevice(secrets.device.id).catch(() => undefined);
      }
      if (secrets.token) {
        for (const hook of this.logoutHooks) await hook().catch(() => undefined);
        await this.api.logout().catch(() => undefined);
      }
      this.store.wipeSecrets();
      this.store.setRuntime({ ...EMPTY_RUNTIME });
      this.lastSettings = null;
      if (failures.length > 0) {
        throw new VpnError("logoutPartial", "internal", { reason: reasonOf(failures[0]) });
      }
    });
  }

  async loginNotices(action: "list"): Promise<LoginOverview>;
  async loginNotices(action: "seen" | "logout-others"): Promise<null>;
  async loginNotices(action: "list" | "seen" | "logout-others"): Promise<LoginOverview | null> {
    try {
      if (action === "list") return await this.api.logins();
      if (action === "seen") await this.api.loginsSeen();
      else await this.api.logoutOthers();
      return null;
    } catch (error) {
      return this.handleApiError(error);
    }
  }

  private withoutObfsTokens(account: ApiAccount): Account {
    this.obfsTokens = new Map(account.devices.flatMap((device) => (device.obfsToken ? [[device.id, device.obfsToken] as const] : [])));
    return { ...account, devices: account.devices.map(({ obfsToken: _token, ...device }) => device) };
  }

  async account(): Promise<Account> {
    const generation = this.tunnelGeneration;
    const deviceId = this.store.getSecrets().device?.id ?? null;
    try {
      const account = this.withoutObfsTokens(await this.api.account());
      this.noteAccount(account, generation, deviceId);
      this.lastSettings = account.settings;
      const secrets = this.store.getSecrets();
      if (secrets.paidUntil !== account.paidUntil) this.store.setSecrets({ ...secrets, paidUntil: account.paidUntil });
      return account;
    } catch (error) {
      return this.handleApiError(error);
    }
  }

  async portForwarding(): Promise<PortForwardingState | null> {
    const device = this.store.getSecrets().device;
    if (!device) return null;
    try {
      return await this.api.portForwarding(device.id, "get");
    } catch (error) {
      if (error instanceof ApiError && error.apiCode === "device_not_found") return null;
      return this.handleApiError(error);
    }
  }

  async setPortForwarding(enabled: boolean): Promise<PortForwardingState | null> {
    const device = this.store.getSecrets().device;
    if (!device) return null;
    try {
      return await this.api.portForwarding(device.id, enabled ? "enable" : "disable");
    } catch (error) {
      if (error instanceof ApiError && error.apiCode === "device_not_found") return null;
      return this.handleApiError(error);
    }
  }

  async tor(enabled?: boolean): Promise<TorState | null> {
    const device = this.store.getSecrets().device;
    if (!device) return null;
    try {
      const own =
        enabled === undefined
          ? (await this.api.account()).devices.find((entry) => entry.id === device.id)
          : await this.api.setDeviceTor(device.id, enabled);
      return own ? torStateFor(own, await this.api.nodes()) : null;
    } catch (error) {
      if (error instanceof ApiError && error.apiCode === "device_not_found") return null;
      return this.handleApiError(error);
    }
  }

  currentDeviceId(): string | null {
    return this.store.getSecrets().device?.id ?? null;
  }

  async renameDevice(id: string, name: string): Promise<Device> {
    try {
      return await this.api.renameDevice(id, name);
    } catch (error) {
      return this.handleApiError(error);
    }
  }

  async removeDevice(id: string): Promise<null> {
    const own = this.currentDeviceId() === id;
    if (own && this.status.phase !== "disconnected") await this.disconnect();
    try {
      await this.api.deleteDevice(id);
    } catch (error) {
      return this.handleApiError(error);
    }
    if (own && this.currentDeviceId() === id) this.forgetDevice();
    return null;
  }

  async devicePortForwarding(deviceId: string, action: Exclude<PortForwardAction, "disable">): Promise<PortForwardingState | null> {
    try {
      return await this.api.portForwarding(deviceId, action);
    } catch (error) {
      if (error instanceof ApiError && error.apiCode === "device_not_found") return null;
      return this.handleApiError(error);
    }
  }

  async proxies(): Promise<ServerProxy[] | null> {
    try {
      return await this.api.proxies();
    } catch (error) {
      return this.handleApiError(error);
    }
  }

  async createProxy(input: ProxyCreate): Promise<ProxyWithPassword> {
    try {
      return await this.api.createProxy(input);
    } catch (error) {
      return this.handleApiError(error);
    }
  }

  async updateProxy(id: string, patch: ProxyPatch): Promise<ProxyWithPassword> {
    try {
      return await this.api.updateProxy(id, patch);
    } catch (error) {
      return this.handleApiError(error);
    }
  }

  async deleteProxy(id: string): Promise<null> {
    try {
      await this.api.deleteProxy(id);
      return null;
    } catch (error) {
      return this.handleApiError(error);
    }
  }

  async nodes(): Promise<VpnNode[]> {
    const nodes = await this.api.nodes();
    this.rememberNodes(nodes, { refreshRules: true });
    this.lastNodes = nodes;
    return nodes;
  }

  async measureLatency(ids: readonly string[]): Promise<LatencyMeasurement[]> {
    if (this.status.phase !== "disconnected" || this.operation !== null || this.measuringLatency) return [];
    const wanted = new Set(ids.slice(0, MAX_PING_TARGETS));
    const targets: PingTarget[] = pingableNodes(this.lastNodes)
      .filter((node) => wanted.has(node.id))
      .map((node) => ({ id: node.id, host: normalizeHost(node.endpointHost), port: node.pingPort as number }));
    if (targets.length === 0) return [];
    this.measuringLatency = true;
    try {
      return await measureTargets(targets, { resolve: (host) => this.hosts.resolve(host) });
    } finally {
      this.measuringLatency = false;
    }
  }

  async checkAppVersion(): Promise<AppVersionInfo> {
    const info = await this.api.appVersion(this.platform.id);
    this.updateRequired = evaluateUpdate(packageVersion, info).kind === "required";
    return info;
  }

  updateSettings(patch: SettingsPatch): Promise<AccountSettings> {
    return this.serialize(async () => {
      const before = this.lastSettings;
      let next: AccountSettings;
      try {
        next = await this.api.updateSettings(patch);
      } catch (error) {
        return this.handleApiError(error);
      }
      this.lastSettings = next;
      const routingChanged =
        !before ||
        before.killSwitch !== next.killSwitch ||
        before.lanAccess !== next.lanAccess ||
        before.ipv6 !== next.ipv6;
      if (routingChanged) this.scheduleReapply();
      return next;
    });
  }

  private scheduleReapply(): void {
    const runtime = this.store.getRuntime();
    const active = this.status.phase !== "disconnected" && runtime.nodeId !== null;
    if (active && runtime.nodeId) {
      void this.connect(runtime.nodeId).catch((error: unknown) => this.publish({ error: messageOf(error) }));
      return;
    }
    if (this.store.getPreferences().alwaysOnKillSwitch) {
      void this.serialize(() => this.applyAlwaysOnRules(true)).catch((error: unknown) =>
        this.publish({ error: messageOf(error) }),
      );
    }
  }

  async deviceKey(): Promise<DeviceKeyInfo | null> {
    const device = this.store.getSecrets().device;
    if (!device) return null;
    if (device.keyCreatedAt !== undefined) return { createdAt: device.keyCreatedAt };
    const account = await this.account();
    return { createdAt: keyCreatedAt(undefined, account.devices.find((entry) => entry.id === device.id)) };
  }

  async rotateDeviceKey(): Promise<DeviceKeyInfo | null> {
    if (!this.store.getSecrets().device) return null;
    const runtime = this.store.getRuntime();
    const reconnect = this.status.phase !== "disconnected" && runtime.nodeId ? runtime.nodeId : null;
    const requests = this.disconnectRequests;
    try {
      if (reconnect) {
        await this.serialize(async () => {
          this.tunnelGeneration += 1;
          this.operation = "connecting";
          this.publish({ phase: "connecting", nodeId: reconnect, error: null, revoked: undefined, quantum: "off" });
          await this.stopTunnelKeepRules();
        });
      }
      return await this.serialize(async () => {
        const device = this.store.getSecrets().device;
        if (!device) return null;
        const next = await this.renewDeviceKey(device).catch((error: unknown) => this.handleApiError(error));
        return { createdAt: next.keyCreatedAt ?? null };
      });
    } finally {
      if (reconnect && this.disconnectRequests === requests) await this.connect(reconnect, requests).catch((error: unknown) => this.publish({ error: messageOf(error) }));
    }
  }

  private async stopTunnelKeepRules(): Promise<void> {
    if (this.platform.refresh) await this.platform.refresh();
    const paths = this.wireguard();
    if (paths && (await this.platform.queryService()).exists) {
      await this.requireTunnelPrerequisites();
      await this.platform.stopTunnel(paths);
    }
    await this.platform.removeTunnelConfig().catch(() => undefined);
    await this.pq.sweepSecrets().catch(() => undefined);
    this.adoptRelay(null);
    this.store.setRuntime({ ...this.store.getRuntime(), connectedAt: null, postQuantum: false, pqSessionKey: null, obfuscated: false });
  }

  private async renewDeviceKey(device: StoredDevice): Promise<StoredDevice> {
    const { pair, response } = await rotateWithPending({
      pending: device.pendingKey,
      generate: generateKeyPair,
      storePending: (pendingKey) => this.saveDevice({ ...device, pendingKey: pendingKey ?? undefined }),
      send: (publicKey) => this.api.rotateDeviceKey(device.id, publicKey),
      answered: (error) => error instanceof ApiError && error.status !== null && error.status >= 400,
    });
    const next: StoredDevice = {
      id: device.id,
      nodeId: response.device.nodeId,
      publicKey: pair.publicKey,
      privateKey: pair.privateKey,
      keySource: "local",
      config: response.config,
      keyCreatedAt: Date.now(),
      obfsToken: response.device.obfsToken,
    };
    this.saveDevice(next);
    return next;
  }

  private saveDevice(device: StoredDevice): void {
    this.store.setSecrets({ ...this.store.getSecrets(), device });
  }

  private async ensureDevice(account: Account, node: VpnNode, tunnelIdle: boolean): Promise<StoredDevice> {
    const secrets = this.store.getSecrets();
    const existing = secrets.device;
    const stillRegistered = existing !== null && account.devices.some((device) => device.id === existing.id);
    if (existing && stillRegistered && existing.nodeId === node.id) {
      const registered = account.devices.find((device) => device.id === existing.id);
      const due = keyRotationDue(keyCreatedAt(existing.keyCreatedAt, registered), Date.now());
      if (!tunnelIdle || !(existing.pendingKey || due)) return existing;
      return this.renewDeviceKey(existing).catch(() => this.store.getSecrets().device ?? existing);
    }
    if (existing && stillRegistered) await this.api.deleteDevice(existing.id).catch(() => undefined);

    const keys = generateKeyPair();
    const response = await this.api.registerDevice({ name: deviceName(this.platform.deviceLabel), nodeId: node.id, publicKey: keys.publicKey });
    const serverKey = response.privateKey;
    const device: StoredDevice = {
      id: response.device.id,
      nodeId: response.device.nodeId,
      publicKey: serverKey ? publicKeyFromPrivate(serverKey) : keys.publicKey,
      privateKey: serverKey ?? keys.privateKey,
      keySource: serverKey ? "server" : "local",
      config: response.config,
      keyCreatedAt: Date.now(),
      obfsToken: response.device.obfsToken,
    };
    this.saveDevice(device);
    return device;
  }

  private async applyFirewall(input: { endpoint: Endpoint | null; tunnelAddresses: string[]; allowLan: boolean }): Promise<string | null> {
    this.applyingFirewall = true;
    try {
      const { hosts, unresolvedApiHost } = await collectHostAllowances({
        resolver: this.hosts,
        baseUrl: this.apiBaseUrl(),
        nodeEndpoints: this.store.getNodeEndpoints(),
        currentEndpoint: input.endpoint,
      });
      await this.platform.enableKillSwitch({ hosts, tunnelAddresses: input.tunnelAddresses, allowLan: input.allowLan });
      this.publish({ firewallActive: true });
      return unresolvedApiHost;
    } finally {
      this.applyingFirewall = false;
    }
  }

  private async applyAlwaysOnRules(requireApi: boolean): Promise<void> {
    await this.requireTunnelPrerequisites();
    const runtime = this.store.getRuntime();
    const unresolved = await this.applyFirewall({
      endpoint: runtime.endpoint ? parseEndpoint(runtime.endpoint) : null,
      tunnelAddresses: runtime.addresses,
      allowLan: this.lastSettings?.lanAccess ?? false,
    });
    if (unresolved && requireApi && this.status.phase !== "connected") throw apiUnreachableInLockdown(unresolved);
  }

  connect(nodeId: string, requests = this.disconnectRequests): Promise<TunnelStatus> {
    if (this.updateRequired && this.status.phase === "disconnected") {
      return Promise.reject(new VpnError("updateRequired", "update_required"));
    }
    const cancelled = () => {
      if (this.disconnectRequests !== requests) throw new VpnError("connectCancelled", "invalid");
    };
    return this.serialize(async () => {
      cancelled();
      const paths = await this.requireTunnelPrerequisites();
      const tunnelIdle = this.status.phase === "disconnected" || this.store.getRuntime().connectedAt === null;
      const replacing = this.status.phase !== "disconnected" && this.store.getRuntime().firewallForTunnel;
      this.tunnelGeneration += 1;
      this.operation = "connecting";
      this.publish({ phase: "connecting", nodeId, error: null, revoked: undefined });
      let firewallForTunnel = false;
      try {
        const [account, nodes] = await Promise.all([this.account(), this.api.nodes()]);
        cancelled();
        this.rememberNodes(nodes, { refreshRules: false });
        const node = nodes.find((entry) => entry.id === nodeId);
        if (!node) throw new VpnError("locationGone", "invalid");
        if (!node.online) throw new VpnError("locationOffline", "server", { city: node.city });
        const postQuantum = this.store.getPreferences().postQuantum === true;
        if (postQuantum && node.postQuantum !== true) throw new PqError("pq_unsupported");
        const mode = this.obfuscationMode();
        if (mode === "on" && !node.obfuscation) throw new VpnError("obfsUnavailable", "invalid", { city: node.city });

        const registered = await this.ensureDevice(account, node, tunnelIdle).catch((error: unknown) => this.handleApiError(error));
        const device = withNodeKey(registered, node);
        cancelled();
        const obfsToken = device.obfsToken ?? this.obfsTokens.get(device.id);
        const offer = node.obfuscation && obfsToken ? { port: node.obfuscation.port, pin: node.obfuscation.pin, token: obfsToken } : null;
        if (mode === "on" && !offer) throw new VpnError("obfsUnavailable", "invalid", { city: node.city });
        const configured = parseEndpoint(device.config.endpoint) ?? { host: node.endpointHost, port: node.endpointPort };
        const [resolved] = await this.hosts.resolve(configured.host);
        if (!resolved) {
          throw new VpnError("endpointUnresolved", "network", { host: configured.host });
        }
        const endpoint = { host: resolved, port: configured.port };

        const establish = async (obfs: { port: number; pin: string; token: string } | null): Promise<void> => {
          const relay = obfs
            ? await this.obfs.start({ server: formatEndpoint({ host: resolved, port: obfs.port }), pin: obfs.pin, token: obfs.token })
            : null;
          const wireguardEndpoint = relay ? { host: "127.0.0.1", port: relay.port } : endpoint;
          try {
            const tunnel = withPlatformLeakProtection(
              buildTunnelConfig({
                privateKey: device.privateKey,
                server: device.config,
                endpoint: wireguardEndpoint,
                settings: account.settings,
                postQuantum,
                bypassHost: relay ? resolved : undefined,
              }),
              this.platform.fullTunnelLeakProtection,
            );

            const alwaysOn = this.store.getPreferences().alwaysOnKillSwitch;
            firewallForTunnel = tunnel.leakProtection !== "none";
            if (alwaysOn || firewallForTunnel) {
              await this.applyFirewall({ endpoint, tunnelAddresses: tunnel.addresses, allowLan: account.settings.lanAccess });
            }
            cancelled();

            await this.platform.startTunnel(paths, tunnel, wireguardEndpoint);
            this.adoptRelay(relay);
            if (!alwaysOn && !firewallForTunnel && this.status.firewallActive) {
              await this.platform.disableKillSwitch();
              this.publish({ firewallActive: false });
            }

            const leakProtection = tunnel.leakProtection === "wireguard" ? "wireguard" : alwaysOn || tunnel.firewallRequired ? "firewall" : "none";
            const runtime: RuntimeState = {
              nodeId,
              connectedAt: Date.now(),
              addresses: tunnel.addresses,
              dns: tunnel.dns,
              endpoint: formatEndpoint(endpoint),
              leakProtection,
              firewallForTunnel,
              postQuantum,
              pqSessionKey: null,
              obfuscated: relay !== null,
            };
            this.store.setRuntime(runtime);
            this.store.setPreferences({ ...this.store.getPreferences(), lastNodeId: nodeId });
            this.publish({
              nodeId,
              connectedAt: runtime.connectedAt,
              addresses: runtime.addresses,
              dns: runtime.dns,
              endpoint: runtime.endpoint,
              leakProtection,
              lastHandshakeAt: null,
              rxBytes: 0,
              txBytes: 0,
              quantum: "off",
              obfuscated: runtime.obfuscated,
            });
            const service = await this.platform.waitForService((query) => query.exists && query.state === "RUNNING", 20_000);
            cancelled();
            if (postQuantum) {
              if (!service.exists || service.state !== "RUNNING") throw new PqError("pq_failed", { cause: "service not running" });
              await this.upgradeQuantum({ paths, device, tunnel, endpoint: formatEndpoint(wireguardEndpoint) });
            }
          } catch (error) {
            if (relay && this.relay !== relay) relay.stop();
            throw error;
          }
        };

        const network = this.obfs.network(this.store.getRuntime().addresses);
        const auto = mode === "auto" && offer !== null;
        if (mode === "on" || (auto && this.obfsNetwork === network)) {
          await establish(offer);
        } else {
          try {
            await establish(null);
            const handshake = !auto || postQuantum || (await this.handshakeWithin(paths, this.obfs.probeMs));
            cancelled();
            if (!handshake) throw UDP_BLOCKED;
          } catch (error) {
            if (!auto || !(error === UDP_BLOCKED || (postQuantum && pqTunnelSilent(error)))) throw error;
            await establish(offer);
            if (postQuantum || (await this.handshakeWithin(paths, this.obfs.confirmMs))) this.obfsNetwork = network;
          }
        }
        if (this.relay) this.obfsRecoveryTried = false;
        this.operation = null;
        this.lastRevocationCheck = Date.now();
        await this.refreshStatus();
        return this.status;
      } catch (error) {
        this.operation = null;
        const blocked = await this.rollbackFailedConnect(paths, firewallForTunnel, replacing);
        this.publish({ phase: blocked ? "stale" : "disconnected", error: messageOf(error), quantum: "off", obfuscated: false });
        throw error;
      }
    });
  }

  private obfuscationMode(): ObfuscationMode {
    return this.store.getPreferences().obfuscation ?? "auto";
  }

  private async handshakeWithin(paths: WireGuardPaths, ms: number): Promise<boolean> {
    const clock = this.pq.clock;
    const deadline = clock.now() + ms;
    for (;;) {
      const status = await this.platform.readInterfaceStatus(paths).catch(() => null);
      if (status?.peers[0]?.latestHandshakeAt != null) return true;
      if (clock.now() >= deadline) return false;
      await clock.sleep(500);
    }
  }

  private adoptRelay(next: Relay | null): void {
    const previous = this.relay;
    this.relay = next;
    if (previous && previous !== next) previous.stop();
    if (next && next !== previous) {
      next.onExit(() => {
        if (this.relay !== next) return;
        this.relay = null;
        void this.refreshStatus().catch(() => undefined);
      });
    }
  }

  setObfuscation(mode: ObfuscationMode): Preferences {
    if (this.obfuscationMode() !== mode) {
      this.store.setPreferences({ ...this.store.getPreferences(), obfuscation: mode });
      this.obfsNetwork = null;
      const runtime = this.store.getRuntime();
      if (this.status.phase !== "disconnected" && runtime.nodeId) {
        const nodeId = runtime.nodeId;
        void this.connect(nodeId).catch((error: unknown) => this.publish({ error: messageOf(error) }));
      }
    }
    return this.store.getPreferences();
  }

  private async upgradeQuantum(input: {
    paths: WireGuardPaths;
    device: StoredDevice;
    tunnel: { addresses: string[]; allowedIps: string[] };
    endpoint: string;
  }): Promise<void> {
    const tunnelIpv4 = input.tunnel.addresses.map(stripPrefix).find((address) => isIPv4(address));
    if (!tunnelIpv4) throw new PqError("pq_failed", { cause: "no tunnel IPv4" });
    const result = await runPqUpgrade({
      wireguard: this.pq.wireguard(input.paths),
      dial: this.pq.dial(tunnelIpv4),
      nodeKey: input.device.config.serverPublicKey,
      clientKey: input.device.publicKey,
      tunnelIpv4,
      endpoint: input.endpoint,
      presharedKey: input.device.config.presharedKey,
      clientPrivateKey: input.device.privateKey,
      allowedIps: input.tunnel.allowedIps,
      onQuantum: (quantum) => this.publish({ quantum }),
      clock: this.pq.clock,
    }).catch((error: unknown) => {
      throw this.platform.pqFailureForUser(error);
    });
    this.store.setRuntime({ ...this.store.getRuntime(), postQuantum: true, pqSessionKey: result.sessionPublicKey });
    this.quantumVerified = true;
    this.quantumRecoveryTried = false;
  }

  setPostQuantum(enabled: boolean): Preferences {
    const preferences = this.store.getPreferences();
    if ((preferences.postQuantum === true) !== enabled) {
      this.store.setPreferences({ ...preferences, postQuantum: enabled });
      const runtime = this.store.getRuntime();
      if (this.status.phase !== "disconnected" && runtime.nodeId) {
        const nodeId = runtime.nodeId;
        void this.connect(nodeId).catch((error: unknown) => this.publish({ error: messageOf(error) }));
      }
    }
    return this.store.getPreferences();
  }

  private async rollbackFailedConnect(paths: WireGuardPaths, firewallForTunnel: boolean, replacing: boolean): Promise<boolean> {
    await this.platform.stopTunnel(paths).catch(() => undefined);
    await this.pq.sweepSecrets().catch(() => undefined);
    await this.platform.removeTunnelConfig().catch(() => undefined);
    this.adoptRelay(null);
    const alwaysOn = this.store.getPreferences().alwaysOnKillSwitch;
    const keepBlocked = replacing && this.status.firewallActive && this.lastSettings?.killSwitch !== false;
    if (firewallForTunnel && !alwaysOn && !keepBlocked) {
      await this.platform.disableKillSwitch().catch(() => undefined);
      this.publish({ firewallActive: false });
    }
    const runtime = this.store.getRuntime();
    this.store.setRuntime({ ...runtime, connectedAt: null, firewallForTunnel: keepBlocked, postQuantum: false, pqSessionKey: null, obfuscated: false });
    return keepBlocked && !alwaysOn;
  }

  private async teardownTunnel(): Promise<void> {
    const runtime = this.store.getRuntime();
    this.adoptRelay(null);
    const stopFailure = await this.stopTunnelKeepRules().then(
      () => null,
      (error: unknown) => ({ error }),
    );
    const alwaysOn = this.store.getPreferences().alwaysOnKillSwitch;
    if (!alwaysOn && (runtime.firewallForTunnel || this.status.firewallActive)) {
      await this.platform.disableKillSwitch();
      this.publish({ firewallActive: false });
    }
    this.store.setRuntime({ ...this.store.getRuntime(), connectedAt: null, firewallForTunnel: false, postQuantum: false, pqSessionKey: null, obfuscated: false });
    if (stopFailure) throw stopFailure.error;
  }

  disconnect(): Promise<TunnelStatus> {
    this.disconnectRequests += 1;
    if (this.operation === "connecting") this.publish({ phase: "disconnecting" });
    return this.serialize(async () => {
      this.tunnelGeneration += 1;
      this.operation = "disconnecting";
      this.publish({ phase: "disconnecting", error: null, revoked: undefined });
      try {
        await this.teardownTunnel();
        this.operation = null;
        this.publish({
          phase: "disconnected",
          connectedAt: null,
          lastHandshakeAt: null,
          rxBytes: 0,
          txBytes: 0,
          serviceState: null,
          leakProtection: this.store.getPreferences().alwaysOnKillSwitch ? "firewall" : "none",
          quantum: "off",
          obfuscated: false,
        });
        return this.status;
      } catch (error) {
        this.operation = null;
        await this.refreshStatus();
        this.publish({ error: messageOf(error) });
        throw error;
      }
    });
  }

  setAlwaysOn(enabled: boolean): Promise<void> {
    return this.serialize(async () => {
      if (enabled) {
        await this.requireTunnelPrerequisites();
        if (!this.lastSettings) await this.account().catch(() => undefined);
        if (this.store.getNodeEndpoints().length === 0) await this.nodes().catch(() => undefined);
        const apiHost = normalizeHost(new URL(this.apiBaseUrl()).hostname);
        if ((await this.hosts.resolve(apiHost)).length === 0) {
          throw new VpnError("apiHostUnresolved", "network", { host: apiHost });
        }
        await this.applyAlwaysOnRules(false);
        this.store.setPreferences({ ...this.store.getPreferences(), alwaysOnKillSwitch: true });
        return;
      }
      this.store.setPreferences({ ...this.store.getPreferences(), alwaysOnKillSwitch: false });
      const runtime = this.store.getRuntime();
      const tunnelNeedsFirewall = runtime.firewallForTunnel && this.status.phase !== "disconnected";
      if (!tunnelNeedsFirewall) {
        await this.platform.disableKillSwitch();
        this.publish({ firewallActive: false });
      }
    });
  }

  reapplyFirewall(): Promise<void> {
    return this.serialize(async () => {
      const runtime = this.store.getRuntime();
      const needed = this.store.getPreferences().alwaysOnKillSwitch || (runtime.firewallForTunnel && this.tunnelActive());
      if (!needed) return;
      await this.applyAlwaysOnRules(true);
    });
  }

  emergencyDisableKillSwitch(): Promise<void> {
    return this.serialize(async () => {
      this.store.setPreferences({ ...this.store.getPreferences(), alwaysOnKillSwitch: false });
      await this.platform.disableKillSwitch();
      this.store.setRuntime({ ...this.store.getRuntime(), firewallForTunnel: false });
      this.publish({ firewallActive: false });
    });
  }

  async detectFirewall(): Promise<void> {
    if (!(await this.platform.isElevated())) return;
    const count = await this.platform.killSwitchRuleCount().catch(() => 0);
    this.publish({ firewallActive: count > 0 });
  }

  async refreshStatus(): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    try {
      await this.pollOnce();
    } finally {
      this.polling = false;
    }
    this.maybeCheckRevocation();
  }

  private maybeCheckRevocation(): void {
    if (this.revocationRunning || this.operation) return;
    if (!checkDue({ status: this.status, lastCheckAt: this.lastRevocationCheck, now: Date.now() })) return;
    void this.checkRevocation().catch(() => undefined);
  }

  private leakProtected(): boolean {
    if (this.store.getPreferences().alwaysOnKillSwitch) return false;
    return this.store.getRuntime().leakProtection !== "none" || this.lastSettings?.killSwitch === true;
  }

  async checkRevocation(): Promise<RevocationReason | null> {
    if (this.revocationRunning || this.operation || !tunnelSettled(this.status)) return null;
    this.revocationRunning = true;
    this.lastRevocationCheck = Date.now();
    const generation = this.tunnelGeneration;
    try {
      const check = await this.deviceCheck();
      return await this.applyRevocation(check, generation);
    } finally {
      this.revocationRunning = false;
    }
  }

  private async deviceCheck(): Promise<DeviceCheck> {
    const secrets = this.store.getSecrets();
    if (!secrets.token) return "session_ended";
    const device = secrets.device;
    const nodeId = this.store.getRuntime().nodeId;
    if (!device || (nodeId !== null && device.nodeId !== nodeId)) return "unknown";
    try {
      const account = await this.api.account();
      if (this.store.getSecrets().device?.id !== device.id) return "unknown";
      return checkAccount(account, device.id, Date.now());
    } catch (error) {
      this.endSessionOn(error);
      return checkError(error);
    }
  }

  private noteAccount(account: Account, generation: number, deviceId: string | null): void {
    if (!deviceId || this.store.getSecrets().device?.id !== deviceId) return;
    const check = checkAccount(account, deviceId, Date.now());
    if (check === "present") return;
    void this.applyRevocation(check, generation).catch(() => undefined);
  }

  private async applyRevocation(check: DeviceCheck, generation: number): Promise<RevocationReason | null> {
    if (generation !== this.tunnelGeneration || this.operation) return null;
    const verdict = revocationVerdict({ check, status: this.status, now: Date.now(), leakProtected: this.leakProtected() });
    if (!verdict) return null;
    const ended = await this.endRevokedTunnel(verdict, generation);
    if (!ended) return null;
    if (verdict !== "tunnel_dead") return verdict;
    const refined = await this.deviceCheck().catch((): DeviceCheck => "unknown");
    const reason: RevocationReason | null = refined === "removed" ? "device_removed" : refined === "locked" ? "account_locked" : null;
    if (!reason || this.status.phase !== "disconnected" || this.status.revoked !== "tunnel_dead") return verdict;
    if (reason === "device_removed") this.forgetDevice();
    this.publish({ error: messageOf(new VpnError(REVOCATION_KEYS[reason], "server")), revoked: reason });
    return reason;
  }

  private forgetDevice(): void {
    const secrets = this.store.getSecrets();
    if (secrets.device) this.store.setSecrets({ ...secrets, device: null });
  }

  private endRevokedTunnel(reason: RevocationReason, generation: number): Promise<boolean> {
    return this.serialize(async () => {
      if (generation !== this.tunnelGeneration || !tunnelSettled(this.status)) return false;
      this.tunnelGeneration += 1;
      this.operation = "disconnecting";
      this.publish({ phase: "disconnecting", error: null });
      try {
        await this.teardownTunnel();
      } catch (error) {
        this.operation = null;
        await this.refreshStatus();
        this.publish({ error: messageOf(error) });
        return false;
      }
      this.operation = null;
      if (reason === "device_removed") this.forgetDevice();
      this.publish({
        phase: "disconnected",
        connectedAt: null,
        lastHandshakeAt: null,
        rxBytes: 0,
        txBytes: 0,
        serviceState: null,
        leakProtection: this.store.getPreferences().alwaysOnKillSwitch ? "firewall" : "none",
        quantum: "off",
        obfuscated: false,
        error: messageOf(new VpnError(REVOCATION_KEYS[reason], "server")),
        revoked: reason,
      });
      return true;
    });
  }

  private async pollOnce(): Promise<void> {
    if (this.operation) return;
    const paths = this.wireguard();
    const runtime = this.store.getRuntime();
    const base = {
      nodeId: runtime.nodeId,
      addresses: runtime.addresses,
      dns: runtime.dns,
      endpoint: runtime.endpoint,
    };
    if (!paths) {
      if (!this.operation) this.publish({ phase: "disconnected", serviceState: null });
      return;
    }
    const service = await this.platform.queryService();
    if (this.operation) return;
    if (!service.exists) {
      const alwaysOn = this.store.getPreferences().alwaysOnKillSwitch;
      if (this.tunnelLostBehindRules()) {
        this.publish({
          ...base,
          phase: "stale",
          serviceState: null,
          lastHandshakeAt: null,
          leakProtection: runtime.leakProtection,
          quantum: "off",
          obfuscated: false,
          error: this.status.error ?? localizeError(new LocalizedError("tunnelLostBlocked")),
        });
        return;
      }
      this.publish({
        ...base,
        phase: "disconnected",
        serviceState: null,
        connectedAt: null,
        lastHandshakeAt: null,
        rxBytes: 0,
        txBytes: 0,
        leakProtection: alwaysOn && this.status.firewallActive ? "firewall" : "none",
        quantum: "off",
        obfuscated: false,
      });
      return;
    }
    if (service.state !== "RUNNING") {
      const phase: TunnelPhase =
        service.state === "START_PENDING" ? "connecting" : service.state === "STOP_PENDING" ? "disconnecting" : "stale";
      this.publish({
        ...base,
        phase,
        serviceState: service.state,
        error: service.state === "STOPPED" ? localizeError(new LocalizedError("serviceStopped")) : this.status.error,
      });
      return;
    }
    const wgStatus = (await this.platform.isElevated()) ? await this.platform.readInterfaceStatus(paths) : null;
    const peer = wgStatus?.peers[0];
    const now = Date.now();
    const connectedAt = runtime.connectedAt ?? this.status.connectedAt ?? now;
    const lastHandshakeAt = peer?.latestHandshakeAt ?? null;
    if (runtime.obfuscated && !this.relay && !(await this.attachRelay())) {
      this.recoverObfuscation(runtime.nodeId);
      return;
    }
    const quantum = this.quantumOf(runtime, wgStatus?.publicKey ?? null);
    if (quantum === "lost") {
      this.recoverQuantum(runtime.nodeId);
      return;
    }
    this.publish({
      ...base,
      phase: phaseFor({ now, connectedAt, lastHandshakeAt }),
      serviceState: service.state,
      connectedAt,
      lastHandshakeAt,
      rxBytes: peer?.rxBytes ?? 0,
      txBytes: peer?.txBytes ?? 0,
      endpoint: peer?.endpoint ?? runtime.endpoint,
      leakProtection: runtime.leakProtection,
      error: this.relayError(),
      quantum,
      obfuscated: runtime.obfuscated,
    });
  }

  private relayError(): string | null {
    const failure = this.relay?.state() === "retrying" ? this.relay.failure() : null;
    if (failure === "rejected") return messageOf(new VpnError("obfsRejected", "server"));
    if (failure === "pin") return messageOf(new VpnError("obfsPinMismatch", "server"));
    return null;
  }

  private async attachRelay(): Promise<boolean> {
    if (this.operation || !this.obfs.attach) return false;
    const relay = await this.obfs.attach().catch(() => null);
    if (!relay) return false;
    if (this.relay || this.operation) {
      relay.release?.();
      return this.relay !== null;
    }
    this.adoptRelay(relay);
    return true;
  }

  relayEndsWithApp(): boolean {
    return this.relay !== null && this.relay.detached !== true;
  }

  private recoverObfuscation(nodeId: string | null): void {
    if (this.operation) return;
    if (!this.obfsRecoveryTried && nodeId) {
      this.obfsRecoveryTried = true;
      void this.connect(nodeId).catch((error: unknown) => this.publish({ error: messageOf(error) }));
      return;
    }
    this.publish({ phase: "stale", error: messageOf(new VpnError("obfsRelayLost", "internal")) });
  }

  private quantumOf(runtime: RuntimeState, interfaceKey: string | null): QuantumState | "lost" {
    if (!runtime.postQuantum) return "off";
    const device = this.store.getSecrets().device;
    if (runtime.pqSessionKey === null) return "lost";
    if (interfaceKey !== null && device !== null && interfaceKey === device.publicKey) return "lost";
    if (!this.quantumVerified) {
      this.quantumVerified = true;
      void this.verifyQuantumSession(runtime);
    }
    return "active";
  }

  private async verifyQuantumSession(runtime: RuntimeState): Promise<void> {
    const tunnelIpv4 = runtime.addresses.map(stripPrefix).find((address) => isIPv4(address));
    const active =
      tunnelIpv4 !== undefined && runtime.pqSessionKey !== null && (await sessionStillActive(this.pq.dial(tunnelIpv4), runtime.pqSessionKey));
    if (!active) this.recoverQuantum(runtime.nodeId);
  }

  private recoverQuantum(nodeId: string | null): void {
    if (this.operation) return;
    if (!this.quantumRecoveryTried && nodeId) {
      this.quantumRecoveryTried = true;
      void this.connect(nodeId).catch((error: unknown) => this.publish({ error: messageOf(error) }));
      return;
    }
    this.publish({ phase: "stale", quantum: "off", error: messageOf(new PqError("pq_not_active")) });
  }

  private tunnelLostBehindRules(): boolean {
    if (this.store.getPreferences().alwaysOnKillSwitch) return false;
    return this.store.getRuntime().firewallForTunnel && this.status.firewallActive;
  }

  async wifiSecurity(): Promise<WifiSecurity> {
    if (!this.platform.wifiSecurity) return "unknown";
    return this.platform.wifiSecurity().catch((): WifiSecurity => "unknown");
  }

  setAutoConnectOpenWifi(enabled: boolean): Preferences {
    this.store.setPreferences({ ...this.store.getPreferences(), autoConnectOpenWifi: enabled });
    this.lastWifi = null;
    return this.store.getPreferences();
  }

  async checkOpenWifi(): Promise<void> {
    const preferences = this.store.getPreferences();
    if (!preferences.autoConnectOpenWifi) {
      this.lastWifi = null;
      return;
    }
    const current = await this.wifiSecurity();
    const previous = this.lastWifi;
    this.lastWifi = current;
    const nodeId = preferences.lastNodeId;
    const hasLocation = nodeId !== null && this.store.getSecrets().token !== null;
    if (!nodeId || !shouldAutoConnect({ previous, current, enabled: true, phase: this.status.phase, hasLocation })) return;
    await this.connect(nodeId).catch((error: unknown) => this.publish({ error: messageOf(error) }));
  }

  setWindowVisible(visible: boolean): void {
    if (visible === this.windowVisible) return;
    this.windowVisible = visible;
    if (!this.pollActive) return;
    if (visible) this.schedulePoll(0);
    else this.schedulePoll(nextPollDelay({ visible, step: this.pollStep }));
  }

  startPolling(): void {
    if (!this.pollActive) void this.pq.sweepSecrets().catch(() => undefined);
    this.pollActive = true;
    this.pollStep = 0;
    this.schedulePoll(0);
    this.wifiTimer ??= setInterval(() => void this.checkOpenWifi().catch(() => undefined), 30_000);
  }

  private schedulePoll(delayMs: number): void {
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = setTimeout(() => void this.pollTick(), delayMs);
  }

  private async pollTick(): Promise<void> {
    this.pollTimer = null;
    await this.refreshStatus().catch(() => undefined);
    if (!this.pollActive || this.pollTimer) return;
    const phase = this.status.phase;
    this.pollStep = this.operation || phase !== this.pollPhase ? 0 : this.pollStep + 1;
    this.pollPhase = phase;
    this.schedulePoll(nextPollDelay({ visible: this.windowVisible, step: this.pollStep }));
  }

  stopPolling(): void {
    this.pollActive = false;
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = null;
    if (this.wifiTimer) clearInterval(this.wifiTimer);
    this.wifiTimer = null;
  }

  tunnelActive(): boolean {
    return this.status.phase !== "disconnected";
  }
}

export function messageOf(error: unknown): string {
  return localizeError(error);
}

function reasonOf(error: unknown): Params[string] {
  const localized = localizedOf(error);
  if (localized) return localized;
  return error instanceof Error && error.message ? error.message : String(error);
}

export function codeOf(error: unknown): ErrorCode {
  if (error instanceof VpnError || error instanceof ApiError || error instanceof PqError) return error.code;
  return "internal";
}
