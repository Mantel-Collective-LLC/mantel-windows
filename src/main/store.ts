import { safeStorage } from "electron";
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { OBFUSCATION_MODES, QUIT_ACTIONS, type LeakProtection, type Preferences } from "../../shared/core/contract";
import { DEFAULT_LANGUAGE_PREFERENCE, LANGUAGE_PREFERENCES } from "../../shared/core/i18n";
import { DEFAULT_THEME_PREFERENCE, THEME_PREFERENCES } from "../../shared/core/theme";
import { baseUrlSchema, obfsTokenSchema, tunnelConfigSchema } from "./api/schemas";
import { MAX_NODE_ENDPOINTS, type NodeEndpoint } from "./firewall/hosts";
import { API_BASE_URL } from "./flavor";
import type { ServerTunnelConfig } from "./wireguard/config";

export type StoredDevice = {
  id: string;
  nodeId: string;
  publicKey: string;
  privateKey: string;
  keySource: "local" | "server";
  config: ServerTunnelConfig;
  keyCreatedAt?: number;
  pendingKey?: { publicKey: string; privateKey: string };
  obfsToken?: string;
};

export type Secrets = {
  token: string | null;
  accountId: string | null;
  paidUntil: string | null;
  device: StoredDevice | null;
  ticketKey?: string | null;
};

export type RuntimeState = {
  nodeId: string | null;
  connectedAt: number | null;
  addresses: string[];
  dns: string[];
  endpoint: string | null;
  leakProtection: LeakProtection;
  firewallForTunnel: boolean;
  postQuantum: boolean;
  pqSessionKey: string | null;
  obfuscated: boolean;
};

export type NetworkCache = {
  hosts: Record<string, string[]>;
  nodeEndpoints: NodeEndpoint[];
};

const MAX_CACHED_HOSTS = 256;

const EMPTY_NETWORK: NetworkCache = { hosts: {}, nodeEndpoints: [] };

const EMPTY_SECRETS: Secrets = { token: null, accountId: null, paidUntil: null, device: null, ticketKey: null };

export const DEFAULT_PREFERENCES: Preferences = {
  baseUrl: API_BASE_URL,
  alwaysOnKillSwitch: false,
  lastNodeId: null,
  language: DEFAULT_LANGUAGE_PREFERENCE,
  postQuantum: false,
  autoConnectOpenWifi: false,
  theme: DEFAULT_THEME_PREFERENCE,
  obfuscation: "auto",
  connectOnLaunch: false,
  quitAction: "ask",
};

export const EMPTY_RUNTIME: RuntimeState = {
  nodeId: null,
  connectedAt: null,
  addresses: [],
  dns: [],
  endpoint: null,
  leakProtection: "none",
  firewallForTunnel: false,
  postQuantum: false,
  pqSessionKey: null,
  obfuscated: false,
};

const secretsSchema = z.object({
  token: z.string().nullable(),
  accountId: z.string().nullable(),
  paidUntil: z.string().nullable(),
  device: z
    .object({
      id: z.string(),
      nodeId: z.string(),
      publicKey: z.string(),
      privateKey: z.string(),
      keySource: z.enum(["local", "server"]),
      config: tunnelConfigSchema,
      keyCreatedAt: z.number().finite().optional().catch(undefined),
      pendingKey: z.object({ publicKey: z.string(), privateKey: z.string() }).optional().catch(undefined),
      obfsToken: obfsTokenSchema.optional().catch(undefined),
    })
    .nullable(),
  ticketKey: z.string().regex(/^[A-Za-z0-9_-]{100,400}$/).nullable().catch(null).default(null),
});

export const preferencesSchema = z.object({
  baseUrl: baseUrlSchema,
  alwaysOnKillSwitch: z.boolean(),
  lastNodeId: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/).nullable(),
  language: z.enum(LANGUAGE_PREFERENCES).catch(DEFAULT_LANGUAGE_PREFERENCE),
  postQuantum: z.boolean().catch(false).default(false),
  autoConnectOpenWifi: z.boolean().catch(false).default(false),
  theme: z.enum(THEME_PREFERENCES).catch(DEFAULT_THEME_PREFERENCE),
  obfuscation: z.enum(OBFUSCATION_MODES).catch("auto").default("auto"),
  connectOnLaunch: z.boolean().catch(false).default(false),
  quitAction: z.enum(QUIT_ACTIONS).catch("ask").default("ask"),
});

const runtimeSchema = z.object({
  nodeId: z.string().nullable(),
  connectedAt: z.number().nullable(),
  addresses: z.array(z.string()),
  dns: z.array(z.string()),
  endpoint: z.string().nullable(),
  leakProtection: z.enum(["wireguard", "firewall", "none"]),
  firewallForTunnel: z.boolean(),
  postQuantum: z.boolean().default(false),
  pqSessionKey: z.string().max(64).nullable().default(null),
  obfuscated: z.boolean().default(false),
});

const hostKey = z.string().min(1).max(253);

const networkSchema = z.object({
  hosts: z.record(hostKey, z.array(z.string().max(64)).max(16)),
  nodeEndpoints: z
    .array(
      z.object({
        host: hostKey,
        port: z.number().int().min(1).max(65535),
        pingPort: z.number().int().min(1).max(65535).optional(),
        tcpPort: z.number().int().min(1).max(65535).optional(),
      }),
    )
    .max(MAX_NODE_ENDPOINTS),
});

function writeAtomic(file: string, content: string | Buffer): void {
  mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, content, { mode: 0o600 });
  renameSync(temporary, file);
}

function withFlavorBaseUrl(preferences: Preferences): Preferences {
  return preferences.baseUrl === API_BASE_URL ? preferences : { ...preferences, baseUrl: API_BASE_URL };
}

function readJson<T>(file: string, schema: z.ZodType<T>, fallback: T): T {
  try {
    const parsed = schema.safeParse(JSON.parse(readFileSync(file, "utf8")));
    return parsed.success ? parsed.data : fallback;
  } catch {
    return fallback;
  }
}

export class Store {
  private secrets: Secrets = { ...EMPTY_SECRETS };
  private preferences: Preferences = { ...DEFAULT_PREFERENCES };
  private runtime: RuntimeState = { ...EMPTY_RUNTIME };
  private network: NetworkCache = { hosts: {}, nodeEndpoints: [] };

  constructor(private readonly directory: string) {}

  get encryptionAvailable(): boolean {
    return safeStorage.isEncryptionAvailable();
  }

  private file(name: string): string {
    return path.join(this.directory, name);
  }

  load(): void {
    this.preferences = withFlavorBaseUrl(readJson<Preferences>(this.file("preferences.json"), preferencesSchema, { ...DEFAULT_PREFERENCES }));
    this.runtime = readJson(this.file("runtime.json"), runtimeSchema, { ...EMPTY_RUNTIME });
    this.network = readJson(this.file("network.json"), networkSchema, { ...EMPTY_NETWORK, hosts: {} });
    if (!this.encryptionAvailable) return;
    try {
      const decrypted = safeStorage.decryptString(readFileSync(this.file("secrets.bin")));
      const parsed = secretsSchema.safeParse(JSON.parse(decrypted));
      if (parsed.success) this.secrets = parsed.data;
    } catch {
      this.secrets = { ...EMPTY_SECRETS };
    }
  }

  getSecrets(): Secrets {
    return this.secrets;
  }

  setSecrets(next: Secrets): void {
    this.secrets = next;
    if (!this.encryptionAvailable) return;
    writeAtomic(this.file("secrets.bin"), safeStorage.encryptString(JSON.stringify(next)));
  }

  wipeSecrets(): void {
    this.secrets = { ...EMPTY_SECRETS };
    rmSync(this.file("secrets.bin"), { force: true });
    rmSync(this.file("secrets.bin.tmp"), { force: true });
  }

  getPreferences(): Preferences {
    return this.preferences;
  }

  setPreferences(next: Preferences): void {
    this.preferences = withFlavorBaseUrl(next);
    writeAtomic(this.file("preferences.json"), JSON.stringify(this.preferences, null, 2));
  }

  resetLocalData(): void {
    this.wipeSecrets();
    this.setPreferences({ ...DEFAULT_PREFERENCES });
    this.setRuntime({ ...EMPTY_RUNTIME });
    this.saveNetwork({ ...EMPTY_NETWORK, hosts: {} });
  }

  getRuntime(): RuntimeState {
    return this.runtime;
  }

  setRuntime(next: RuntimeState): void {
    this.runtime = next;
    writeAtomic(this.file("runtime.json"), JSON.stringify(next, null, 2));
  }

  getCachedAddresses(host: string): string[] {
    return this.network.hosts[host] ?? [];
  }

  setCachedAddresses(host: string, addresses: string[]): void {
    const hosts = { ...this.network.hosts };
    delete hosts[host];
    hosts[host] = addresses;
    const names = Object.keys(hosts);
    for (const name of names.slice(0, Math.max(0, names.length - MAX_CACHED_HOSTS))) delete hosts[name];
    this.saveNetwork({ ...this.network, hosts });
  }

  getNodeEndpoints(): NodeEndpoint[] {
    return this.network.nodeEndpoints;
  }

  setNodeEndpoints(endpoints: NodeEndpoint[]): void {
    this.saveNetwork({ ...this.network, nodeEndpoints: endpoints.slice(0, MAX_NODE_ENDPOINTS) });
  }

  private saveNetwork(next: NetworkCache): void {
    this.network = next;
    writeAtomic(this.file("network.json"), JSON.stringify(next, null, 2));
  }
}
