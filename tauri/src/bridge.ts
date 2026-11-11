import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { describeApiError } from "../../shared/core/api-errors";
import { parseAppVersionInfo } from "../../shared/core/app-version";
import {
  torStateFor,
  type Account,
  type DebugBridge,
  type Environment,
  type ErrorCode,
  type MantelBridge,
  type PortForwardingState,
  type Preferences,
  type Result,
  type Theme,
  type TunnelStatus,
} from "../../shared/core/contract";
import { errorMessage, languageOfLocale, resolveLanguage, type Language, type Params } from "../../shared/core/i18n";
import { isProxyId, isTelegramProxyLink, parseProxyCreate, parseProxyPatch } from "../../shared/core/proxy";
import { describeSupportError, isSupportCategory, isSupportText, SUPPORT_ID, type SupportService } from "../../shared/core/support";
import { createTauriSupport } from "./support";
import {
  accountCodeSchema,
  accountSchema,
  deviceSchema,
  errorSchema,
  loginsSchema,
  nodeIdSchema,
  nodesSchema,
  portForwardingSchema,
  proxyListSchema,
  proxyWithPasswordSchema,
  settingsPatchSchema,
  settingsSchema,
  referralInputSchema,
  totpInputSchema,
} from "../../src/main/api/schemas";
import type { z } from "zod";

export type Failure =
  | { kind: "localized"; key: string; params: Params; code: ErrorCode }
  | { kind: "api"; status: number; body: unknown };

const PREVIEW_TEXT: Record<Language, string> = {
  de: "In der Tauri-Vorschau noch nicht verfügbar.",
  en: "Not available in the Tauri preview yet.",
};

const IS_DEBUG = import.meta.env.MANTEL_FLAVOR === "debug";

export type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>;
export type Listen = (event: string, handler: (payload: unknown) => void) => () => void;

function isFailure(value: unknown): value is Failure {
  if (typeof value !== "object" || value === null) return false;
  const kind = (value as { kind?: unknown }).kind;
  return kind === "localized" || kind === "api";
}

export function describeFailure(failure: unknown, language: Language): { error: string; code: ErrorCode } {
  if (!isFailure(failure)) return { error: errorMessage(failure, language), code: "internal" };
  if (failure.kind === "api") {
    const parsed = errorSchema.safeParse(failure.body);
    const described = describeApiError(failure.status, parsed.success ? parsed.data : null, { debug: IS_DEBUG });
    const message = typeof described.message === "string" ? described.message : errorMessage({ i18n: described.message }, language);
    return { error: message, code: described.code };
  }
  if (failure.key === "tauriPreview") return { error: PREVIEW_TEXT[language], code: failure.code };
  if (failure.key === "__plain") return { error: String(failure.params.message ?? ""), code: failure.code };
  const i18n = Object.keys(failure.params).length > 0 ? { key: failure.key, params: failure.params } : { key: failure.key };
  return { error: errorMessage({ i18n }, language), code: failure.code };
}

const invalid = (): Failure => ({ kind: "localized", key: "invalidInput", params: {}, code: "invalid" });
const unexpected = (): Failure => ({ kind: "localized", key: "apiUnexpectedFormat", params: {}, code: "server" });

function parsed<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw unexpected();
  return result.data;
}

function withoutObfsToken<T extends { obfsToken?: string }>(device: T): Omit<T, "obfsToken"> {
  const { obfsToken: _token, ...rest } = device;
  return rest;
}

function validLocalPort(value: unknown): boolean {
  return value === null || (typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535);
}

function portForwardingOf(value: unknown): PortForwardingState | null {
  if (value === null) return null;
  const body = parsed(portForwardingSchema, value);
  return {
    nodeId: body.nodeId,
    city: body.city,
    available: body.available,
    reason: body.reason,
    max: body.max,
    localPort: body.localPort ?? false,
    forwards: body.forwards.map((forward) => ({ port: forward.port, host: forward.host, localPort: forward.localPort ?? null })),
  };
}

export function createTauriBridge(call: Invoke, on: Listen, locales: readonly string[] = [], support: SupportService = createTauriSupport(call)): MantelBridge {
  let language: Language = "en";
  const remember = (preferences: Preferences): Preferences => {
    language = resolveLanguage(preferences.language);
    return preferences;
  };
  const ready = (call("preferences") as Promise<Preferences>).then(remember).catch(() => undefined);

  async function result<T>(command: string, args?: Record<string, unknown>, map: (value: unknown) => T = (value) => value as T): Promise<Result<T>> {
    try {
      return { ok: true, value: map(await call(command, args)) };
    } catch (failure) {
      await ready;
      return { ok: false, ...describeFailure(failure, language) };
    }
  }

  async function refuse<T>(): Promise<Result<T>> {
    await ready;
    return { ok: false, ...describeFailure(invalid(), language) };
  }

  async function supportResult<T>(task: () => Promise<T>): Promise<Result<T>> {
    try {
      return { ok: true, value: await task() };
    } catch (error) {
      await ready;
      const described = describeSupportError(error, { debug: IS_DEBUG });
      if (!described) return { ok: false, ...describeFailure(error, language) };
      const message = typeof described.message === "string" ? described.message : errorMessage({ i18n: described.message }, language);
      return { ok: false, error: message, code: described.code };
    }
  }
  const isTicketId = (id: unknown): id is string => typeof id === "string" && SUPPORT_ID.test(id);

  const preferencesResult = (command: string, args?: Record<string, unknown>) =>
    result(command, args, (value) => remember(value as Preferences));

  const subscribe = <T>(event: string, listener: (payload: T) => void) => on(event, (payload) => listener(payload as T));

  return {
    environment: async () => {
      const { systemLocales, ...environment } = (await call("environment")) as Environment & { systemLocales?: string[] };
      const systemLocale = systemLocales?.[0] ?? locales[0];
      return { ...environment, systemLanguage: languageOfLocale(systemLocale), ...(systemLocale ? { systemLocale } : {}) };
    },
    session: () => call("session") as never,
    login: (code, totp) => {
      const first = accountCodeSchema.safeParse(String(code));
      const second = totpInputSchema.safeParse(totp === undefined ? null : String(totp));
      if (!first.success || !second.success) return refuse();
      return result("login", { code: first.data, totp: second.data ?? null });
    },
    register: (referralCode) => {
      const parsed = referralInputSchema.safeParse(referralCode === undefined ? null : String(referralCode));
      if (!parsed.success) return refuse();
      return result("register", { referralCode: parsed.data ?? null });
    },
    confirmRegistration: () => result("confirm_registration"),
    logout: async () => {
      await support.unregister();
      const done = await result<null>("logout");
      if (done.ok) await support.forget().catch(() => undefined);
      return done;
    },
    account: () =>
      result("account", undefined, (value): Account => {
        const account = parsed(accountSchema, value);
        return { ...account, devices: account.devices.map(withoutObfsToken) };
      }),
    nodes: () => result("nodes", undefined, (value) => parsed(nodesSchema, value)),
    updateSettings: (patch) => {
      const checked = settingsPatchSchema.safeParse(patch);
      if (!checked.success) return refuse();
      return result("update_settings", { patch: checked.data }, (value) => parsed(settingsSchema, value));
    },
    connect: (nodeId) => {
      const checked = nodeIdSchema.safeParse(String(nodeId));
      if (!checked.success) return refuse();
      return result("connect", { nodeId: checked.data });
    },
    disconnect: () => result("disconnect"),
    tunnelStatus: () => call("tunnel_status") as Promise<TunnelStatus>,
    preferences: async () => remember((await call("preferences")) as Preferences),
    setAlwaysOnKillSwitch: (enabled) => preferencesResult("set_always_on_kill_switch", { enabled: enabled === true }),
    selectNode: (nodeId) => {
      const checked = nodeIdSchema.safeParse(String(nodeId));
      if (!checked.success) return refuse();
      return preferencesResult("select_node", { nodeId: checked.data });
    },
    setLanguage: (value) => preferencesResult("set_language", { language: String(value) }),
    setPostQuantum: (enabled) => preferencesResult("set_post_quantum", { enabled: enabled === true }),
    wifiSecurity: () => call("wifi_security") as never,
    setAutoConnectOpenWifi: (enabled) => preferencesResult("set_auto_connect_open_wifi", { enabled: enabled === true }),
    setObfuscation: (mode) => preferencesResult("set_obfuscation", { mode: String(mode) }),
    setTheme: (theme) => preferencesResult("set_theme", { theme: String(theme) }),
    autostart: () => call("autostart") as never,
    setAutostart: (enabled) => result("set_autostart", { enabled: enabled === true }),
    setConnectOnLaunch: (enabled) => preferencesResult("set_connect_on_launch", { enabled: enabled === true }),
    setQuitAction: (action) => preferencesResult("set_quit_action", { action: String(action) }),
    openWireGuardDownload: async () => {
      await call("open_wireguard_download");
    },
    installWireGuard: () => result("install_wire_guard"),
    copyText: (text) => result("copy_text", { text: String(text) }),
    openAccountPage: () => result("open_account_page"),
    checkAppVersion: () =>
      result("check_app_version", undefined, (value) => {
        const info = parseAppVersionInfo(value, "windows");
        if (!info) throw unexpected();
        return info;
      }),
    openDownloadPage: () => result("open_download_page"),
    measureLatency: (nodeIds) => call("measure_latency", { nodeIds: Array.isArray(nodeIds) ? nodeIds.map(String) : [] }) as never,
    portForwarding: () => result("port_forwarding", undefined, portForwardingOf),
    setPortForwarding: (enabled) => result("set_port_forwarding", { enabled: enabled === true }, portForwardingOf),
    tor: () => result("tor", undefined, torOf),
    setTor: (enabled) => result("set_tor", { enabled: enabled === true }, torOf),
    deviceKey: () => result("device_key"),
    rotateDeviceKey: () => result("rotate_device_key"),
    recentLogins: () => result("recent_logins", undefined, (value) => parsed(loginsSchema, value)),
    markLoginsSeen: () => result("mark_logins_seen"),
    logoutOtherSessions: () => result("logout_other_sessions"),
    openSecurityPage: () => result("open_security_page"),
    currentDeviceId: () => call("current_device_id") as never,
    renameDevice: (id, name) => result("rename_device", { id: String(id), name: String(name) }, (value) => withoutObfsToken(parsed(deviceSchema, value))),
    removeDevice: (id) => result("remove_device", { id: String(id) }),
    devicePortForwarding: (id) => result("device_port_forwarding", { id: String(id) }, portForwardingOf),
    addPortForward: (id, localPort) => {
      if (!validLocalPort(localPort ?? null)) return refuse();
      return result("add_port_forward", { id: String(id), localPort: localPort ?? null }, portForwardingOf);
    },
    setPortForwardLocalPort: (id, port, localPort) => {
      if (!Number.isInteger(port) || port < 1 || port > 65535 || !validLocalPort(localPort)) return refuse();
      return result("set_port_forward_local_port", { id: String(id), port, localPort }, portForwardingOf);
    },
    removePortForward: (id, port) => {
      if (!Number.isInteger(port) || port < 1 || port > 65535) return refuse();
      return result("remove_port_forward", { id: String(id), port }, portForwardingOf);
    },
    proxies: () => result("proxies", undefined, (value) => (value === null ? null : parsed(proxyListSchema, value).proxies)),
    createProxy: (input) => {
      const checked = parseProxyCreate(input);
      if (!checked) return refuse();
      return result("create_proxy", { input: checked }, (value) => parsed(proxyWithPasswordSchema, value));
    },
    updateProxy: (id, patch) => {
      const checked = parseProxyPatch(patch);
      if (!isProxyId(id) || !checked) return refuse();
      return result("update_proxy", { id, patch: checked }, (value) => parsed(proxyWithPasswordSchema, value));
    },
    deleteProxy: (id) => (isProxyId(id) ? result("delete_proxy", { id }) : refuse()),
    openTelegramProxy: (link) => (isTelegramProxyLink(link) ? result("open_telegram_proxy", { link }) : refuse()),
    supportOverview: () => supportResult(() => support.overview()),
    supportUnread: () => supportResult(() => support.unread()),
    supportTicket: (id) => (isTicketId(id) ? supportResult(() => support.ticket(id)) : refuse()),
    supportCreate: (category, text) =>
      isSupportCategory(category) && isSupportText(text) ? supportResult(() => support.create(category, text)) : refuse(),
    supportReply: (id, text) => (isTicketId(id) && isSupportText(text) ? supportResult(() => support.reply(id, text)) : refuse()),
    supportSetClosed: (id, closed) =>
      isTicketId(id) && typeof closed === "boolean" ? supportResult(() => support.setClosed(id, closed)) : refuse(),
    onTunnelStatus: (listener) => subscribe<TunnelStatus>("tunnel-status", listener),
    onSessionEnded: (listener) => subscribe<void>("session-ended", () => listener()),
    onSystemThemeChange: (listener) => subscribe<Theme>("system-theme", listener),
    ...(IS_DEBUG ? { debug: debugBridge(call, result) } : {}),
  };
}

function debugBridge(call: Invoke, result: <T>(command: string, args?: Record<string, unknown>) => Promise<Result<T>>): DebugBridge {
  return {
    info: () => call("debug_info") as never,
    requestLog: () => call("debug_request_log") as never,
    clearRequestLog: async () => {
      await call("debug_clear_request_log");
    },
    healthCheck: () => call("debug_health_check") as never,
    setVerbose: (enabled) => call("debug_set_verbose", { enabled: enabled === true }) as never,
    copyDiagnostics: () => result("debug_copy_diagnostics"),
    resetLocalData: () => result("debug_reset_local_data"),
    openDevTools: async () => {
      await call("debug_open_devtools");
    },
  };
}

function torOf(value: unknown) {
  if (value === null) return null;
  const { device, nodes } = value as { device?: { nodeId?: unknown }; nodes?: unknown };
  if (!device || device.nodeId === null) return null;
  return torStateFor(withoutObfsToken(parsed(deviceSchema, device)), parsed(nodesSchema, nodes));
}

export function installTauriBridge(): void {
  const on: Listen = (event, handler) => {
    const pending = listen(event, (message) => handler(message.payload));
    return () => {
      void pending.then((unlisten) => unlisten());
    };
  };
  const bridge = createTauriBridge((command, args) => invoke(command, args), on, navigator.languages);
  Object.defineProperty(window, "mantel", { value: Object.freeze(bridge), writable: false, configurable: false });
}
