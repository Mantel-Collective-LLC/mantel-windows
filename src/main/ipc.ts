import { app, clipboard, ipcMain, shell, type IpcMainInvokeEvent, type WebContents } from "electron";
import { z } from "zod";
import {
  accountPageUrl,
  securityPageUrl,
  downloadPageUrl,
  IPC,
  OBFUSCATION_MODES,
  MAX_DEVICE_NAME,
  QUIT_ACTIONS,
  SUPPORT_CATEGORIES,
  WIREGUARD_DOWNLOAD_URL,
  type Environment,
  type PlatformFeatures,
  type Preferences,
  type Result,
} from "../../shared/core/contract";
import { LANGUAGE_PREFERENCES, LocalizedError } from "../../shared/core/i18n";
import { MAX_PING_TARGETS, type LatencyMeasurement } from "../../shared/core/latency";
import { THEME_PREFERENCES } from "../../shared/core/theme";
import { isProxyId, isTelegramProxyLink, parseProxyCreate, parseProxyPatch } from "../../shared/core/proxy";
import { isSupportText, SUPPORT_ID, type SupportService } from "../../shared/core/support";
import { accountCodeSchema, nodeIdSchema, referralInputSchema, settingsPatchSchema, totpInputSchema } from "./api/schemas";
import { localizeError, setLanguagePreference, systemLanguage, systemLocale } from "./i18n";
import { autostartState, type LoginLauncher } from "./lifecycle";
import type { Store } from "./store";
import { supportError } from "./support";
import { codeOf, messageOf, VpnController } from "./vpn";

const languageSchema = z.enum(LANGUAGE_PREFERENCES);
const themeSchema = z.enum(THEME_PREFERENCES);

const WINDOWS_FEATURES: PlatformFeatures = {
  desktopWindow: true,
  managedWireGuard: true,
  firewallLockdown: true,
  systemLockdown: false,
  appExclusion: false,
};

type Handler = (event: IpcMainInvokeEvent, ...args: unknown[]) => unknown;

export type HandleFn = (channel: string, argCount: number, handler: Handler) => void;

const latencyIdsSchema = z.array(nodeIdSchema).max(MAX_PING_TARGETS);

const supportIdSchema = z.string().regex(SUPPORT_ID);
const supportCategorySchema = z.enum(SUPPORT_CATEGORIES);
const supportTextSchema = z.string().refine(isSupportText);

const deviceIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const deviceNameSchema = z.string().trim().min(1).max(MAX_DEVICE_NAME);
const forwardPortSchema = z.number().int().min(1).max(65535);
const localPortSchema = z.number().int().min(1).max(65535).nullable();

const clipboardTextSchema = z.string().min(1).max(64 * 1024);

function invalid<T>(): Result<T> {
  return { ok: false, error: localizeError(new LocalizedError("invalidInput")), code: "invalid" };
}

async function wrap<T>(task: () => Promise<T>): Promise<Result<T>> {
  try {
    return { ok: true, value: await task() };
  } catch (error) {
    return { ok: false, error: messageOf(error), code: codeOf(error) };
  }
}

export function registerIpc(options: {
  store: Store;
  vpn: VpnController;
  isTrustedSender: (contents: WebContents, frameUrl: string | undefined) => boolean;
  onPreferencesChanged: () => void;
  onThemeChanged?: () => void;
  refreshSystemLanguage?: () => void;
  support?: SupportService;
  registerExtra?: (handle: HandleFn) => void;
  assumeWireGuardInstalled?: boolean;
  launcher?: LoginLauncher;
}): void {
  const { store, vpn } = options;

  const handle: HandleFn = (channel, argCount, handler) => {
    ipcMain.handle(channel, (event, ...args: unknown[]) => {
      if (!options.isTrustedSender(event.sender, event.senderFrame?.url)) {
        throw new Error("Unerwarteter Absender.");
      }
      if (args.length !== argCount) return invalid();
      return handler(event, ...args);
    });
  };

  handle(IPC.environment, 0, async (): Promise<Environment> => {
    options.refreshSystemLanguage?.();
    await vpn.refreshPlatform();
    const paths = vpn.wireguard();
    return {
      platform: process.platform,
      elevated: await vpn.isElevated(),
      wireguardInstalled: paths !== null || options.assumeWireGuardInstalled === true,
      wireguardPath: paths?.directory ?? null,
      wireguardSource: paths?.source ?? null,
      encryptionAvailable: store.encryptionAvailable,
      appVersion: app.getVersion(),
      features: { ...WINDOWS_FEATURES },
      systemLanguage: systemLanguage(),
      ...(systemLocale() ? { systemLocale: systemLocale() } : {}),
    };
  });

  handle(IPC.session, 0, () => vpn.session());

  handle(IPC.login, 2, (_event, code, totp) => {
    const parsed = accountCodeSchema.safeParse(code);
    const second = totpInputSchema.safeParse(totp);
    if (!parsed.success || !second.success) return invalid();
    return wrap(() => vpn.login(parsed.data, second.data ?? undefined));
  });

  handle(IPC.register, 1, (_event, referralCode) => {
    const parsed = referralInputSchema.safeParse(referralCode);
    if (!parsed.success) return invalid();
    return wrap(() => vpn.register(parsed.data ?? undefined));
  });

  handle(IPC.confirmRegistration, 0, () => wrap(() => vpn.confirmRegistration()));

  handle(IPC.logout, 0, () => wrap(async () => {
    await vpn.logout();
    return null;
  }));

  handle(IPC.account, 0, () => wrap(() => vpn.account()));

  handle(IPC.nodes, 0, () => wrap(() => vpn.nodes()));

  handle(IPC.updateSettings, 1, (_event, patch) => {
    const parsed = settingsPatchSchema.safeParse(patch);
    if (!parsed.success) return invalid();
    return wrap(() => vpn.updateSettings(parsed.data));
  });

  handle(IPC.connect, 1, (_event, nodeId) => {
    const parsed = nodeIdSchema.safeParse(nodeId);
    if (!parsed.success) return invalid();
    return wrap(() => vpn.connect(parsed.data));
  });

  handle(IPC.disconnect, 0, () => wrap(() => vpn.disconnect()));

  handle(IPC.tunnelStatus, 0, () => vpn.getStatus());

  handle(IPC.preferences, 0, (): Preferences => store.getPreferences());

  handle(IPC.setAlwaysOnKillSwitch, 1, (_event, enabled) => {
    const parsed = z.boolean().safeParse(enabled);
    if (!parsed.success) return invalid();
    return wrap(async () => {
      await vpn.setAlwaysOn(parsed.data);
      options.onPreferencesChanged();
      return store.getPreferences();
    });
  });

  handle(IPC.selectNode, 1, (_event, nodeId) => {
    const parsed = nodeIdSchema.safeParse(nodeId);
    if (!parsed.success) return invalid();
    return wrap(async () => {
      store.setPreferences({ ...store.getPreferences(), lastNodeId: parsed.data });
      options.onPreferencesChanged();
      return store.getPreferences();
    });
  });

  handle(IPC.setLanguage, 1, (_event, language) => {
    const parsed = languageSchema.safeParse(language);
    if (!parsed.success) return invalid();
    return wrap(async () => {
      store.setPreferences({ ...store.getPreferences(), language: parsed.data });
      setLanguagePreference(parsed.data);
      options.onPreferencesChanged();
      return store.getPreferences();
    });
  });

  handle(IPC.setPostQuantum, 1, (_event, enabled) => {
    const parsed = z.boolean().safeParse(enabled);
    if (!parsed.success) return invalid();
    return wrap(async () => vpn.setPostQuantum(parsed.data));
  });

  handle(IPC.wifiSecurity, 0, () => vpn.wifiSecurity());

  handle(IPC.setAutoConnectOpenWifi, 1, (_event, enabled) => {
    const parsed = z.boolean().safeParse(enabled);
    if (!parsed.success) return invalid();
    return wrap(async () => vpn.setAutoConnectOpenWifi(parsed.data));
  });

  handle(IPC.setObfuscation, 1, (_event, mode) => {
    const parsed = z.enum(OBFUSCATION_MODES).safeParse(mode);
    if (!parsed.success) return invalid();
    return wrap(async () => vpn.setObfuscation(parsed.data));
  });

  handle(IPC.autostart, 0, () => (options.launcher ? autostartState(options.launcher) : { supported: false, enabled: false }));

  handle(IPC.setAutostart, 1, (_event, enabled) => {
    const parsed = z.boolean().safeParse(enabled);
    const launcher = options.launcher;
    if (!parsed.success || !launcher?.supported) return invalid();
    return wrap(async () => {
      await launcher.setEnabled(parsed.data);
      return autostartState(launcher);
    });
  });

  handle(IPC.setConnectOnLaunch, 1, (_event, enabled) => {
    const parsed = z.boolean().safeParse(enabled);
    if (!parsed.success) return invalid();
    return wrap(async () => {
      store.setPreferences({ ...store.getPreferences(), connectOnLaunch: parsed.data });
      return store.getPreferences();
    });
  });

  handle(IPC.setQuitAction, 1, (_event, action) => {
    const parsed = z.enum(QUIT_ACTIONS).safeParse(action);
    if (!parsed.success) return invalid();
    return wrap(async () => {
      store.setPreferences({ ...store.getPreferences(), quitAction: parsed.data });
      return store.getPreferences();
    });
  });

  handle(IPC.setTheme, 1, (_event, theme) => {
    const parsed = themeSchema.safeParse(theme);
    if (!parsed.success) return invalid();
    return wrap(async () => {
      store.setPreferences({ ...store.getPreferences(), theme: parsed.data });
      options.onThemeChanged?.();
      return store.getPreferences();
    });
  });

  handle(IPC.openWireGuardDownload, 0, async () => {
    await shell.openExternal(WIREGUARD_DOWNLOAD_URL);
  });

  handle(IPC.openAccountPage, 0, () =>
    wrap(async () => {
      try {
        await shell.openExternal(accountPageUrl(store.getPreferences().baseUrl));
      } catch (error) {
        throw new LocalizedError("openWebsiteFailed", undefined, { cause: error });
      }
      return null;
    }),
  );

  handle(IPC.checkAppVersion, 0, () => wrap(() => vpn.checkAppVersion()));

  handle(IPC.openDownloadPage, 0, () =>
    wrap(async () => {
      try {
        await shell.openExternal(downloadPageUrl(store.getPreferences().baseUrl));
      } catch (error) {
        throw new LocalizedError("openWebsiteFailed", undefined, { cause: error });
      }
      return null;
    }),
  );

  handle(IPC.installWireGuard, 0, () => wrap(async () => ({ version: await vpn.installWireGuard() })));

  handle(IPC.portForwarding, 0, () => wrap(() => vpn.portForwarding()));

  handle(IPC.deviceKey, 0, () => wrap(() => vpn.deviceKey()));

  handle(IPC.rotateDeviceKey, 0, () => wrap(() => vpn.rotateDeviceKey()));

  handle(IPC.recentLogins, 0, () => wrap(() => vpn.loginNotices("list")));
  handle(IPC.markLoginsSeen, 0, () => wrap(() => vpn.loginNotices("seen")));
  handle(IPC.logoutOtherSessions, 0, () => wrap(() => vpn.loginNotices("logout-others")));
  handle(IPC.openSecurityPage, 0, () =>
    wrap(async () => {
      try {
        await shell.openExternal(securityPageUrl(store.getPreferences().baseUrl));
      } catch (error) {
        throw new LocalizedError("openWebsiteFailed", undefined, { cause: error });
      }
      return null;
    }),
  );

  handle(IPC.setPortForwarding, 1, (_event, enabled) => {
    if (typeof enabled !== "boolean") return invalid();
    return wrap(() => vpn.setPortForwarding(enabled));
  });

  handle(IPC.tor, 0, () => wrap(() => vpn.tor()));

  handle(IPC.setTor, 1, (_event, enabled) => {
    if (typeof enabled !== "boolean") return invalid();
    return wrap(() => vpn.tor(enabled));
  });

  handle(IPC.currentDeviceId, 0, () => vpn.currentDeviceId());

  handle(IPC.renameDevice, 2, (_event, id, name) => {
    const parsedId = deviceIdSchema.safeParse(id);
    const parsedName = deviceNameSchema.safeParse(name);
    if (!parsedId.success || !parsedName.success) return invalid();
    return wrap(() => vpn.renameDevice(parsedId.data, parsedName.data));
  });

  handle(IPC.removeDevice, 1, (_event, id) => {
    const parsed = deviceIdSchema.safeParse(id);
    if (!parsed.success) return invalid();
    return wrap(() => vpn.removeDevice(parsed.data));
  });

  handle(IPC.devicePortForwarding, 1, (_event, id) => {
    const parsed = deviceIdSchema.safeParse(id);
    if (!parsed.success) return invalid();
    return wrap(() => vpn.devicePortForwarding(parsed.data, "get"));
  });

  handle(IPC.addPortForward, 2, (_event, id, localPort) => {
    const parsed = deviceIdSchema.safeParse(id);
    const parsedLocal = localPortSchema.safeParse(localPort);
    if (!parsed.success || !parsedLocal.success) return invalid();
    return wrap(() => vpn.devicePortForwarding(parsed.data, parsedLocal.data === null ? "enable" : { addLocalPort: parsedLocal.data }));
  });

  handle(IPC.setPortForwardLocalPort, 3, (_event, id, port, localPort) => {
    const parsed = deviceIdSchema.safeParse(id);
    const parsedPort = forwardPortSchema.safeParse(port);
    const parsedLocal = localPortSchema.safeParse(localPort);
    if (!parsed.success || !parsedPort.success || !parsedLocal.success) return invalid();
    return wrap(() => vpn.devicePortForwarding(parsed.data, { port: parsedPort.data, localPort: parsedLocal.data }));
  });

  handle(IPC.removePortForward, 2, (_event, id, port) => {
    const parsed = deviceIdSchema.safeParse(id);
    const parsedPort = forwardPortSchema.safeParse(port);
    if (!parsed.success || !parsedPort.success) return invalid();
    return wrap(() => vpn.devicePortForwarding(parsed.data, { removePort: parsedPort.data }));
  });

  handle(IPC.proxies, 0, () => wrap(() => vpn.proxies()));

  handle(IPC.createProxy, 1, (_event, input) => {
    const parsed = parseProxyCreate(input);
    if (!parsed) return invalid();
    return wrap(() => vpn.createProxy(parsed));
  });

  handle(IPC.updateProxy, 2, (_event, id, patch) => {
    const parsed = parseProxyPatch(patch);
    if (!isProxyId(id) || !parsed) return invalid();
    return wrap(() => vpn.updateProxy(id, parsed));
  });

  handle(IPC.deleteProxy, 1, (_event, id) => {
    if (!isProxyId(id)) return invalid();
    return wrap(() => vpn.deleteProxy(id));
  });

  handle(IPC.openTelegramProxy, 1, (_event, link) => {
    if (!isTelegramProxyLink(link)) return invalid();
    return wrap(async () => {
      try {
        await shell.openExternal(link);
      } catch (error) {
        throw new LocalizedError("openWebsiteFailed", undefined, { cause: error });
      }
      return null;
    });
  });

  const support = <T>(task: (service: SupportService) => Promise<T>) =>
    wrap(async () => {
      const service = options.support;
      if (!service) throw new LocalizedError("unknown");
      try {
        return await task(service);
      } catch (error) {
        const mapped = supportError(error);
        vpn.noteApiError(mapped);
        throw mapped;
      }
    });

  handle(IPC.supportOverview, 0, () => support((service) => service.overview()));

  handle(IPC.supportUnread, 0, () => support((service) => service.unread()));

  handle(IPC.supportTicket, 1, (_event, id) => {
    const parsed = supportIdSchema.safeParse(id);
    if (!parsed.success) return invalid();
    return support((service) => service.ticket(parsed.data));
  });

  handle(IPC.supportCreate, 2, (_event, category, text) => {
    const parsedCategory = supportCategorySchema.safeParse(category);
    const parsedText = supportTextSchema.safeParse(text);
    if (!parsedCategory.success || !parsedText.success) return invalid();
    return support((service) => service.create(parsedCategory.data, parsedText.data));
  });

  handle(IPC.supportReply, 2, (_event, id, text) => {
    const parsedId = supportIdSchema.safeParse(id);
    const parsedText = supportTextSchema.safeParse(text);
    if (!parsedId.success || !parsedText.success) return invalid();
    return support((service) => service.reply(parsedId.data, parsedText.data));
  });

  handle(IPC.supportSetClosed, 2, (_event, id, closed) => {
    const parsedId = supportIdSchema.safeParse(id);
    if (!parsedId.success || typeof closed !== "boolean") return invalid();
    return support((service) => service.setClosed(parsedId.data, closed));
  });

  handle(IPC.measureLatency, 1, async (_event, ids): Promise<LatencyMeasurement[]> => {
    const parsed = latencyIdsSchema.safeParse(ids);
    if (!parsed.success) return [];
    return vpn.measureLatency(parsed.data).catch(() => []);
  });

  handle(IPC.copyText, 1, (_event, text) => {
    const parsed = clipboardTextSchema.safeParse(text);
    if (!parsed.success) return invalid();
    clipboard.writeText(parsed.data);
    return { ok: true, value: null } satisfies Result<null>;
  });

  options.registerExtra?.(handle);
}
