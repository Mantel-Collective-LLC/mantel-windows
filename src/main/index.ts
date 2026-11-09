import { app, BrowserWindow, dialog, Menu, nativeTheme, protocol, session, Tray, type WebContents } from "electron";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { IPC, type TunnelStatus } from "../../shared/core/contract";
import { registerDebugIpc } from "./debug/ipc";
import { IDENTITY, IS_DEBUG } from "./flavor";
import { i18n, setLanguagePreference, setSystemLocales } from "./i18n";
import { registerIpc } from "./ipc";
import { AUTOSTART_FLAG, connectAtLogin, macLauncher, quitPlan, windowsLauncher } from "./lifecycle";
import { createDesktopSupport } from "./support";
import { applyMacMenu } from "./mac-menu";
import { macosPlatform } from "./platform/macos";
import { repairService, windowsServicePlatform } from "./platform/windows-service";
import { sidecarRelay } from "./obfs/relay";
import { Store } from "./store";
import { ThemeController, windowChrome } from "./theme";
import { trayImage } from "./tray-icon";
import { codeOf, messageOf, VpnController } from "./vpn";

const IS_MAC = process.platform === "darwin";

const APP_SCHEME = "app";
const APP_HOST = "mantel";
const APP_ORIGIN = `${APP_SCHEME}://${APP_HOST}`;
const DISABLE_KILLSWITCH_FLAG = "--disable-killswitch";
const PRODUCTION_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "font-src 'self'",
  "img-src 'self'",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join("; ");

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

app.enableSandbox();
app.setAppUserModelId(IDENTITY.appUserModelId);

protocol.registerSchemesAsPrivileged([
  { scheme: APP_SCHEME, privileges: { standard: true, secure: true, supportFetchAPI: false, corsEnabled: false } },
]);

function originOf(url: string): string | null {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

const devRendererUrl = !app.isPackaged ? process.env.ELECTRON_RENDERER_URL : undefined;
const allowedOrigin = devRendererUrl ? (originOf(devRendererUrl) ?? APP_ORIGIN) : APP_ORIGIN;
const rendererRoot = path.join(__dirname, "../renderer");

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let quitting = false;
let quitConfirmed = false;
let theme: ThemeController | null = null;

if (!app.isPackaged) app.setPath("userData", path.join(app.getPath("appData"), IDENTITY.devUserDataName));
else if (IS_DEBUG) app.setPath("userData", path.join(app.getPath("appData"), IDENTITY.userDataName));
if (IS_DEBUG) app.setName(IDENTITY.productName);

const store = new Store(app.getPath("userData"));

function macHelperBinary(): string {
  return app.isPackaged
    ? path.join(process.resourcesPath, "helper", "mantel-helper")
    : path.join(app.getAppPath(), "build", "mac", "helper", "mantel-helper");
}

const platform = IS_MAC
  ? macosPlatform({
      helperBinary: macHelperBinary(),
      appVersion: app.getVersion(),
      installPrompt: () => i18n().t.mac.helperPrompt,
    })
  : windowsServicePlatform({
      serviceExe: app.isPackaged
        ? path.join(process.resourcesPath, "service", "mantel.exe")
        : path.join(app.getAppPath(), "build", "service", "mantel.exe"),
      repair: () => repairService({ packaged: app.isPackaged, execPath: process.execPath, resourcesPath: process.resourcesPath }),
    });
function obfsBinary(): string {
  const name = IS_MAC ? "mantel-obfs" : "mantel-obfs.exe";
  if (app.isPackaged) return path.join(process.resourcesPath, "obfs", name);
  return path.join(app.getAppPath(), "build", ...(IS_MAC ? ["mac", "obfs"] : ["obfs"]), name);
}

const sidecar = sidecarRelay(obfsBinary());
const vpn = new VpnController(store, {}, platform, platform.obfsRelay?.(sidecar) ?? { start: sidecar });
const support = createDesktopSupport({ store, transport: vpn.api.tickets });
vpn.logoutHooks.push(() => support.unregister());
const launcher = IS_MAC
  ? macLauncher(app, app.isPackaged)
  : windowsLauncher({
      packaged: app.isPackaged,
      exe: process.execPath,
      taskName: IDENTITY.autostartTask,
      description: `${IDENTITY.productName}: Start bei der Anmeldung (Einstellungen → Verbindung)`,
    });

function isTrustedSender(contents: WebContents, frameUrl: string | undefined): boolean {
  if (!mainWindow || contents.id !== mainWindow.webContents.id) return false;
  if (!frameUrl) return false;
  return originOf(frameUrl) === allowedOrigin;
}

async function serveRenderer(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.host !== APP_HOST) return new Response("Not found", { status: 404 });
  const relative = decodeURIComponent(url.pathname === "/" ? "/index.html" : url.pathname);
  const target = path.normalize(path.join(rendererRoot, relative));
  if (!target.startsWith(rendererRoot + path.sep)) return new Response("Forbidden", { status: 403 });
  try {
    const body = await readFile(target);
    return new Response(body, {
      headers: {
        "Content-Type": MIME[path.extname(target).toLowerCase()] ?? "application/octet-stream",
        "Content-Security-Policy": PRODUCTION_CSP,
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Opener-Policy": "same-origin",
      },
    });
  } catch {
    return new Response("Not found", { status: 404 });
  }
}

function hardenSessions(): void {
  const defaultSession = session.defaultSession;
  defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  defaultSession.setPermissionCheckHandler(() => false);
  defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const url = details.url;
    const allowed =
      url.startsWith(`${APP_ORIGIN}/`) ||
      url.startsWith("devtools://") ||
      (devRendererUrl !== undefined && (url.startsWith(allowedOrigin) || url.startsWith(allowedOrigin.replace("http", "ws"))));
    callback({ cancel: !allowed });
  });
}

app.on("web-contents-created", (_event, contents) => {
  contents.setWindowOpenHandler(() => ({ action: "deny" }));
  contents.on("will-navigate", (event, url) => {
    if (originOf(url) !== allowedOrigin) event.preventDefault();
  });
  contents.on("will-redirect", (event, url) => {
    if (originOf(url) !== allowedOrigin) event.preventDefault();
  });
  contents.on("will-attach-webview", (event) => event.preventDefault());
});

function sendToRenderer(channel: string, payload?: unknown): void {
  const contents = mainWindow?.webContents;
  if (!contents || contents.isDestroyed() || contents.isCrashed()) return;
  try {
    contents.send(channel, payload);
  } catch {
    return;
  }
}

function showWindow(): void {
  if (!mainWindow) {
    createWindow();
    return;
  }
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function createWindow(): void {
  const chrome = theme?.chrome() ?? windowChrome("light");
  mainWindow = new BrowserWindow({
    width: 420,
    height: 720,
    minWidth: 380,
    minHeight: 620,
    show: false,
    title: IDENTITY.productName,
    backgroundColor: chrome.backgroundColor,
    ...(IS_MAC
      ? { titleBarStyle: "hiddenInset" as const, trafficLightPosition: { x: 14, y: 13 } }
      : { titleBarStyle: "hidden" as const, titleBarOverlay: chrome.titleBarOverlay, icon: trayImage("disconnected") }),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
      devTools: !app.isPackaged || IS_DEBUG,
      backgroundThrottling: true,
    },
  });
  mainWindow.removeMenu();
  mainWindow.once("ready-to-show", () => mainWindow?.show());
  mainWindow.on("close", (event) => {
    if (quitting) return;
    event.preventDefault();
    mainWindow?.hide();
  });
  mainWindow.on("show", () => vpn.setWindowVisible(!mainWindow?.isMinimized()));
  mainWindow.on("restore", () => vpn.setWindowVisible(true));
  mainWindow.on("hide", () => vpn.setWindowVisible(false));
  mainWindow.on("minimize", () => vpn.setWindowVisible(false));
  mainWindow.on("closed", () => {
    mainWindow = null;
    theme?.attach(null);
  });
  theme?.attach(mainWindow);

  if (devRendererUrl) {
    void mainWindow.loadURL(devRendererUrl);
    return;
  }
  void mainWindow.loadURL(`${APP_ORIGIN}/index.html`);
}

function statusLabel(status: TunnelStatus): string {
  return i18n().t.tray.status[status.phase];
}

function systemLocales(): string[] {
  try {
    const preferred = app.getPreferredSystemLanguages();
    if (preferred.length > 0) return preferred;
  } catch {
  }
  const locale = app.getLocale();
  return locale ? [locale] : [];
}

function applyLanguage(): void {
  setSystemLocales(systemLocales());
  setLanguagePreference(store.getPreferences().language);
}

function refreshSystemLanguage(): void {
  const before = i18n().language;
  setSystemLocales(systemLocales());
  if (i18n().language !== before) {
    safely(updateTray);
    safely(updateMacMenu);
  }
}

async function connectFromTray(): Promise<void> {
  const preferred = store.getPreferences().lastNodeId;
  const nodes = await vpn.nodes().catch(() => []);
  const target = nodes.find((node) => node.id === preferred && node.online) ?? nodes.find((node) => node.online);
  if (!target) {
    showWindow();
    return;
  }
  await vpn.connect(target.id).catch(() => showWindow());
}

async function disableKillSwitchInteractive(): Promise<void> {
  try {
    await vpn.emergencyDisableKillSwitch();
    const { t } = i18n();
    dialog.showMessageBoxSync({ type: "info", title: "Mantel", message: IS_MAC ? t.mac.killSwitchDisabled : t.dialogs.killSwitchDisabled });
  } catch (error) {
    const { t, format } = i18n();
    dialog.showErrorBox("Mantel", format(t.dialogs.killSwitchFailed, { reason: messageOf(error) }));
  }
}

function updateTray(): void {
  if (!tray || tray.isDestroyed()) return;
  const status = vpn.getStatus();
  const session = vpn.session();
  const active = status.phase !== "disconnected";
  const { t, format } = i18n();
  const title = format(t.tray.title, { status: statusLabel(status) }).replace(/^Mantel\b/, IDENTITY.productName);
  tray.setImage(trayImage(status.phase));
  tray.setToolTip(title);
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: title, enabled: false },
      { type: "separator" },
      {
        label: t.tray.connect,
        visible: !active,
        enabled: session.loggedIn,
        click: () => void connectFromTray(),
      },
      { label: t.tray.disconnect, visible: active, click: () => void vpn.disconnect().catch(() => showWindow()) },
      { label: t.tray.openWindow, click: showWindow },
      { type: "separator" },
      {
        label: t.tray.disableKillSwitch,
        visible: status.firewallActive || store.getPreferences().alwaysOnKillSwitch,
        click: () => void disableKillSwitchInteractive(),
      },
      { label: t.tray.quit, click: () => app.quit() },
    ]),
  );
}

function createTray(): void {
  tray = new Tray(trayImage("disconnected"));
  if (!IS_MAC) tray.on("click", showWindow);
  updateTray();
}

function updateMacMenu(): void {
  if (!IS_MAC) return;
  const { t, format } = i18n();
  applyMacMenu({ t, format, productName: IDENTITY.productName, debug: IS_DEBUG, onShowWindow: showWindow });
}

async function confirmQuit(status: TunnelStatus): Promise<{ choice: "keep" | "disconnect" | "cancel"; remember: boolean }> {
  const { t } = i18n();
  const working = status.phase === "connected";
  const blocked = !working && status.firewallActive;
  const options = {
    type: "question" as const,
    title: t.dialogs.quitTitle,
    message: blocked ? t.dialogs.quitBlockedMessage : t.dialogs.quitMessage,
    detail: blocked
      ? t.dialogs.quitBlockedDetail
      : vpn.relayEndsWithApp()
        ? t.dialogs.quitDetailObfuscated
        : IS_MAC
          ? t.mac.quitDetail
          : t.dialogs.quitDetail,
    buttons: [blocked ? t.dialogs.quitKeepBlocked : t.dialogs.quitKeep, t.dialogs.quitDisconnect, t.dialogs.quitCancel],
    defaultId: working ? 0 : 1,
    cancelId: 2,
    noLink: true,
    ...(working ? { checkboxLabel: t.dialogs.quitRemember, checkboxChecked: false } : {}),
  };
  const result = mainWindow ? await dialog.showMessageBox(mainWindow, options) : await dialog.showMessageBox(options);
  const choice = result.response === 0 ? "keep" : result.response === 1 ? "disconnect" : "cancel";
  return { choice, remember: working && result.checkboxChecked === true && choice !== "cancel" };
}

app.on("before-quit", (event) => {
  if (quitConfirmed) {
    quitting = true;
    return;
  }
  event.preventDefault();
  void (async () => {
    const status = vpn.getStatus();
    const plan = quitPlan(status.phase, store.getPreferences().quitAction, vpn.relayEndsWithApp());
    let choice: "quit" | "keep" | "disconnect" | "cancel" = plan === "ask" ? "cancel" : plan;
    if (plan === "ask") {
      const answer = await confirmQuit(status);
      choice = answer.choice;
      if (answer.remember && answer.choice !== "cancel") {
        store.setPreferences({ ...store.getPreferences(), quitAction: answer.choice });
      }
    }
    if (choice === "cancel") return;
    if (choice === "disconnect") {
      try {
        await vpn.disconnect();
      } catch (error) {
        dialog.showErrorBox("Mantel", messageOf(error));
        showWindow();
        return;
      }
    }
    quitConfirmed = true;
    quitting = true;
    vpn.stopPolling();
    app.quit();
  })();
});

app.on("will-quit", () => {
  tray?.destroy();
  tray = null;
});

function safely(task: () => void): void {
  try {
    task();
  } catch (error) {
    console.error("Mantel: UI-Update fehlgeschlagen", error);
  }
}

async function runDisableKillSwitchCli(): Promise<void> {
  await app.whenReady();
  store.load();
  applyLanguage();
  try {
    await vpn.emergencyDisableKillSwitch();
    process.stdout.write(`${i18n().t.dialogs.cliKillSwitchDisabled}\n`);
    app.exit(0);
  } catch (error) {
    process.stderr.write(`Mantel: ${messageOf(error)}\n`);
    app.exit(1);
  }
}

function main(): void {
  const primary = app.requestSingleInstanceLock();
  if (process.argv.includes(DISABLE_KILLSWITCH_FLAG)) {
    if (primary) void runDisableKillSwitchCli();
    else app.quit();
    return;
  }
  if (!primary) {
    app.quit();
    return;
  }
  app.on("second-instance", (_event, argv) => {
    if (argv.includes(DISABLE_KILLSWITCH_FLAG)) {
      void disableKillSwitchInteractive();
      return;
    }
    showWindow();
  });

  void app.whenReady().then(async () => {
    store.load();
    applyLanguage();
    theme = new ThemeController(
      nativeTheme,
      () => store.getPreferences().theme,
      (system) => safely(() => sendToRenderer(IPC.systemThemeEvent, system)),
    );
    protocol.handle(APP_SCHEME, serveRenderer);
    hardenSessions();
    registerIpc({
      store,
      vpn,
      isTrustedSender,
      support,
      onPreferencesChanged: () => {
        safely(updateTray);
        safely(updateMacMenu);
      },
      onThemeChanged: () => safely(() => theme?.apply()),
      refreshSystemLanguage,
      launcher,
      assumeWireGuardInstalled:
        import.meta.env.MANTEL_FLAVOR === "debug" && !app.isPackaged && process.env.MANTEL_DEV_ASSUME_WIREGUARD === "1",
      registerExtra:
        import.meta.env.MANTEL_FLAVOR === "debug"
          ? (handle) =>
              registerDebugIpc(handle, {
                store,
                vpn,
                openDevTools: () => mainWindow?.webContents.openDevTools({ mode: "detach" }),
                onReset: () => {
                  safely(updateTray);
                  safely(() => theme?.apply());
                },
              })
          : undefined,
    });
    app.on("browser-window-focus", refreshSystemLanguage);
    let sentStatus = "";
    let trayState = "";
    vpn.on("status", (status: TunnelStatus) => {
      const next = JSON.stringify({ ...status, checkedAt: 0 });
      if (next !== sentStatus || IS_DEBUG) {
        sentStatus = next;
        safely(() => sendToRenderer(IPC.tunnelStatusEvent, status));
      }
      const tray = `${status.phase}|${status.firewallActive}|${vpn.session().loggedIn}`;
      if (tray !== trayState) {
        trayState = tray;
        safely(updateTray);
      }
    });
    vpn.on("session-ended", () => {
      safely(() => sendToRenderer(IPC.sessionEndedEvent));
      safely(updateTray);
    });
    createTray();
    updateMacMenu();
    if (IS_MAC) app.on("activate", showWindow);
    const atLogin = process.argv.includes(AUTOSTART_FLAG) || (IS_MAC && app.getLoginItemSettings().wasOpenedAtLogin === true);
    if (!atLogin) {
      createWindow();
      vpn.startPolling();
      await vpn.detectFirewall();
      return;
    }
    await vpn.detectFirewall();
    await vpn.refreshStatus().catch(() => undefined);
    vpn.startPolling();
    if (!store.getPreferences().connectOnLaunch || !(await launcher.isEnabled().catch(() => false))) return;
    await connectAtLogin({
      ready: () => ({ loggedIn: vpn.session().loggedIn, nodeId: store.getPreferences().lastNodeId, tunnelActive: vpn.tunnelActive() }),
      connect: (nodeId) => vpn.connect(nodeId),
      retryable: (error) => codeOf(error) === "network",
    });
  });

  app.on("window-all-closed", () => undefined);
}

main();
