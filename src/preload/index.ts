import { contextBridge, ipcRenderer, type IpcRendererEvent } from "electron";
import { IPC, type DebugBridge, type MantelBridge, type Theme, type TunnelStatus } from "../../shared/core/contract";
import { DEBUG_IPC } from "../../shared/core/debug-ipc";

const debug: DebugBridge | undefined =
  import.meta.env.MANTEL_FLAVOR === "debug"
    ? Object.freeze({
        info: () => ipcRenderer.invoke(DEBUG_IPC.info),
        requestLog: () => ipcRenderer.invoke(DEBUG_IPC.requestLog),
        clearRequestLog: () => ipcRenderer.invoke(DEBUG_IPC.clearRequestLog),
        healthCheck: () => ipcRenderer.invoke(DEBUG_IPC.healthCheck),
        setVerbose: (enabled: boolean) => ipcRenderer.invoke(DEBUG_IPC.setVerbose, enabled === true),
        copyDiagnostics: () => ipcRenderer.invoke(DEBUG_IPC.copyDiagnostics),
        resetLocalData: () => ipcRenderer.invoke(DEBUG_IPC.resetLocalData),
        openDevTools: () => ipcRenderer.invoke(DEBUG_IPC.openDevTools),
      })
    : undefined;

const bridge: MantelBridge = {
  environment: () => ipcRenderer.invoke(IPC.environment),
  session: () => ipcRenderer.invoke(IPC.session),
  login: (code, totp) => ipcRenderer.invoke(IPC.login, String(code), totp === undefined ? null : String(totp)),
  register: () => ipcRenderer.invoke(IPC.register),
  confirmRegistration: () => ipcRenderer.invoke(IPC.confirmRegistration),
  logout: () => ipcRenderer.invoke(IPC.logout),
  account: () => ipcRenderer.invoke(IPC.account),
  nodes: () => ipcRenderer.invoke(IPC.nodes),
  updateSettings: (patch) => ipcRenderer.invoke(IPC.updateSettings, patch),
  connect: (nodeId) => ipcRenderer.invoke(IPC.connect, String(nodeId)),
  disconnect: () => ipcRenderer.invoke(IPC.disconnect),
  tunnelStatus: () => ipcRenderer.invoke(IPC.tunnelStatus),
  preferences: () => ipcRenderer.invoke(IPC.preferences),
  setAlwaysOnKillSwitch: (enabled) => ipcRenderer.invoke(IPC.setAlwaysOnKillSwitch, enabled === true),
  selectNode: (nodeId) => ipcRenderer.invoke(IPC.selectNode, String(nodeId)),
  setLanguage: (language) => ipcRenderer.invoke(IPC.setLanguage, String(language)),
  setPostQuantum: (enabled) => ipcRenderer.invoke(IPC.setPostQuantum, enabled === true),
  wifiSecurity: () => ipcRenderer.invoke(IPC.wifiSecurity),
  setAutoConnectOpenWifi: (enabled) => ipcRenderer.invoke(IPC.setAutoConnectOpenWifi, enabled === true),
  setObfuscation: (mode) => ipcRenderer.invoke(IPC.setObfuscation, String(mode)),
  setTheme: (theme) => ipcRenderer.invoke(IPC.setTheme, String(theme)),
  autostart: () => ipcRenderer.invoke(IPC.autostart),
  setAutostart: (enabled) => ipcRenderer.invoke(IPC.setAutostart, enabled === true),
  setConnectOnLaunch: (enabled) => ipcRenderer.invoke(IPC.setConnectOnLaunch, enabled === true),
  setQuitAction: (action) => ipcRenderer.invoke(IPC.setQuitAction, String(action)),
  openWireGuardDownload: () => ipcRenderer.invoke(IPC.openWireGuardDownload),
  installWireGuard: () => ipcRenderer.invoke(IPC.installWireGuard),
  copyText: (text) => ipcRenderer.invoke(IPC.copyText, String(text)),
  openAccountPage: () => ipcRenderer.invoke(IPC.openAccountPage),
  checkAppVersion: () => ipcRenderer.invoke(IPC.checkAppVersion),
  openDownloadPage: () => ipcRenderer.invoke(IPC.openDownloadPage),
  measureLatency: (nodeIds) => ipcRenderer.invoke(IPC.measureLatency, Array.isArray(nodeIds) ? nodeIds.map(String) : []),
  portForwarding: () => ipcRenderer.invoke(IPC.portForwarding),
  recentLogins: () => ipcRenderer.invoke(IPC.recentLogins),
  markLoginsSeen: () => ipcRenderer.invoke(IPC.markLoginsSeen),
  logoutOtherSessions: () => ipcRenderer.invoke(IPC.logoutOtherSessions),
  openSecurityPage: () => ipcRenderer.invoke(IPC.openSecurityPage),
  setPortForwarding: (enabled) => ipcRenderer.invoke(IPC.setPortForwarding, enabled === true),
  tor: () => ipcRenderer.invoke(IPC.tor),
  setTor: (enabled) => ipcRenderer.invoke(IPC.setTor, enabled === true),
  deviceKey: () => ipcRenderer.invoke(IPC.deviceKey),
  rotateDeviceKey: () => ipcRenderer.invoke(IPC.rotateDeviceKey),
  currentDeviceId: () => ipcRenderer.invoke(IPC.currentDeviceId),
  renameDevice: (id, name) => ipcRenderer.invoke(IPC.renameDevice, String(id), String(name)),
  removeDevice: (id) => ipcRenderer.invoke(IPC.removeDevice, String(id)),
  devicePortForwarding: (id) => ipcRenderer.invoke(IPC.devicePortForwarding, String(id)),
  addPortForward: (id) => ipcRenderer.invoke(IPC.addPortForward, String(id)),
  removePortForward: (id, port) => ipcRenderer.invoke(IPC.removePortForward, String(id), Number(port)),
  proxies: () => ipcRenderer.invoke(IPC.proxies),
  createProxy: (input) => ipcRenderer.invoke(IPC.createProxy, input),
  updateProxy: (id, patch) => ipcRenderer.invoke(IPC.updateProxy, String(id), patch),
  deleteProxy: (id) => ipcRenderer.invoke(IPC.deleteProxy, String(id)),
  openTelegramProxy: (link) => ipcRenderer.invoke(IPC.openTelegramProxy, String(link)),
  supportOverview: () => ipcRenderer.invoke(IPC.supportOverview),
  supportUnread: () => ipcRenderer.invoke(IPC.supportUnread),
  supportTicket: (id) => ipcRenderer.invoke(IPC.supportTicket, String(id)),
  supportCreate: (category, text) => ipcRenderer.invoke(IPC.supportCreate, String(category), String(text)),
  supportReply: (id, text) => ipcRenderer.invoke(IPC.supportReply, String(id), String(text)),
  supportSetClosed: (id, closed) => ipcRenderer.invoke(IPC.supportSetClosed, String(id), closed === true),
  onTunnelStatus: (listener) => {
    const wrapped = (_event: IpcRendererEvent, status: TunnelStatus) => listener(status);
    ipcRenderer.on(IPC.tunnelStatusEvent, wrapped);
    return () => {
      ipcRenderer.removeListener(IPC.tunnelStatusEvent, wrapped);
    };
  },
  onSessionEnded: (listener) => {
    const wrapped = () => listener();
    ipcRenderer.on(IPC.sessionEndedEvent, wrapped);
    return () => {
      ipcRenderer.removeListener(IPC.sessionEndedEvent, wrapped);
    };
  },
  onSystemThemeChange: (listener) => {
    const wrapped = (_event: IpcRendererEvent, theme: Theme) => listener(theme);
    ipcRenderer.on(IPC.systemThemeEvent, wrapped);
    return () => {
      ipcRenderer.removeListener(IPC.systemThemeEvent, wrapped);
    };
  },
  ...(debug ? { debug } : {}),
};

contextBridge.exposeInMainWorld("mantel", Object.freeze(bridge));
