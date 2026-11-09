import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { Environment, MantelBridge, TunnelStatus } from "../shared/core/contract";
import { createTranslator, DICTIONARIES, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { AlwaysOnHint, TunnelControls } from "../shared/ui/src/ui/tunnel-controls";

const DOWN: TunnelStatus = {
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
  checkedAt: 0,
};
const UP: TunnelStatus = { ...DOWN, phase: "connected", nodeId: "fra", connectedAt: 1, lastHandshakeAt: 1, leakProtection: "wireguard" };

const environment = (android: boolean): Environment => ({
  platform: android ? "android" : "win32",
  elevated: true,
  wireguardInstalled: true,
  wireguardPath: null,
  wireguardSource: null,
  encryptionAvailable: true,
  appVersion: "2026.0.1",
  features: {
    desktopWindow: !android,
    managedWireGuard: !android,
    firewallLockdown: !android,
    systemLockdown: android,
    appExclusion: android,
  },
});

const bridge = { disconnect: async () => ({ ok: true, value: DOWN }) } as unknown as MantelBridge;

function render(node: ReactNode, language: Language = "de"): string {
  return renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{node}</I18nProvider>);
}

describe("TunnelControls", () => {
  it("logged out with a running tunnel: a clear disconnect button (Windows and Android)", () => {
    for (const android of [false, true]) {
      const html = render(<TunnelControls bridge={bridge} environment={environment(android)} status={UP} />);
      expect(html).toContain("Der VPN-Tunnel ist noch aktiv");
      expect(html).toContain("Du bist nicht angemeldet, der Tunnel läuft aber weiter.");
      expect(html).toContain("Verbindung trennen");
      expect(html).toContain('data-testid="tunnel-controls"');
    }
    const en = render(<TunnelControls bridge={bridge} environment={environment(false)} status={UP} />, "en");
    expect(en).toContain("The VPN tunnel is still active");
    expect(en).toContain("Disconnect");
  });

  it("a stale tunnel says that it no longer responds; while disconnecting the button is busy", () => {
    const stale = render(<TunnelControls bridge={bridge} environment={environment(true)} status={{ ...UP, phase: "stale" }} />);
    expect(stale).toContain("Der Tunnel antwortet nicht mehr.");
    const busy = render(<TunnelControls bridge={bridge} environment={environment(true)} status={{ ...UP, phase: "disconnecting" }} />);
    expect(busy).toContain('aria-busy="true"');
  });

  it("explains a tunnel Mantel ended itself (device removed on the website)", () => {
    const status: TunnelStatus = { ...DOWN, revoked: "device_removed", error: DICTIONARIES.de.errors.deviceRemoved };
    const html = render(<TunnelControls bridge={bridge} environment={environment(true)} status={status} />);
    expect(html).toContain("Verbindung getrennt");
    expect(html).toContain("Dieses Gerät wurde entfernt. Verbinde dich neu, um es wieder anzumelden.");
    expect(html).not.toContain("Verbindung trennen");
  });

  it("renders nothing without a tunnel and without a reason", () => {
    expect(render(<TunnelControls bridge={bridge} environment={environment(false)} status={DOWN} />)).toBe("");
    expect(render(<TunnelControls bridge={bridge} environment={environment(true)} status={{ ...DOWN, error: "alt" }} />)).toBe("");
  });

  it("always-on hint: Android will restart the tunnel, with a link to the system settings", () => {
    const withSettings = { ...bridge, openSystemVpnSettings: async () => undefined } as MantelBridge;
    const html = render(<AlwaysOnHint bridge={withSettings} />);
    expect(html).toContain("„Durchgehend aktives VPN“ ist für Mantel eingeschaltet");
    expect(html).toContain("Android-Einstellungen öffnen");
    expect(render(<AlwaysOnHint bridge={bridge} />)).not.toContain("Android-Einstellungen öffnen");
  });
});
