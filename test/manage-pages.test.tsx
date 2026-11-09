import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { Account, MantelBridge, VpnNode } from "../shared/core/contract";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { DevicesPage } from "../shared/ui/src/screens/devices";
import { PortForwardsPage } from "../shared/ui/src/screens/port-forwards";
import { ProxiesPage } from "../shared/ui/src/screens/proxies";
import { deviceKind } from "../shared/ui/src/ui/manage";

const ok = <T,>(value: T) => Promise.resolve({ ok: true as const, value });
const bridge = {
  currentDeviceId: () => Promise.resolve(null),
  renameDevice: () => ok(null),
  removeDevice: () => ok(null),
  devicePortForwarding: () => ok(null),
  addPortForward: () => ok(null),
  removePortForward: () => ok(null),
  proxies: () => ok([]),
} as unknown as MantelBridge;

const nodes = [{ id: "nl-ams", city: "Amsterdam", country: "NL", endpointHost: "198.51.100.4", endpointPort: 51820, online: true }] as VpnNode[];
const account = (devices: Account["devices"]): Account => ({
  id: "acc_1",
  paidUntil: "2027-01-01",
  settings: { killSwitch: true, lanAccess: false, ipv6: false, dns: { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false } },
  devices,
});

function render(language: Language, element: React.ReactElement) {
  return renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{element}</I18nProvider>);
}

describe("device type", () => {
  it("is guessed from the names the apps give", () => {
    expect(deviceKind("Windows 7F3A")).toBe("windows");
    expect(deviceKind("macOS 01AB")).toBe("macos");
    expect(deviceKind("Android · Pixel 8")).toBe("android");
    expect(deviceKind("Router Wohnzimmer")).toBe("other");
    expect(deviceKind("Windowsill")).toBe("other");
  });
});

describe("devices page", () => {
  it("lists every device with type and location, each opens its details", () => {
    const html = render(
      "de",
      <DevicesPage
        bridge={bridge}
        account={account([
          { id: "a1", name: "Windows 7F3A", nodeId: "nl-ams", ipv4: "10.8.0.2", createdOn: "2026-10-01" },
          { id: "a2", name: "Router", nodeId: "xx-gone", ipv4: "10.8.0.3", createdOn: "2026-10-01" },
        ])}
        nodes={nodes}
        onAccount={() => undefined}
        onOpenForwards={() => undefined}
        onShowConnect={() => undefined}
      />,
    );
    expect(html).toContain("Windows · Amsterdam");
    expect(html).toContain("WireGuard · Unbekannter Standort");
    expect(html).toContain('aria-label="Details zu Router"');
    expect(html).not.toContain("10.8.0.2");
  });

  it("empty: one sentence and one button", () => {
    const html = render(
      "en",
      <DevicesPage bridge={bridge} account={account([])} nodes={nodes} onAccount={() => undefined} onOpenForwards={() => undefined} onShowConnect={() => undefined} />,
    );
    expect(html).toContain("No devices yet");
    expect(html.match(/<button/g)).toHaveLength(1);
  });
});

describe("forwards and proxies pages", () => {
  it("forwards: empty state without devices, a card per device otherwise", () => {
    expect(render("de", <PortForwardsPage bridge={bridge} account={account([])} nodes={nodes} onShowConnect={() => undefined} />)).toContain(
      "Noch keine Geräte",
    );
    const html = render(
      "de",
      <PortForwardsPage
        bridge={bridge}
        account={account([{ id: "a1", name: "Windows 7F3A", nodeId: "nl-ams", ipv4: "10.8.0.2", createdOn: "2026-10-01" }])}
        nodes={nodes}
        onShowConnect={() => undefined}
      />,
    );
    expect(html).toContain('aria-label="Windows 7F3A"');
    expect(html).toContain("UPnP/NAT-PMP");
  });

  it("proxies: header and honest info, list loads after mount", () => {
    const html = render("en", <ProxiesPage bridge={bridge} nodes={nodes} />);
    expect(html).toContain("Proxies");
    expect(html).toContain("unencrypted");
  });
});
