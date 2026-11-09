import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { TunnelStatus, VpnNode } from "../shared/core/contract";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider, translatorFor } from "../shared/ui/src/i18n/context";
import { ConnectCard } from "../shared/ui/src/screens/home";
import { LocationButton, PickerPanel } from "../shared/ui/src/ui/location-picker";
import { SaveIndicator } from "../shared/ui/src/ui/primitives";

const NODES: VpnNode[] = [
  { id: "de-fra", city: "Frankfurt", country: "DE", endpointHost: "fra.example", endpointPort: 51820, online: true, latencyMs: 12 },
  { id: "at-vie", city: "Wien", country: "AT", endpointHost: "vie.example", endpointPort: 51820, online: false },
];

const DISCONNECTED: TunnelStatus = {
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

function render(language: Language, node: React.ReactNode): string {
  return renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{node}</I18nProvider>);
}

describe("translated renderer output", () => {
  it("renders the location button and picker in both languages", () => {
    const button = <LocationButton node={NODES[0] ?? null} nodes={NODES} loading={false} onOpen={() => undefined} />;
    expect(render("de", button)).toContain("Frankfurt");
    expect(render("de", button)).toContain("Deutschland");
    expect(render("en", button)).toContain("Germany");
    const picker = (
      <PickerPanel
        onClose={() => undefined}
        nodes={NODES}
        selectedId="de-fra"
        activeId={null}
        favorites={["at-vie"]}
        onToggleFavorite={() => undefined}
        onSelect={() => undefined}
        touch
      />
    );
    const german = render("de", picker);
    expect(german).toContain("Standort wählen");
    expect(german).toContain("1 von 2 verfügbar");
    expect(german).toContain("Favoriten");
    expect(german).toContain("Offline");
    expect(german).toContain("Gerade nicht erreichbar");
    expect(german).toContain('aria-checked="true"');
    expect(german).toContain('aria-disabled="true"');
    const english = render("en", picker);
    expect(english).toContain("Choose location");
    expect(english).toContain("Response time: fast");
    expect(english).not.toMatch(/\d ms/);
    expect(german).toContain("Antwortzeit: schnell");
    expect(english).toContain("Unreachable right now");
    expect(english).not.toContain("Standort");
  });

  it("renders the connect card in both languages", () => {
    const card = (
      <ConnectCard
        status={DISCONNECTED}
        node={NODES[0] ?? null}
        busy={false}
        canConnect
        error={null}
        protection={{ android: false, systemLockdown: null }}
        onToggle={() => undefined}
      />
    );
    const german = render("de", card);
    expect(german).toContain("Nicht verbunden");
    expect(german).toContain('aria-label="Verbinden"');
    expect(german).toContain("Dein Traffic läuft direkt über deinen Provider.");
    const english = render("en", card);
    expect(english).toContain("Not connected");
    expect(english).toContain('aria-label="Connect"');
    expect(english).toContain("Your traffic goes straight through your provider.");
    expect(english).toContain("Last handshake");
  });

  it("renders the save indicator", () => {
    expect(render("de", <SaveIndicator state="saved" />)).toContain("Gespeichert");
    expect(render("en", <SaveIndicator state="saved" />)).toContain("Saved");
  });

  it("picks the language from the preference only; the OS locale just formats dates of a matching language", () => {
    expect(translatorFor("en", { systemLocale: "de-DE" }).language).toBe("en");
    expect(translatorFor("de", { systemLocale: "de-AT" })).toMatchObject({ language: "de", locale: "de-AT" });
    expect(translatorFor(undefined, { systemLocale: "en-US" })).toMatchObject({ language: "en", locale: "en-US" });
    expect(translatorFor("system", { systemLocale: "de-CH" }).language).toBe("en");
    expect(translatorFor(undefined, { systemLocale: "de-DE" }).language).toBe("en");
  });
});
