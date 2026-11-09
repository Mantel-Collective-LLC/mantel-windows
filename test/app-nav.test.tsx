import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { TunnelPhase, VpnNode } from "../shared/core/contract";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { resolveBack } from "../shared/ui/src/lib/navigation";
import { AppNav, type Tab } from "../shared/ui/src/ui/app-nav";
import { LocationBrowser } from "../shared/ui/src/ui/location-picker";
import { WorldMap } from "../shared/ui/src/ui/map/world-map";

const NODES: VpnNode[] = [
  { id: "de-fra", city: "Frankfurt", country: "DE", endpointHost: "fra.example", endpointPort: 51820, online: true, latencyMs: 12 },
  { id: "hk-hkg", city: "Hongkong", country: "HK", endpointHost: "hkg.example", endpointPort: 51820, online: true, latencyMs: 200 },
  { id: "at-vie", city: "Wien", country: "AT", endpointHost: "vie.example", endpointPort: 51820, online: true, status: "paused" },
];

function render(language: Language, node: React.ReactNode): string {
  return renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{node}</I18nProvider>);
}

function nav(language: Language, tab: Tab, phase: TunnelPhase, orientation: "bar" | "rail" = "bar"): string {
  return render(language, <AppNav tab={tab} phase={phase} orientation={orientation} onChange={() => undefined} />);
}

describe("tab bar", () => {
  it("is one navigation landmark with three buttons, the active one marked as the current page", () => {
    const html = nav("de", "locations", "disconnected");
    expect(html.match(/<nav /g)).toHaveLength(1);
    expect(html).toContain('aria-label="Hauptnavigation"');
    expect(html.match(/<button /g)).toHaveLength(3);
    expect(html.match(/aria-current="page"/g)).toHaveLength(1);
    expect(html).toMatch(/aria-current="page"[^>]*>(?:(?!<\/button>).)*Standorte/);
    for (const label of ["Verbindung", "Standorte", "Einstellungen"]) expect(html).toContain(label);
  });

  it("is translated", () => {
    const html = nav("en", "connect", "disconnected");
    expect(html).toContain('aria-label="Main navigation"');
    for (const label of ["Connection", "Locations", "Settings"]) expect(html).toContain(label);
    expect(html).not.toContain("Einstellungen");
  });

  it("shows a status dot on the connection tab only while a tunnel is up or coming up", () => {
    expect(nav("de", "connect", "disconnected")).not.toMatch(/bg-accent|bg-amber-500|bg-red-500/);
    expect(nav("de", "settings", "connected")).toContain("bg-accent");
    expect(nav("de", "settings", "connecting")).toContain("bg-amber-500");
    expect(nav("de", "settings", "stale")).toContain("bg-red-500");
  });

  it("is a bottom bar on narrow windows and a side rail on wide ones (never both visible)", () => {
    const bar = nav("de", "connect", "disconnected", "bar");
    const rail = nav("de", "connect", "disconnected", "rail");
    expect(bar).toContain("lg:hidden");
    expect(bar).toContain("safe-area-inset-bottom");
    expect(rail).toMatch(/class="hidden [^"]*lg:flex/);
  });

  it("Android back: sub-page → its tab, other tabs → connection, connection → the shell", () => {
    expect(resolveBack({ subScreen: true, tab: "settings" })).toBe("close-sub-screen");
    expect(resolveBack({ subScreen: false, tab: "locations" })).toBe("show-connect");
    expect(resolveBack({ subScreen: false, tab: "settings" })).toBe("show-connect");
    expect(resolveBack({ subScreen: false, tab: "connect" })).toBeNull();
  });
});

describe("locations tab", () => {
  const page = (language: Language) =>
    render(
      language,
      <LocationBrowser
        nodes={NODES}
        selectedId="hk-hkg"
        activeId="hk-hkg"
        favorites={["de-fra"]}
        onToggleFavorite={() => undefined}
        onChoose={() => undefined}
        autoFocus={false}
        layout="page"
        keyboardHint
      />,
    );

  it("lists the locations inline (no dialog) with a sticky search, favourites and the connected one", () => {
    const html = page("de");
    expect(html).not.toContain('role="dialog"');
    expect(html).toContain('role="radiogroup"');
    expect(html).toMatch(/<header class="[^"]*sticky top-0/);
    expect(html).toContain('placeholder="Land oder Stadt suchen"');
    expect(html).toContain("Favoriten");
    expect(html).toContain("Verbunden");
    expect(html).toContain("Pausiert");
    expect(html).toContain('aria-disabled="true"');
    expect(html.match(/aria-checked="true"/g)).toHaveLength(1);
    expect(html).toContain("↑↓");
  });

  it("is translated", () => {
    const html = page("en");
    expect(html).toContain('placeholder="Search country or city"');
    expect(html).toContain("Favourites");
    expect(html).not.toContain("Standort");
  });
});

describe("world map", () => {
  it("describes itself for screen readers and stays local (no external URLs)", () => {
    const off = render("de", <WorldMap nodes={NODES} node={NODES[0] ?? null} phase="disconnected" home={{ lat: 52.52, lon: 13.4 }} />);
    expect(off).toContain('role="img"');
    expect(off).toContain('aria-label="Weltkarte mit 2 Standorten. Nicht verbunden."');
    const on = render("en", <WorldMap nodes={NODES} node={NODES[1] ?? null} phase="connected" home={{ lat: 52.52, lon: 13.4 }} />);
    expect(on).toMatch(/aria-label="World map: connected to Hongkong, Hong Kong[^"]*."/);
    expect(on + off).not.toMatch(/https?:\/\//);
  });
});
