import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { TunnelPhase, TunnelStatus, VpnNode } from "../shared/core/contract";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { ConnectCard } from "../shared/ui/src/screens/home";
import { LocationBrowser, LocationButton } from "../shared/ui/src/ui/location-picker";
import { WorldMap } from "../shared/ui/src/ui/map/world-map";

const NODE: VpnNode = { id: "hk-hkg", city: "Hongkong", country: "HK", endpointHost: "203.0.113.60", endpointPort: 51820, online: true };
const INTERNALS = ["hk-hkg", "203.0.113.60", "51820", "10.64.12.7", "fd00:6d61"];

function status(phase: TunnelPhase): TunnelStatus {
  const live = phase === "connected" || phase === "stale";
  return {
    phase,
    nodeId: phase === "disconnected" ? null : NODE.id,
    connectedAt: live ? 1 : null,
    lastHandshakeAt: live ? 1 : null,
    rxBytes: 0,
    txBytes: 0,
    endpoint: live ? "203.0.113.60:51820" : null,
    addresses: live ? ["10.64.12.7/32", "fd00:6d61:6e74::7/128"] : [],
    dns: [],
    leakProtection: "wireguard",
    firewallActive: false,
    serviceState: null,
    error: null,
    checkedAt: 0,
  };
}

function render(language: Language, node: React.ReactNode): string {
  return renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{node}</I18nProvider>);
}

function card(language: Language, phase: TunnelPhase, withLocation: boolean): string {
  return render(
    language,
    <ConnectCard
      status={status(phase)}
      node={NODE}
      busy={false}
      canConnect
      error={null}
      protection={{ android: false, systemLockdown: null }}
      location={withLocation ? <LocationButton node={NODE} nodes={[NODE]} loading={false} inline onOpen={() => undefined} /> : undefined}
      onToggle={() => undefined}
    />,
  );
}

describe("connection card without internals", () => {
  it("shows no location id, tunnel address or endpoint in any state or language", () => {
    for (const language of ["de", "en"] as const) {
      for (const phase of ["disconnected", "connecting", "connected", "stale", "disconnecting"] as const) {
        for (const withLocation of [true, false]) {
          const html = card(language, phase, withLocation);
          for (const internal of INTERNALS) expect(html, `${language} ${phase} ${internal}`).not.toContain(internal);
          expect(html).not.toMatch(/Tunnel-Adresse|Tunnel address/);
        }
      }
    }
  });

  it("keeps the protocol label and names the country instead of the endpoint", () => {
    const html = card("de", "connected", false);
    expect(html).toMatch(/>WireGuard</);
    expect(html).toContain("Hongkong");
    expect(card("en", "disconnected", false)).toContain("Hong Kong");
  });

  it("the locations tab and the map do not show them either", () => {
    const list = render(
      "de",
      <LocationBrowser
        nodes={[NODE]}
        selectedId={NODE.id}
        activeId={NODE.id}
        favorites={[]}
        onToggleFavorite={() => undefined}
        onChoose={() => undefined}
        autoFocus={false}
        layout="page"
        keyboardHint={false}
      />,
    );
    const map = render("de", <WorldMap nodes={[NODE]} node={NODE} phase="connected" home={null} fill />);
    for (const html of [list, map]) {
      const shown = html.replace(/\s(id|aria-labelledby|aria-describedby|aria-controls|data-[a-z-]+)="[^"]*"/g, "");
      for (const internal of INTERNALS) expect(shown).not.toContain(internal);
    }
  });
});
