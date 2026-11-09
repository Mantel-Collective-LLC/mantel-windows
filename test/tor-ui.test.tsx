import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { Account, TorState } from "../shared/core/contract";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { torActive, TorBadge, TorView, withTorState, type TorLoad } from "../shared/ui/src/ui/tor";

function view(language: Language, load: TorLoad, extra: { pending?: boolean; error?: string | null } = {}): string {
  return renderToStaticMarkup(
    <I18nProvider translator={createTranslator(language)}>
      <TorView load={load} pending={extra.pending ?? false} error={extra.error ?? null} onToggle={() => undefined} />
    </I18nProvider>,
  );
}

const OFF: TorState = { deviceId: "dev1", nodeId: "nl-ams", city: "Amsterdam", enabled: false, availability: "ready", socks: null };
const switchOf = (html: string) => /<button[^>]*role="switch"[^>]*>/.exec(html)?.[0] ?? "";

describe("settings row", () => {
  it("ready: can be switched on, honest limits always shown (DE/EN)", () => {
    const html = view("de", { kind: "ready", state: OFF });
    expect(html).toContain("Über Tor");
    expect(html).toContain("Amsterdam schickt allen Verkehr");
    expect(html).toContain("Nur TCP");
    expect(html).toContain(".onion");
    expect(html).toContain("Tor-Browser");
    expect(html).toContain("Portweiterleitung ist im Tor-Modus aus");
    expect(switchOf(html)).not.toContain('disabled=""');
    const english = view("en", { kind: "ready", state: { ...OFF, enabled: true } });
    expect(english).toContain("Route through Tor");
    expect(english).toContain("TCP only");
    expect(switchOf(english)).toContain('aria-checked="true"');
  });

  it("starting: hint and switchable; unavailable: hint, cannot be switched on but off", () => {
    const starting = view("de", { kind: "ready", state: { ...OFF, availability: "starting" } });
    expect(starting).toContain("Tor startet auf Amsterdam");
    expect(switchOf(starting)).not.toContain('disabled=""');
    const unavailable = view("de", { kind: "ready", state: { ...OFF, availability: "unavailable" } });
    expect(unavailable).toContain("Amsterdam bietet Tor gerade nicht an.");
    expect(switchOf(unavailable)).toContain('disabled=""');
    expect(switchOf(view("de", { kind: "ready", state: { ...OFF, enabled: true, availability: "unavailable" } }))).not.toContain('disabled=""');
  });

  it("no device yet, loading, pending, errors", () => {
    const none = view("de", { kind: "ready", state: null });
    expect(none).toContain("Verbinde dich einmal mit einem Standort");
    expect(switchOf(none)).toContain('disabled=""');
    expect(switchOf(view("de", { kind: "loading" }))).toContain('disabled=""');
    expect(switchOf(view("de", { kind: "ready", state: OFF }, { pending: true }))).toContain('disabled=""');
    expect(view("de", { kind: "failed", error: "Netzwerk weg" })).toContain("Netzwerk weg");
    expect(view("de", { kind: "ready", state: OFF }, { error: "Kaputt" })).toContain("Kaputt");
  });
});

describe("home badge", () => {
  const account: Account = {
    id: "acc",
    paidUntil: "2027-01-01T00:00:00.000Z",
    settings: { killSwitch: true, lanAccess: false, ipv6: true, dns: {} as never },
    devices: [{ id: "dev1", name: "PC", nodeId: "nl-ams", ipv4: "10.8.0.5", createdOn: "2026-10-01", tor: true }],
  };
  const up = { phase: "connected" as const, nodeId: "nl-ams", addresses: ["10.8.0.5/32"] };

  it("shows only for the running tunnel's own device with tor on", () => {
    expect(torActive(account, up)).toBe(true);
    expect(torActive(account, { ...up, phase: "disconnected" })).toBe(false);
    expect(torActive(account, { ...up, addresses: ["10.8.0.6/32"] })).toBe(false);
    expect(torActive(withTorState(account, { ...OFF, enabled: false }), up)).toBe(false);
    expect(torActive(null, up)).toBe(false);
    const html = renderToStaticMarkup(
      <I18nProvider translator={createTranslator("de")}>
        <TorBadge active />
      </I18nProvider>,
    );
    expect(html).toContain("Über Tor");
  });
});
