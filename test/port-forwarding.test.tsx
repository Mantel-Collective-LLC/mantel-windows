import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { PortForwardingState } from "../shared/core/contract";
import de from "../shared/core/i18n/de.json";
import en from "../shared/core/i18n/en.json";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { PortForwardingRow, PortForwardingView, type PortForwardingLoad } from "../shared/ui/src/ui/port-forwarding";
import { parseLocalPort } from "../shared/ui/src/screens/port-forwards";

function view(language: Language, load: PortForwardingLoad, extra: { pending?: boolean; error?: string | null; copied?: boolean } = {}): string {
  return renderToStaticMarkup(
    <I18nProvider translator={createTranslator(language)}>
      <PortForwardingView
        load={load}
        pending={extra.pending ?? false}
        error={extra.error ?? null}
        copied={extra.copied ?? false}
        onToggle={() => undefined}
        onCopy={() => undefined}
      />
    </I18nProvider>,
  );
}

const OFF: PortForwardingState = { nodeId: "nl-ams", city: "Amsterdam", available: true, reason: null, max: 1, localPort: false, forwards: [] };
const ON: PortForwardingState = { ...OFF, forwards: [{ port: 41234, host: "198.51.100.4", localPort: null }] };
const switchOf = (html: string) => /<button[^>]*role="switch"[^>]*>/.exec(html)?.[0] ?? "";

describe("settings row", () => {
  it("off: switch available, description names the location, warning always visible", () => {
    const html = view("de", { kind: "ready", state: OFF });
    expect(html).toContain("Portweiterleitung");
    expect(html).toContain("Öffnet einen Port auf Amsterdam");
    expect(html).toContain("aus dem Internet erreichbar");
    expect(switchOf(html)).toContain('aria-checked="false"');
    expect(switchOf(html)).not.toContain('disabled=""');
    expect(html).not.toContain("41234");
  });

  it("on: shows „Port 41234 auf Amsterdam“, host:port, TCP/UDP, copy button and the torrent hint (DE/EN)", () => {
    const html = view("de", { kind: "ready", state: ON });
    expect(html).toContain("Port 41234 auf Amsterdam");
    expect(html).toContain("198.51.100.4:41234");
    expect(html).toContain("TCP und UDP");
    expect(html).toContain("Port kopieren");
    expect(html).toContain("Listening-Port");
    expect(html).toContain("VPN-Schnittstelle");
    expect(switchOf(html)).toContain('aria-checked="true"');
    const english = view("en", { kind: "ready", state: ON }, { copied: true });
    expect(english).toContain("Port 41234 on Amsterdam");
    expect(english).toContain("Copied");
    expect(english).toContain("reachable from the internet");
    expect(english).toContain("bind the client to the VPN interface");
  });

  it("not offered: reason shown, cannot be switched on; an active port shows „Pausiert“ and can still be switched off", () => {
    const unsupported = view("de", { kind: "ready", state: { ...OFF, available: false, reason: "unsupported" } });
    expect(unsupported).toContain("Amsterdam bietet noch keine Portweiterleitung an.");
    expect(switchOf(unsupported)).toContain('disabled=""');
    const paused = view("de", { kind: "ready", state: { ...ON, available: false, reason: "expired" } });
    expect(paused).toContain("Pausiert");
    expect(paused).toContain("nur mit aktivem Konto");
    expect(switchOf(paused)).not.toContain('disabled=""');
    expect(view("en", { kind: "ready", state: { ...OFF, available: false, reason: "disabled" } })).toContain("switched off on Amsterdam");
    expect(view("en", { kind: "ready", state: { ...OFF, available: false, reason: "offline" } })).toContain("Amsterdam is unreachable");
  });

  it("no device yet, loading, errors", () => {
    const none = view("de", { kind: "ready", state: null });
    expect(none).toContain("Verbinde dich einmal mit einem Standort");
    expect(switchOf(none)).toContain('disabled=""');
    expect(switchOf(view("de", { kind: "loading" }))).toContain('disabled=""');
    expect(view("de", { kind: "failed", error: "Netzwerk weg" })).toContain("Netzwerk weg");
    expect(view("de", { kind: "ready", state: OFF }, { error: "Kaputt" })).toContain("Kaputt");
    expect(switchOf(view("de", { kind: "ready", state: OFF }, { pending: true }))).toContain('disabled=""');
  });

  it("hidden when the bridge has no port forwarding (older shells)", () => {
    const html = renderToStaticMarkup(
      <I18nProvider translator={createTranslator("de")}>
        <PortForwardingRow bridge={{} as never} />
      </I18nProvider>,
    );
    expect(html).toBe("");
  });

  it("local port field: live validation (empty = public port, 1–65535 only)", () => {
    expect(parseLocalPort("")).toBeNull();
    expect(parseLocalPort("  ")).toBeNull();
    expect(parseLocalPort("3000")).toBe(3000);
    expect(parseLocalPort(" 1 ")).toBe(1);
    expect(parseLocalPort("65535")).toBe(65535);
    for (const bad of ["0", "65536", "99999", "-1", "3e3", "30.5", "abc", "3000a", "123456"]) expect(parseLocalPort(bad)).toBeUndefined();
  });

  it("local port texts: hint about 0.0.0.0 in both languages", () => {
    expect(en.forwards.listenHint).toBe("The program on your device must listen on 0.0.0.0 (all interfaces), not only on 127.0.0.1.");
    expect(de.forwards.listenHint).toContain("0.0.0.0");
    for (const dict of [de, en]) {
      for (const key of ["localPort", "localPortPlaceholder", "localPortHelp", "localPortInvalid", "localPortFor", "save"] as const) {
        expect(dict.forwards[key].length).toBeGreaterThan(0);
      }
    }
  });

  it("texts exist in both languages", () => {
    for (const dict of [de, en]) {
      for (const key of ["portForwarding", "portForwardingDescription", "portForwardingNoDevice", "portForwardingActive", "portForwardingHint", "portForwardingWarning", "portForwardingPaused"] as const) {
        expect(dict.settings[key].length).toBeGreaterThan(0);
      }
      expect(Object.keys(dict.settings.portForwardingReasons).sort()).toEqual(["disabled", "expired", "offline", "tor", "unsupported"]);
    }
  });
});
