import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { PortForwardingState } from "../shared/core/contract";
import de from "../shared/core/i18n/de.json";
import en from "../shared/core/i18n/en.json";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { PortForwardingRow, PortForwardingView, type PortForwardingLoad } from "../shared/ui/src/ui/port-forwarding";
import { DeviceForwardsView, ForwardNotes, publishPort, parseLocalPort, type ForwardsLoad } from "../shared/ui/src/screens/port-forwards";
import type { MantelBridge } from "../shared/core/contract";

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
    expect(en.forwards.listenHint).toBe("The program must listen on 0.0.0.0 (all interfaces), not only on 127.0.0.1.");
    expect(de.forwards.listenHint).toContain("0.0.0.0");
    for (const dict of [de, en]) {
      for (const key of ["localPort", "localPortPlaceholder", "localPortHelp", "localPortInvalid", "localPortFor", "save", "localUnsupported", "changeLocal", "unpublish", "publicAddress", "torrentTitle"] as const) {
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

const device = { id: "a1", name: "Windows 7F3A", nodeId: "nl-ams", ipv4: "10.8.0.2", createdOn: "2026-10-01" };
const node = { id: "nl-ams", city: "Amsterdam", country: "NL", endpointHost: "198.51.100.4", endpointPort: 51820, online: true } as never;
const LOCAL: PortForwardingState = { ...OFF, localPort: true };

function card(
  language: Language,
  load: ForwardsLoad,
  extra: { own?: boolean; localText?: string; error?: string | null } = {},
): string {
  return renderToStaticMarkup(
    <I18nProvider translator={createTranslator(language)}>
      <DeviceForwardsView
        bridge={{ setPortForwardLocalPort: () => undefined } as unknown as MantelBridge}
        device={device}
        node={node}
        own={extra.own ?? true}
        load={load}
        pending={null}
        error={extra.error ?? null}
        localText={extra.localText ?? ""}
        onLocalText={() => undefined}
        onPublish={() => undefined}
        onRemove={() => undefined}
        onSaveLocal={() => Promise.resolve(true)}
        onRetry={() => undefined}
      />
    </I18nProvider>,
  );
}
const publishButton = (html: string) => /<button[^>]*type="submit"[^>]*>/.exec(html)?.[0] ?? "";

describe("publish a port (Einstellungen → Portfreigaben)", () => {
  it("form: labelled local port field with placeholder 3000, Publish, hint about the empty field", () => {
    const html = card("en", { kind: "ready", state: LOCAL });
    expect(html).toContain(">Local port</label>");
    expect(html).toContain('placeholder="3000"');
    expect(html).toContain('aria-describedby="pf-local-a1-help"');
    expect(html).toContain("same port number on both sides");
    expect(html).toContain(">Publish</button>");
    expect(publishButton(html)).not.toContain('disabled=""');
    expect(card("de", { kind: "ready", state: LOCAL })).toContain(">Veröffentlichen</button>");
  });

  it("result row: public address → this device :local port, TCP and UDP, copy, change, unpublish", () => {
    const state: PortForwardingState = { ...LOCAL, forwards: [{ port: 41873, host: "203.0.113.162", localPort: 3000 }] };
    const html = card("en", { kind: "ready", state });
    expect(html).toContain("203.0.113.162:41873");
    expect(html).toContain("→ this device :3000");
    expect(html).toContain("TCP and UDP");
    expect(html).toContain('aria-label="Public address 203.0.113.162:41873: Copy"');
    expect(html).toContain("Change local port");
    expect(html).toContain('aria-label="Unpublish port 41873"');
    expect(html).not.toContain('type="submit"');
    expect(html).toContain("Unpublish one to publish another.");
    const torrent = card("en", { kind: "ready", state: { ...OFF, forwards: [{ port: 41234, host: "198.51.100.4", localPort: null }] } }, { own: false });
    expect(torrent).toContain("→ Windows 7F3A :41234");
    expect(torrent).not.toContain("Change local port");
  });

  it("invalid field: error text, Publish disabled", () => {
    const html = card("en", { kind: "ready", state: LOCAL }, { localText: "70000" });
    expect(html).toContain("Enter a whole number from 1 to 65535.");
    expect(html).toContain('aria-invalid="true"');
    expect(publishButton(html)).toContain('disabled=""');
  });

  it("location without local ports: plain explanation, Publish disabled until the field is empty", () => {
    const html = card("en", { kind: "ready", state: OFF }, { localText: "3000" });
    expect(html).toContain(
      "Amsterdam can&#x27;t publish to a different local port yet. Leave the field empty to use the same port number, or try another location.",
    );
    expect(publishButton(html)).toContain('disabled=""');
    expect(publishButton(card("en", { kind: "ready", state: OFF }))).not.toContain('disabled=""');
    expect(card("de", { kind: "ready", state: OFF }, { localText: "3000" })).toContain(
      "Amsterdam kann noch nicht an einen anderen lokalen Port veröffentlichen",
    );
  });

  it("not offered, no tunnel, errors", () => {
    const off = card("en", { kind: "ready", state: { ...LOCAL, available: false, reason: "disabled" } });
    expect(off).toContain("switched off on Amsterdam");
    expect(off).not.toContain('type="submit"');
    expect(card("en", { kind: "ready", state: null })).toContain("no tunnel");
    expect(card("en", { kind: "failed", error: "Network down" })).toContain("Network down");
    expect(card("en", { kind: "ready", state: LOCAL }, { error: "Kaputt" })).toContain("Kaputt");
  });

  it("submit sends the local port, null for an empty field, nothing when invalid or unsupported", async () => {
    const calls: unknown[][] = [];
    const bridge = {
      addPortForward: (...args: unknown[]) => {
        calls.push(args);
        return Promise.resolve({ ok: true as const, value: LOCAL });
      },
    } as unknown as MantelBridge;
    expect(await publishPort(bridge, "a1", " 3000 ", true)).toEqual({ ok: true, value: LOCAL });
    await publishPort(bridge, "a1", "", true);
    await publishPort(bridge, "a1", "", false);
    expect(calls).toEqual([
      ["a1", 3000],
      ["a1", null],
      ["a1", null],
    ]);
    expect(publishPort(bridge, "a1", "3000", false)).toBeNull();
    expect(publishPort(bridge, "a1", "abc", true)).toBeNull();
    expect(publishPort({} as MantelBridge, "a1", "3000", true)).toBeNull();
    expect(calls).toHaveLength(3);
  });

  it("notes: short list, warning, torrent steps folded away", () => {
    const html = renderToStaticMarkup(
      <I18nProvider translator={createTranslator("en")}>
        <ForwardNotes />
      </I18nProvider>,
    );
    expect(html).toContain("0.0.0.0");
    expect(html).toContain("connected to the VPN");
    expect(html).toContain("public address changes");
    expect(html).toContain("reachable from the internet");
    expect(html).toMatch(/<details[^>]*><summary[^>]*>Using it for torrents\?<\/summary>/);
    expect(html).toContain("UPnP/NAT-PMP");
  });
});
