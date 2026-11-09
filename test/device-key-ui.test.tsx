import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { DeviceKeyView, keyAgeText, type DeviceKeyLoad } from "../shared/ui/src/ui/device-key";

const NOW = Date.parse("2026-11-04T12:00:00.000Z");
const MINUTE = 60_000;
const DAY = 86_400_000;

function view(language: Language, load: DeviceKeyLoad, extra: { pending?: boolean; renewed?: boolean; error?: string | null } = {}) {
  return renderToStaticMarkup(
    <I18nProvider translator={createTranslator(language)}>
      <DeviceKeyView
        load={load}
        now={NOW}
        pending={extra.pending ?? false}
        renewed={extra.renewed ?? false}
        error={extra.error ?? null}
        onRenew={() => undefined}
      />
    </I18nProvider>,
  );
}
const buttonOf = (html: string) => /<button[^>]*>.*?<\/button>/.exec(html)?.[0] ?? "";

describe("key age", () => {
  it("just now, minutes, hours, days (DE/EN, plural)", () => {
    const de = createTranslator("de");
    const en = createTranslator("en");
    expect(keyAgeText(20_000, de)).toBe("Gerade erneuert");
    expect(keyAgeText(2 * MINUTE, de)).toBe("Erneuert vor 2 Min.");
    expect(keyAgeText(3 * 60 * MINUTE, de)).toBe("Erneuert vor 3 Std.");
    expect(keyAgeText(DAY, de)).toBe("Erneuert vor 1 Tag");
    expect(keyAgeText(12 * DAY + 5, de)).toBe("Erneuert vor 12 Tagen");
    expect(keyAgeText(2 * MINUTE, en)).toBe("Renewed 2 min ago");
    expect(keyAgeText(DAY, en)).toBe("Renewed 1 day ago");
    expect(keyAgeText(-5, en)).toBe("Renewed just now");
  });
});

describe("settings row", () => {
  it("shows the key age, the automatic interval, the explanation and an enabled button", () => {
    const html = view("de", { kind: "ready", info: { createdAt: NOW - 12 * DAY } });
    expect(html).toContain("WireGuard-Schlüssel");
    expect(html).toContain("Erneuert vor 12 Tagen");
    expect(html).toContain("automatisch alle 30 Tage");
    expect(html).toContain("Der private Schlüssel verlässt das Gerät nie");
    expect(buttonOf(html)).toContain("Erneuern");
    expect(buttonOf(html)).toContain('aria-label="Schlüssel erneuern"');
    expect(buttonOf(html)).not.toContain('disabled=""');
  });

  it("pending: spinner and busy button; renewed: check, accent age", () => {
    const pending = view("en", { kind: "ready", info: { createdAt: NOW - 3 * DAY } }, { pending: true });
    expect(buttonOf(pending)).toContain('aria-busy="true"');
    expect(buttonOf(pending)).toContain("Renewing");
    const renewed = view("en", { kind: "ready", info: { createdAt: NOW - 2 * MINUTE } }, { renewed: true });
    expect(buttonOf(renewed)).toContain("Renewed");
    expect(renewed).toContain('class="tabular-nums text-accent-strong">Renewed 2 min ago');
  });

  it("no device yet: hint, button disabled; load error shown", () => {
    const empty = view("de", { kind: "ready", info: null });
    expect(empty).toContain("Verbinde dich einmal mit einem Standort");
    expect(buttonOf(empty)).toContain('disabled=""');
    expect(view("de", { kind: "failed", error: "Server nicht erreichbar" })).toContain("Server nicht erreichbar");
    expect(view("de", { kind: "ready", info: { createdAt: NOW } }, { error: "Zu viele Versuche" })).toContain("Zu viele Versuche");
  });
});
