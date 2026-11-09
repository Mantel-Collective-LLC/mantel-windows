import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { MantelBridge, Preferences } from "../shared/core/contract";
import { createTranslator, DICTIONARIES, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { ObfuscatedBadge, ObfuscationSettingRow, ObfuscationSettingView } from "../shared/ui/src/ui/obfuscation";

function render(language: Language, node: React.ReactNode): string {
  return renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{node}</I18nProvider>);
}

const selected = (html: string) => /<button[^>]*aria-selected="true"[^>]*>.*?<span class="relative">([^<]*)<\/span>/.exec(html)?.[1];

describe("setting row", () => {
  it.each(["de", "en"] as const)("%s: label, help text and the three modes", (language) => {
    const t = DICTIONARIES[language].settings;
    const html = render(language, <ObfuscationSettingView mode="auto" error={null} onChange={() => undefined} />);
    expect(html).toContain(t.obfuscation);
    expect(html).toContain(t.obfuscationDescription);
    for (const label of Object.values(t.obfuscationModes)) expect(html).toContain(`>${label}</span>`);
    expect(html).toContain(`aria-label="${t.obfuscation}"`);
    expect(selected(html)).toBe(t.obfuscationModes.auto);
  });

  it("marks the stored mode and shows an error", () => {
    const html = render("de", <ObfuscationSettingView mode="on" error="Speichern fehlgeschlagen" onChange={() => undefined} />);
    expect(selected(html)).toBe("An");
    expect(html).toContain("Speichern fehlgeschlagen");
    expect(DICTIONARIES.de.settings.obfuscationDescription).toContain("TLS, TCP 443");
  });

  it("only where the bridge can store it", () => {
    const preferences = { obfuscation: "off" } as Preferences;
    const without = render("de", <ObfuscationSettingRow bridge={{} as MantelBridge} preferences={preferences} onPreferences={() => undefined} />);
    expect(without).toBe("");
    const bridge = { setObfuscation: async () => ({ ok: true, value: preferences }) } as unknown as MantelBridge;
    const withBridge = render("de", <ObfuscationSettingRow bridge={bridge} preferences={preferences} onPreferences={() => undefined} />);
    expect(selected(withBridge)).toBe("Aus");
  });
});

describe("connection card", () => {
  it.each(["de", "en"] as const)("%s: quiet „Verschleiert · TLS“ only while obfuscated", (language) => {
    const home = DICTIONARIES[language].home;
    expect(render(language, <ObfuscatedBadge obfuscated />)).toContain(home.obfuscated);
    expect(render(language, <ObfuscatedBadge obfuscated={false} />)).toBe("");
    expect(render(language, <ObfuscatedBadge obfuscated={undefined} />)).toBe("");
  });

  it("wording", () => {
    expect(DICTIONARIES.de.home.obfuscated).toBe("Verschleiert · TLS");
    expect(DICTIONARIES.en.home.obfuscated).toBe("Obfuscated · TLS");
  });
});
