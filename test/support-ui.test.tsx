import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { resolveBack } from "../shared/ui/src/lib/navigation";
import { SupportScreen } from "../shared/ui/src/screens/support";
import { AppNav } from "../shared/ui/src/ui/app-nav";
import type { MantelBridge } from "../shared/core/contract";

function render(language: Language, node: React.ReactNode): string {
  return renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{node}</I18nProvider>);
}

describe("support tab", () => {
  it("appears as a fourth tab only with support, with an unread badge", () => {
    const without = render("de", <AppNav tab="connect" phase="disconnected" orientation="bar" onChange={() => undefined} />);
    expect(without.match(/<button /g)).toHaveLength(3);
    expect(without).not.toContain("Support");
    const withSupport = render("de", <AppNav tab="support" phase="disconnected" orientation="bar" onChange={() => undefined} support={{ unread: 3 }} />);
    expect(withSupport.match(/<button /g)).toHaveLength(4);
    expect(withSupport).toContain("grid-cols-4");
    expect(withSupport).toMatch(/data-testid="support-badge"[^>]*>3</);
    expect(withSupport).toMatch(/aria-current="page"[^>]*>(?:(?!<\/button>).)*Support/);
    const none = render("en", <AppNav tab="connect" phase="disconnected" orientation="rail" onChange={() => undefined} support={{ unread: 0 }} />);
    expect(none).not.toContain("support-badge");
  });

  it("Android back from the support tab goes to the connection", () => {
    expect(resolveBack({ subScreen: false, tab: "support" })).toBe("show-connect");
  });

  it("the screen says it is end-to-end encrypted, in both languages, without any key wording", () => {
    const bridge = { supportOverview: async () => ({ ok: true, value: { available: true, unread: 0, tickets: [] } }) } as unknown as MantelBridge;
    const de = render("de", <SupportScreen bridge={bridge} />);
    expect(de).toContain("Ende-zu-Ende verschlüsselt");
    const en = render("en", <SupportScreen bridge={bridge} />);
    expect(en).toMatch(/end-to-end encrypted/i);
    expect(de + en).not.toMatch(/PGP|privat(e)? (key|Schlüssel)/i);
  });
});
