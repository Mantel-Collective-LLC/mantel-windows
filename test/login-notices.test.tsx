import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { LoginOverview, MantelBridge } from "../shared/core/contract";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { NOTHING_PENDING, type LoginNotices } from "../shared/ui/src/lib/logins";
import { LoginNoticeBanner, LoginsPage, loginSummary } from "../shared/ui/src/ui/login-notices";

const ONE: LoginOverview = { logins: [{ client: "windows", method: "code" }] };
const TWO: LoginOverview = { logins: [{ client: "browser", method: "passkey" }, { client: "android", method: "code" }] };

function notices(overview: LoginOverview | null): LoginNotices {
  const ok = async () => ({ ok: true as const, value: null });
  return { available: true, overview, reload: async () => undefined, confirm: ok, logoutOthers: ok };
}

const render = (language: Language, node: React.ReactNode) =>
  renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{node}</I18nProvider>);
const text = (html: string) => html.replace(/<[^>]*>/g, " ");

const TIME = /\d{1,2}:\d{2}|\d{1,2}\.\s?\d{1,2}\.|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b|vor \d|\bago\b/;

describe("renderer", () => {
  it("banner: kind of app and method, no time (DE/EN), sign out others / that was me", () => {
    const german = render("de", <LoginNoticeBanner notices={notices(ONE)} onReview={() => undefined} />);
    expect(german).toContain("Neue Anmeldung: Windows-App (Kontonummer)");
    expect(german).toContain("Andere abmelden");
    expect(german).toContain("Das war ich");
    expect(text(german)).not.toMatch(TIME);
    const english = render("en", <LoginNoticeBanner notices={notices(TWO)} onReview={() => undefined} />);
    expect(english).toContain("2 new sign-ins: Browser (passkey), Android app (account number)");
    expect(text(english)).not.toMatch(TIME);
    expect(render("de", <LoginNoticeBanner notices={notices(NOTHING_PENDING)} onReview={() => undefined} />)).toBe("");
    expect(render("de", <LoginNoticeBanner notices={notices(null)} onReview={() => undefined} />)).toBe("");
  });

  it("page: only unconfirmed sign-ins, sign out others, passkeys only on the website", () => {
    const bridge = {
      logoutOtherSessions: async () => ({ ok: true, value: null }),
      openSecurityPage: async () => ({ ok: true, value: null }),
    } as unknown as MantelBridge;
    const html = render("de", <LoginsPage bridge={bridge} notices={notices(TWO)} />);
    expect(html).toContain("Unbestätigte Anmeldungen");
    expect(html).toContain("Browser (Passkey)");
    expect(html).toContain("Android-App (Kontonummer)");
    expect(html).toContain("Andere Sitzungen abmelden");
    expect(html).toContain("Im Web-Dashboard öffnen");
    expect(text(html)).not.toMatch(TIME);
    expect(render("de", <LoginsPage bridge={bridge} notices={notices(NOTHING_PENDING)} />)).toContain("Nichts zu bestätigen.");
    const plain = render("en", <LoginsPage bridge={{} as MantelBridge} notices={notices(ONE)} />);
    expect(plain).toContain("two-factor authentication with an authenticator app in the web dashboard");
    expect(plain).not.toContain("Open web dashboard");
    expect(plain).not.toContain("Sign out other sessions");
  });

  it("settings summary", () => {
    const i18n = createTranslator("de");
    expect(loginSummary(notices(null), i18n)).toBe("Lädt …");
    expect(loginSummary(notices(ONE), i18n)).toBe("1 unbestätigte Anmeldung");
    expect(loginSummary(notices(TWO), i18n)).toBe("2 unbestätigte Anmeldungen");
    expect(loginSummary(notices(NOTHING_PENDING), i18n)).toBe("Nichts zu bestätigen");
  });
});
