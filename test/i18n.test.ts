import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import de from "../shared/core/i18n/de.json";
import en from "../shared/core/i18n/en.json";
import {
  createTranslator,
  DEFAULT_LANGUAGE_PREFERENCE,
  errorMessage,
  intlLocale,
  languageOfLocale,
  LocalizedError,
  plural,
  resolveLanguage,
  translate,
} from "../shared/core/i18n";
import { ApiClient, ApiError } from "../src/main/api/client";
import { activeLanguage, i18n, localizeError, setLanguagePreference, setSystemLocales, systemLanguage } from "../src/main/i18n";
import { UnresolvedHostError } from "../src/main/net/resolve";
import { BootstrapError, msiArchFor } from "../src/main/wireguard/bootstrap";
import { formatAgo, formatBytes, formatDate, formatRemaining } from "../shared/ui/src/lib/format";

type Tree = { [key: string]: string | Tree };

function leaves(tree: Tree, prefix = ""): Map<string, string> {
  const result = new Map<string, string>();
  for (const [key, value] of Object.entries(tree)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof value === "string") result.set(path, value);
    else for (const [inner, text] of leaves(value, path)) result.set(inner, text);
  }
  return result;
}

const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();

describe("language files", () => {
  const german = leaves(de as Tree);
  const english = leaves(en as Tree);

  it("have exactly the same keys", () => {
    expect([...english.keys()].sort()).toEqual([...german.keys()].sort());
  });

  it("use the same placeholders in both languages", () => {
    for (const [key, text] of german) expect(placeholders(english.get(key) ?? ""), key).toEqual(placeholders(text));
  });

  it("have no empty strings", () => {
    for (const [key, text] of [...german, ...english]) expect(text.trim(), key).not.toBe("");
  });
});

describe("language resolution", () => {
  it("lets an explicit choice win", () => {
    expect(resolveLanguage("de")).toBe("de");
    expect(resolveLanguage("en")).toBe("en");
  });

  it("is English without a choice: nothing saved and the legacy system value never follow the OS", () => {
    expect(resolveLanguage("system")).toBe("en");
    expect(resolveLanguage(undefined)).toBe("en");
    expect(resolveLanguage(null)).toBe("en");
    expect(DEFAULT_LANGUAGE_PREFERENCE).toBe("en");
  });

  it("still tells the OS language apart (reported to the UI only)", () => {
    expect(languageOfLocale("de-AT")).toBe("de");
    expect(languageOfLocale("de_CH")).toBe("de");
    expect(languageOfLocale("dem")).toBe("en");
    expect(languageOfLocale(undefined)).toBe("en");
  });

  it("formats with the OS locale when it matches the language", () => {
    expect(intlLocale("en", "en-US")).toBe("en-US");
    expect(intlLocale("de", "de-AT")).toBe("de-AT");
    expect(intlLocale("de", "en-US")).toBe("de-DE");
    expect(intlLocale("en", "de-DE")).toBe("en-GB");
    expect(intlLocale("en", "not a locale")).toBe("en-GB");
  });
});

describe("translation helpers", () => {
  it("handles plurals and placeholders", () => {
    expect(plural("de", de.format.days, 1)).toBe("1 Tag");
    expect(plural("de", de.format.days, 2)).toBe("2 Tage");
    expect(plural("en", en.format.days, 1)).toBe("1 day");
    expect(plural("en", en.format.days, 0)).toBe("0 days");
  });

  it("translates nested messages", () => {
    const message = { key: "logoutPartial" as const, params: { reason: { key: "tunnelStillRunning" as const } } };
    expect(translate("de", message)).toBe("Abgemeldet, aber der Tunnel läuft noch: trenne ihn mit „Trennen“ oder starte das Gerät neu. Grund: Der Tunnel läuft noch.");
    expect(translate("en", message)).toBe("Signed out, but the tunnel is still running: disconnect it with “Disconnect” or restart the device. Reason: The tunnel is still running.");
  });

  it("keeps German in .message and translates on demand", () => {
    const error = new LocalizedError("locationOffline", { city: "Wien" });
    expect(error.message).toBe("Wien ist gerade nicht erreichbar. Wähle einen anderen Standort oder versuch es später.");
    expect(errorMessage(error, "en")).toBe("Wien is not reachable right now. Choose another location or try again later.");
    expect(errorMessage(new Error("raw"), "en")).toBe("raw");
    expect(errorMessage("x", "en")).toBe("Unknown error.");
  });
});

describe("renderer formatting", () => {
  const german = createTranslator("de");
  const english = createTranslator("en", "en-US");

  it("formats durations", () => {
    expect(formatRemaining(0, german)).toBe("Abgelaufen");
    expect(formatRemaining(0, english)).toBe("Expired");
    expect(formatRemaining(3 * 86_400_000, german)).toBe("3 Tage");
    expect(formatRemaining(86_400_000 + 5, english)).toBe("1 day");
    expect(formatRemaining(2 * 3_600_000 + 5 * 60_000, german)).toBe("2 Std 5 Min");
    expect(formatRemaining(2 * 3_600_000 + 5 * 60_000, english)).toBe("2 h 5 min");
    expect(formatAgo(12_000, german)).toBe("vor 12 s");
    expect(formatAgo(12_000, english)).toBe("12 s ago");
    expect(formatAgo(3 * 60_000, english)).toBe("3 min ago");
  });

  it("formats numbers and dates in the active locale", () => {
    expect(formatBytes(1536, german)).toBe("1,5 KB");
    expect(formatBytes(1536, english)).toBe("1.5 KB");
    expect(formatDate("2026-03-04T12:00:00Z", german)).toBe("04.03.2026");
    expect(formatDate("2026-03-04T12:00:00Z", english)).toBe("03/04/2026");
    expect(formatDate("2026-03-04T12:00:00Z", createTranslator("en"))).toBe("04/03/2026");
  });
});

describe("main process language", () => {
  afterEach(() => {
    setSystemLocales([]);
    setLanguagePreference("system");
  });

  it("resolves from the stored preference only: English unless German was chosen, whatever the OS says", () => {
    setSystemLocales(["de-DE", "en-US"]);
    setLanguagePreference("system");
    expect(activeLanguage()).toBe("en");
    expect(systemLanguage()).toBe("de");
    setLanguagePreference("de");
    expect(i18n().t.tray.quit).toBe("Beenden");
    setLanguagePreference("en");
    expect(activeLanguage()).toBe("en");
    expect(systemLanguage()).toBe("de");
    expect(i18n().format(i18n().t.tray.title, { status: i18n().t.tray.status.connected })).toBe("Mantel · Connected");
    setSystemLocales(["fr-FR"]);
    setLanguagePreference(undefined);
    expect(activeLanguage()).toBe("en");
  });

  it("translates errors raised deep in main with the active language", () => {
    const bootstrap = new BootstrapError("downloadFailed", "network", { status: 404 });
    const unresolved = new UnresolvedHostError("vpn.example", false);
    setLanguagePreference("de");
    expect(localizeError(bootstrap)).toBe("Download fehlgeschlagen (HTTP 404).");
    expect(localizeError(unresolved)).toBe("Die Adresse vpn.example lässt sich nicht auflösen.");
    setLanguagePreference("en");
    expect(localizeError(bootstrap)).toBe("Download failed (HTTP 404).");
    expect(localizeError(unresolved)).toBe("The address vpn.example cannot be resolved.");
    expect(() => msiArchFor("mips")).toThrow("Nicht unterstützte Architektur: mips");
    try {
      msiArchFor("mips");
    } catch (error) {
      expect(localizeError(error)).toBe("Unsupported architecture: mips");
    }
  });
});

describe("API client errors", () => {
  let server: Server;
  let base = "";
  const seen: Array<string | undefined> = [];

  beforeAll(async () => {
    server = createServer((request, response) => {
      seen.push(request.headers["accept-language"]);
      if (request.url === "/api/v1/nodes") {
        response.writeHead(503);
        response.end();
        return;
      }
      response.writeHead(404, { "content-type": "text/html" });
      response.end("<html>nope</html>");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("carries message keys that are translated where they are shown", async () => {
    const api = new ApiClient(() => base, () => "token", undefined, () => "en");
    const status = await api.nodes().catch((error: unknown) => error);
    expect(status).toBeInstanceOf(ApiError);
    expect((status as ApiError).message).toBe("Serverfehler (503).");
    expect(errorMessage(status, "en")).toBe("Server error (503).");
    expect(seen.at(-1)).toBe("en");

    const html = await api.account().catch((error: unknown) => error);
    expect(errorMessage(html, "de")).toBe(
      "Der Server antwortet nicht wie die Mantel-API. Versuche es später erneut (HTTP 404, text/html).",
    );
    expect(errorMessage(html, "en")).toBe(
      "The server does not respond like the Mantel API. Try again later (HTTP 404, text/html).",
    );

    const offline = new ApiClient(() => "http://127.0.0.1:1", () => null);
    const unreachable = await offline.nodes().catch((error: unknown) => error);
    expect(errorMessage(unreachable, "en")).toBe("Server not reachable. Check your connection.");
    const notLoggedIn = await offline.account().catch((error: unknown) => error);
    expect(errorMessage(notLoggedIn, "de")).toBe("Nicht angemeldet.");
  });
});
