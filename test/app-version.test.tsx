import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import {
  compareVersions,
  evaluateUpdate,
  isSnoozed,
  normalizeVersion,
  parseAppVersionInfo,
  parseSnooze,
  parseVersion,
  SNOOZE_MS,
  versionCode,
  type AppVersionInfo,
} from "../shared/core/app-version";
import { downloadPageUrl, type MantelBridge, type TunnelStatus } from "../shared/core/contract";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import {
  fetchVersionInfo,
  INACTIVE_UPDATE_CHECK,
  readSnooze,
  UpdateProvider,
  writeSnooze,
  type UpdateCheck,
} from "../shared/ui/src/lib/update-check";
import { UpdateBanner, UpdateRequiredScreen, VersionLine } from "../shared/ui/src/ui/update";
import packageJson from "../package.json";

const INFO: AppVersionInfo = {
  platform: "windows",
  latest: "2026.1.0",
  minimum: "2026.0.1",
  downloadUrl: "/download",
  notes: { de: "Schneller verbinden.", en: "Faster connecting." },
  sha256: "a".repeat(64),
};

describe("version scheme", () => {
  it("compares numerically per YEAR.MINOR.PATCH", () => {
    const ordered = ["2025.99.999", "2026.0.1", "2026.0.2", "2026.0.10", "2026.1.0", "2026.10.0", "2027.0.0"];
    for (let i = 0; i < ordered.length; i++) {
      for (let j = 0; j < ordered.length; j++) expect(compareVersions(ordered[i], ordered[j])).toBe(Math.sign(i - j));
    }
    expect(compareVersions("2026.0.10", "2026.0.9")).toBe(1);
    expect(versionCode(parseVersion("2026.0.1")!)).toBe(202600001);
    expect(versionCode(parseVersion("2026.1.0")!)).toBe(202601000);
  });

  it("ignores a build suffix and rejects everything else", () => {
    expect(normalizeVersion("2026.0.1-browser")).toBe("2026.0.1");
    expect(normalizeVersion(" 2026.00.01 ")).toBe("2026.0.1");
    for (const bad of ["", "2026.0", "26.0.1", "2026.100.0", "2026.0.1000", "v2026.0.1", null, undefined, 2026, "x".repeat(80)]) {
      expect(parseVersion(bad)).toBeNull();
    }
    expect(compareVersions("2026.0.1", "kaputt")).toBeNull();
  });

  it("the running app has a valid version", () => {
    expect(parseVersion(packageJson.version)).not.toBeNull();
  });
});

describe("evaluateUpdate", () => {
  it("up to date, newer, below minimum", () => {
    expect(evaluateUpdate("2026.1.0", INFO)).toEqual({ kind: "current" });
    expect(evaluateUpdate("2027.0.0", INFO)).toEqual({ kind: "current" });
    expect(evaluateUpdate("2026.0.1", INFO)).toEqual({ kind: "available", latest: "2026.1.0" });
    expect(evaluateUpdate("2026.0.0", INFO)).toEqual({ kind: "required", latest: "2026.1.0", minimum: "2026.0.1" });
    expect(evaluateUpdate("2026.0.0-browser", INFO).kind).toBe("required");
  });

  it("never blocks without data, without a newer download or with an unknown own version", () => {
    expect(evaluateUpdate("2026.0.0", null)).toEqual({ kind: "current" });
    expect(evaluateUpdate("2026.0.0", { ...INFO, latest: null, minimum: null })).toEqual({ kind: "current" });
    expect(evaluateUpdate("unbekannt", INFO)).toEqual({ kind: "current" });
    expect(evaluateUpdate(undefined, INFO)).toEqual({ kind: "current" });
    expect(evaluateUpdate("2026.1.0", { ...INFO, minimum: "2027.0.0" })).toEqual({ kind: "current" });
    expect(evaluateUpdate("2026.0.1", { ...INFO, minimum: null })).toEqual({ kind: "available", latest: "2026.1.0" });
  });
});

describe("parseAppVersionInfo", () => {
  it("accepts the API answer and validates every field", () => {
    expect(parseAppVersionInfo({ ...INFO }, "windows")).toEqual(INFO);
    expect(parseAppVersionInfo({ ...INFO, latest: null, minimum: null, notes: null, sha256: null }, "windows")).toEqual({
      ...INFO,
      latest: null,
      minimum: null,
      notes: null,
      sha256: null,
    });
    expect(parseAppVersionInfo(INFO, "android")).toBeNull();
    expect(parseAppVersionInfo({ ...INFO, latest: "neu" }, "windows")).toBeNull();
    expect(parseAppVersionInfo({ ...INFO, minimum: 5 }, "windows")).toBeNull();
    expect(parseAppVersionInfo("nope", "windows")).toBeNull();
    expect(parseAppVersionInfo([], "windows")).toBeNull();
    const odd = parseAppVersionInfo(
      { ...INFO, downloadUrl: "https://evil.example/x", sha256: "XYZ", notes: { de: "x".repeat(501), en: "y" } },
      "windows",
    );
    expect(odd).toMatchObject({ downloadUrl: "/download", sha256: null, notes: null });
  });

  it("the download page is always the fixed path on the API server", () => {
    expect(downloadPageUrl("https://api.example.org")).toBe("https://api.example.org/download");
  });
});

describe("Später (snooze)", () => {
  const memory = () => {
    const data = new Map<string, string>();
    return {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => void data.set(key, value),
      removeItem: (key: string) => void data.delete(key),
    };
  };
  const available = { kind: "available", latest: "2026.1.0" } as const;

  it("hides this version for 3 days, a newer one shows at once", () => {
    const store = memory();
    const now = 1_000_000;
    writeSnooze("2026.1.0", now, store);
    const snooze = readSnooze(store);
    expect(snooze).toEqual({ version: "2026.1.0", until: now + SNOOZE_MS });
    expect(isSnoozed(available, snooze, now + SNOOZE_MS - 1)).toBe(true);
    expect(isSnoozed(available, snooze, now + SNOOZE_MS)).toBe(false);
    expect(isSnoozed({ kind: "available", latest: "2026.1.1" }, snooze, now)).toBe(false);
    expect(isSnoozed({ kind: "required", latest: "2026.1.0", minimum: "2026.1.0" }, snooze, now)).toBe(false);
    expect(isSnoozed(available, snooze, now - 1000)).toBe(false);
  });

  it("survives broken or missing storage", () => {
    expect(parseSnooze("{kaputt")).toBeNull();
    expect(parseSnooze(JSON.stringify({ version: "x", until: 1 }))).toBeNull();
    const throwing = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
      removeItem: () => undefined,
    };
    expect(readSnooze(throwing)).toBeNull();
    expect(writeSnooze("2026.1.0", 5, throwing)).toEqual({ version: "2026.1.0", until: 5 + SNOOZE_MS });
    expect(readSnooze(null)).toBeNull();
  });
});

describe("fetchVersionInfo", () => {
  it("is silent on every failure", async () => {
    expect(await fetchVersionInfo({})).toBeNull();
    expect(await fetchVersionInfo({ checkAppVersion: async () => ({ ok: false, error: "offline", code: "network" }) })).toBeNull();
    expect(
      await fetchVersionInfo({
        checkAppVersion: async () => {
          throw new Error("bridge gone");
        },
      }),
    ).toBeNull();
    expect(await fetchVersionInfo({ checkAppVersion: async () => ({ ok: true, value: INFO }) })).toEqual(INFO);
  });
});

const DISCONNECTED: TunnelStatus = {
  phase: "disconnected",
  nodeId: null,
  connectedAt: null,
  lastHandshakeAt: null,
  rxBytes: 0,
  txBytes: 0,
  endpoint: null,
  addresses: [],
  dns: [],
  leakProtection: "none",
  firewallActive: false,
  serviceState: null,
  error: null,
  checkedAt: 0,
};
const CONNECTED: TunnelStatus = { ...DISCONNECTED, phase: "connected", nodeId: "ch-zrh", connectedAt: 1 };

function checkFor(currentVersion: string, overrides: Partial<UpdateCheck> = {}): UpdateCheck {
  return { ...INACTIVE_UPDATE_CHECK, supported: true, info: INFO, state: evaluateUpdate(currentVersion, INFO), ...overrides };
}

function render(node: ReactNode, update: UpdateCheck, language: Language = "de"): string {
  return renderToStaticMarkup(
    <I18nProvider translator={createTranslator(language)}>
      <UpdateProvider value={update}>{node}</UpdateProvider>
    </I18nProvider>,
  );
}

const bridge = {} as MantelBridge;

describe("UpdateBanner", () => {
  it("shows the new version with Herunterladen and Später", () => {
    const html = render(<UpdateBanner />, checkFor("2026.0.1"));
    expect(html).toContain("Neue Version 2026.1.0 verfügbar");
    expect(html).toContain("Herunterladen");
    expect(html).toContain("Später");
    expect(html).toContain("Schneller verbinden.");
    expect(html).toContain('aria-label="Hinweis auf Version 2026.1.0 für 3 Tage ausblenden"');
    expect(html).toMatch(/aria-labelledby="[^"]+"/);
  });

  it("speaks English", () => {
    const html = render(<UpdateBanner />, checkFor("2026.0.1"), "en");
    expect(html).toContain("New version 2026.1.0 available");
    expect(html).toContain("Download");
    expect(html).toContain("Later");
    expect(html).toContain("Faster connecting.");
  });

  it("stays silent when up to date, snoozed, unsupported or when the update is required", () => {
    expect(render(<UpdateBanner />, checkFor("2026.1.0"))).toBe("");
    expect(render(<UpdateBanner />, checkFor("2026.0.1", { snoozed: true }))).toBe("");
    expect(render(<UpdateBanner />, INACTIVE_UPDATE_CHECK)).toBe("");
    expect(render(<UpdateBanner />, checkFor("2026.0.0"))).toBe("");
  });
});

describe("UpdateRequiredScreen", () => {
  it("blocks with a download button; no connect button", () => {
    const html = render(<UpdateRequiredScreen bridge={bridge} status={DISCONNECTED} currentVersion="2026.0.0" />, checkFor("2026.0.0"));
    expect(html).toContain("Update erforderlich");
    expect(html).toContain("Herunterladen");
    expect(html).toContain("2026.0.0");
    expect(html).toContain("2026.0.1");
    expect(html).toContain("2026.1.0");
    expect(html).toContain("Erneut prüfen");
    expect(html).not.toContain("Verbindung trennen");
    expect(html).not.toContain("Verbinden<");
  });

  it("lets a running tunnel be disconnected", () => {
    const html = render(<UpdateRequiredScreen bridge={bridge} status={CONNECTED} currentVersion="2026.0.0" />, checkFor("2026.0.0"));
    expect(html).toContain("Verbindung trennen");
    expect(html).toContain("bleibt aktiv, bis du sie trennst");
    const en = render(<UpdateRequiredScreen bridge={bridge} status={CONNECTED} currentVersion="2026.0.0" />, checkFor("2026.0.0"), "en");
    expect(en).toContain("Update required");
    expect(en).toContain("Disconnect");
  });

  it("renders nothing unless the update is required", () => {
    expect(render(<UpdateRequiredScreen bridge={bridge} status={DISCONNECTED} currentVersion="2026.0.1" />, checkFor("2026.0.1"))).toBe("");
  });
});

describe("VersionLine (settings)", () => {
  it("Version 2026.0.1 · Nach Updates suchen", () => {
    const html = render(<VersionLine version="2026.0.1" />, checkFor("2026.0.1"));
    expect(html).toContain("Version 2026.0.1");
    expect(html).toContain("Nach Updates suchen");
    expect(render(<VersionLine version="2026.0.1" />, checkFor("2026.0.1"), "en")).toContain("Check for updates");
  });

  it("reports the outcome of a manual check", () => {
    expect(render(<VersionLine version="2026.1.0" />, checkFor("2026.1.0", { manual: "current" }))).toContain("Mantel ist aktuell.");
    expect(render(<VersionLine version="2026.0.1" />, checkFor("2026.0.1", { manual: "available" }))).toContain(
      "Version 2026.1.0 ist verfügbar.",
    );
    expect(render(<VersionLine version="2026.0.1" />, checkFor("2026.0.1", { manual: "failed" }))).toContain(
      "Gerade keine Verbindung zum Update-Server.",
    );
    expect(render(<VersionLine version="2026.0.1" />, checkFor("2026.0.1", { manual: "checking" }))).toContain("Suche nach Updates");
  });

  it("without a bridge that can check, only the version", () => {
    const html = render(<VersionLine version="2026.0.1" />, INACTIVE_UPDATE_CHECK);
    expect(html).toContain("Version 2026.0.1");
    expect(html).not.toContain("Nach Updates suchen");
  });
});
