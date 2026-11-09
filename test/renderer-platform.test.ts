import { describe, expect, it } from "vitest";
import type { InstalledApp } from "../shared/core/contract";
import { createTranslator } from "../shared/core/i18n";
import { excludedSummary, filterApps, indexApps, toggleExcluded } from "../shared/ui/src/lib/apps";
import { resolveBack } from "../shared/ui/src/lib/navigation";

const APPS: InstalledApp[] = [
  { label: "Firefox", packageName: "org.mozilla.firefox", system: false, icon: null },
  { label: "Einstellungen", packageName: "com.android.settings", system: true, icon: null },
  { label: "Signal", packageName: "org.thoughtcrime.securesms", system: false, icon: null },
];

describe("hardware back (Android)", () => {
  it("closes the sub-screen first, then leaves settings, otherwise lets the shell handle it", () => {
    expect(resolveBack({ subScreen: true, tab: "settings" })).toBe("close-sub-screen");
    expect(resolveBack({ subScreen: false, tab: "settings" })).toBe("show-connect");
    expect(resolveBack({ subScreen: false, tab: "locations" })).toBe("show-connect");
    expect(resolveBack({ subScreen: false, tab: "connect" })).toBeNull();
  });
});

describe("app exclusion list", () => {
  const indexed = indexApps(APPS);

  it("hides system apps unless requested", () => {
    expect(filterApps(indexed, "", false).map((app) => app.label)).toEqual(["Firefox", "Signal"]);
    expect(filterApps(indexed, "", true)).toHaveLength(3);
  });

  it("searches label and package name, case-insensitive", () => {
    expect(filterApps(indexed, "  FIRE ", false).map((app) => app.label)).toEqual(["Firefox"]);
    expect(filterApps(indexed, "thoughtcrime", false).map((app) => app.label)).toEqual(["Signal"]);
    expect(filterApps(indexed, "settings", false)).toEqual([]);
    expect(filterApps(indexed, "settings", true).map((app) => app.label)).toEqual(["Einstellungen"]);
  });

  it("toggles without duplicates", () => {
    expect(toggleExcluded([], "b", true)).toEqual(["b"]);
    expect(toggleExcluded(["b"], "a", true)).toEqual(["a", "b"]);
    expect(toggleExcluded(["a", "b"], "a", true)).toEqual(["a", "b"]);
    expect(toggleExcluded(["a", "b"], "a", false)).toEqual(["b"]);
  });

  it("summarises the count in German", () => {
    const de = createTranslator("de");
    expect(excludedSummary(0, de)).toBe("Alle Apps nutzen den Tunnel");
    expect(excludedSummary(1, de)).toBe("1 App nutzt den Tunnel nicht");
    expect(excludedSummary(3, de)).toBe("3 Apps nutzen den Tunnel nicht");
  });

  it("summarises the count in English", () => {
    const en = createTranslator("en");
    expect(excludedSummary(0, en)).toBe("All apps use the tunnel");
    expect(excludedSummary(1, en)).toBe("1 app does not use the tunnel");
    expect(excludedSummary(3, en)).toBe("3 apps do not use the tunnel");
  });
});
