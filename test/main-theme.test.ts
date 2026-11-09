import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IPC } from "../shared/core/contract";
import { API_BASE_URL } from "../src/main/flavor";
import { THEME_CANVAS, THEME_INK, type ThemePreference } from "../shared/core/theme";
import {
  systemThemeFrom,
  ThemeController,
  TITLE_BAR_HEIGHT,
  windowChrome,
  type NativeThemeLike,
  type ThemedWindow,
} from "../src/main/theme";

vi.mock("electron", () => ({ safeStorage: { isEncryptionAvailable: () => false } }));
const { DEFAULT_PREFERENCES, preferencesSchema, Store } = await import("../src/main/store");

function fakeNativeTheme(dark = false) {
  const listeners = new Set<() => void>();
  const native: NativeThemeLike & { setDark(next: boolean): void; listeners: Set<() => void> } = {
    themeSource: "light",
    shouldUseDarkColors: dark,
    on: (_event, listener) => listeners.add(listener),
    removeListener: (_event, listener) => listeners.delete(listener),
    listeners,
    setDark(next) {
      (this as { shouldUseDarkColors: boolean }).shouldUseDarkColors = next;
      listeners.forEach((listener) => listener());
    },
  };
  return native;
}

function fakeWindow() {
  const calls: Array<{ background?: string; overlay?: { color: string; symbolColor: string; height: number } }> = [];
  const window: ThemedWindow & { calls: typeof calls; destroyed: boolean } = {
    calls,
    destroyed: false,
    isDestroyed() {
      return this.destroyed;
    },
    setBackgroundColor: (color) => calls.push({ background: color }),
    setTitleBarOverlay: (overlay) => calls.push({ overlay }),
  };
  return window;
}

describe("window chrome per theme", () => {
  it("uses the canvas colour for background and title bar and ink for the window buttons", () => {
    expect(windowChrome("dark")).toEqual({
      backgroundColor: THEME_CANVAS.dark,
      titleBarOverlay: { color: THEME_CANVAS.dark, symbolColor: THEME_INK.dark, height: TITLE_BAR_HEIGHT },
    });
    expect(windowChrome("light").backgroundColor).toBe(THEME_CANVAS.light);
    expect(windowChrome("light").titleBarOverlay.symbolColor).toBe(THEME_INK.light);
  });

  it("reads the OS appearance from nativeTheme", () => {
    expect(systemThemeFrom({ shouldUseDarkColors: true })).toBe("dark");
    expect(systemThemeFrom({ shouldUseDarkColors: false })).toBe("light");
  });
});

describe("ThemeController (main process)", () => {
  it("keeps nativeTheme on 'system' so prefers-color-scheme in the renderer stays the real OS appearance", () => {
    const native = fakeNativeTheme();
    let preference: ThemePreference = "dark";
    const controller = new ThemeController(native, () => preference);
    expect(native.themeSource).toBe("system");
    preference = "light";
    controller.apply();
    expect(native.themeSource).toBe("system");
  });

  it("resolves the explicit choice first and 'system' / a missing value from the OS", () => {
    const native = fakeNativeTheme(true);
    let preference: ThemePreference | undefined = "light";
    const controller = new ThemeController(native, () => preference);
    expect(controller.theme()).toBe("light");
    preference = "system";
    expect(controller.theme()).toBe("dark");
    preference = undefined;
    expect(controller.theme()).toBe("dark");
    expect(controller.chrome()).toEqual(windowChrome("dark"));
  });

  it("recolours the attached window on a preference change and when the OS appearance changes", () => {
    const native = fakeNativeTheme(false);
    let preference: ThemePreference = "system";
    const reported: string[] = [];
    const controller = new ThemeController(native, () => preference, (theme) => reported.push(theme));
    const window = fakeWindow();

    controller.attach(window);
    expect(window.calls).toEqual([
      { background: THEME_CANVAS.light },
      { overlay: windowChrome("light").titleBarOverlay },
    ]);

    window.calls.length = 0;
    preference = "dark";
    controller.apply();
    expect(window.calls[0]).toEqual({ background: THEME_CANVAS.dark });

    window.calls.length = 0;
    native.setDark(true);
    expect(reported).toEqual(["dark"]);
    expect(window.calls[0]).toEqual({ background: THEME_CANVAS.dark });

    window.calls.length = 0;
    preference = "system";
    native.setDark(false);
    expect(reported).toEqual(["dark", "light"]);
    expect(window.calls[0]).toEqual({ background: THEME_CANVAS.light });
  });

  it("ignores destroyed or detached windows and never throws over the title bar", () => {
    const native = fakeNativeTheme(true);
    const controller = new ThemeController(native, () => "system");
    const window = fakeWindow();
    window.setTitleBarOverlay = () => {
      throw new Error("Titlebar overlay is not enabled");
    };
    expect(() => controller.attach(window)).not.toThrow();
    expect(window.calls).toEqual([{ background: THEME_CANVAS.dark }]);

    window.destroyed = true;
    window.calls.length = 0;
    controller.apply();
    expect(window.calls).toEqual([]);

    controller.attach(null);
    expect(() => controller.apply()).not.toThrow();
  });

  it("unsubscribes from nativeTheme on dispose", () => {
    const native = fakeNativeTheme();
    const controller = new ThemeController(native, () => "system");
    expect(native.listeners.size).toBe(1);
    controller.dispose();
    expect(native.listeners.size).toBe(0);
  });

  it("has its own IPC channels", () => {
    expect(IPC.setTheme).toBe("mantel:set-theme");
    expect(IPC.systemThemeEvent).toBe("mantel:system-theme-event");
    expect(new Set(Object.values(IPC)).size).toBe(Object.values(IPC).length);
  });
});

describe("preferences store: theme", () => {
  let directory: string;
  beforeEach(() => {
    directory = mkdtempSync(path.join(os.tmpdir(), "mantel-store-"));
  });
  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  const file = () => path.join(directory, "preferences.json");
  const legacy = { baseUrl: API_BASE_URL, alwaysOnKillSwitch: true, lastNodeId: "de-fra", language: "en" };

  it("defaults to 'system'", () => {
    expect(DEFAULT_PREFERENCES.theme).toBe("system");
    const store = new Store(directory);
    store.load();
    expect(store.getPreferences().theme).toBe("system");
  });

  it("reads files written before the setting existed without losing the other preferences", () => {
    writeFileSync(file(), JSON.stringify(legacy));
    const store = new Store(directory);
    store.load();
    expect(store.getPreferences()).toEqual({ ...legacy, theme: "system", postQuantum: false, autoConnectOpenWifi: false, connectOnLaunch: false, quitAction: "ask", obfuscation: "auto" });
  });

  it("falls back to 'system' for an unknown value instead of resetting everything", () => {
    writeFileSync(file(), JSON.stringify({ ...legacy, theme: "sepia" }));
    const store = new Store(directory);
    store.load();
    expect(store.getPreferences()).toEqual({ ...legacy, theme: "system", postQuantum: false, autoConnectOpenWifi: false, connectOnLaunch: false, quitAction: "ask", obfuscation: "auto" });
    expect(preferencesSchema.parse({ ...legacy, theme: 42 }).theme).toBe("system");
  });

  it("stores and reloads an explicit choice", () => {
    const store = new Store(directory);
    store.load();
    store.setPreferences({ ...store.getPreferences(), theme: "dark" });
    expect(JSON.parse(readFileSync(file(), "utf8")).theme).toBe("dark");
    const reloaded = new Store(directory);
    reloaded.load();
    expect(reloaded.getPreferences().theme).toBe("dark");
  });

  it("goes back to 'system' on the debug reset", () => {
    const store = new Store(directory);
    store.load();
    store.setPreferences({ ...store.getPreferences(), theme: "light" });
    store.resetLocalData();
    expect(store.getPreferences().theme).toBe("system");
  });
});
