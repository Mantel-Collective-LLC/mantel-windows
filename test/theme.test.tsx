import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_THEME_PREFERENCE,
  isTheme,
  isThemePreference,
  parseThemePreference,
  resolveTheme,
  THEME_CANVAS,
  THEME_PREFERENCES,
} from "../shared/core/theme";
import {
  applyTheme,
  effectiveThemePreference,
  readStoredTheme,
  storeTheme,
  systemThemeOf,
  THEME_STORAGE_KEY,
  watchSystemTheme,
  type ColorSchemeQuery,
  type ThemeStorage,
  type ThemeTarget,
} from "../shared/ui/src/lib/theme";
import type { Theme } from "../shared/core/contract";

function memoryStorage(initial: Record<string, string> = {}): ThemeStorage & { data: Map<string, string> } {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => void data.set(key, value),
    removeItem: (key) => void data.delete(key),
  };
}

const brokenStorage: ThemeStorage = {
  getItem: () => {
    throw new Error("SecurityError");
  },
  setItem: () => {
    throw new Error("QuotaExceededError");
  },
  removeItem: () => {
    throw new Error("SecurityError");
  },
};

function fakeQuery(dark: boolean): ColorSchemeQuery & { flip(next: boolean): void; listeners: number } {
  const listeners = new Set<(event: { matches: boolean }) => void>();
  const query = {
    matches: dark,
    get listeners() {
      return listeners.size;
    },
    addEventListener: (_type: "change", listener: (event: { matches: boolean }) => void) => void listeners.add(listener),
    removeEventListener: (_type: "change", listener: (event: { matches: boolean }) => void) => void listeners.delete(listener),
    flip(next: boolean) {
      query.matches = next;
      listeners.forEach((listener) => listener({ matches: next }));
    },
  };
  return query;
}

function fakeTarget(): ThemeTarget & { meta: Record<string, string> } {
  const meta: Record<string, string> = {};
  return {
    meta,
    documentElement: { dataset: {}, style: { colorScheme: "" } },
    querySelector: (selector) =>
      selector === 'meta[name="theme-color"]' ? { setAttribute: (name, value) => void (meta[name] = value) } : null,
  };
}

describe("theme preference (shared)", () => {
  it("offers System, Light and Dark with System as the default", () => {
    expect(THEME_PREFERENCES).toEqual(["system", "light", "dark"]);
    expect(DEFAULT_THEME_PREFERENCE).toBe("system");
  });

  it("validates values", () => {
    expect(isTheme("dark")).toBe(true);
    expect(isTheme("system")).toBe(false);
    expect(isThemePreference("system")).toBe(true);
    expect(isThemePreference("sepia")).toBe(false);
    expect(parseThemePreference("light")).toBe("light");
    expect(parseThemePreference(undefined)).toBe("system");
    expect(parseThemePreference(42)).toBe("system");
  });

  it("lets an explicit choice win and follows the OS for System", () => {
    expect(resolveTheme("light", "dark")).toBe("light");
    expect(resolveTheme("dark", "light")).toBe("dark");
    expect(resolveTheme("system", "dark")).toBe("dark");
    expect(resolveTheme("system", "light")).toBe("light");
    expect(resolveTheme(undefined, "dark")).toBe("dark");
    expect(resolveTheme(null, "light")).toBe("light");
  });
});

describe("theme persistence (renderer)", () => {
  it("round-trips the choice and removes the entry for System", () => {
    const storage = memoryStorage();
    expect(readStoredTheme(storage)).toBe("system");
    storeTheme("dark", storage);
    expect(storage.data.get(THEME_STORAGE_KEY)).toBe("dark");
    expect(readStoredTheme(storage)).toBe("dark");
    storeTheme("system", storage);
    expect(storage.data.has(THEME_STORAGE_KEY)).toBe(false);
    expect(readStoredTheme(storage)).toBe("system");
  });

  it("treats corrupt or unreadable storage as System and never throws", () => {
    expect(readStoredTheme(memoryStorage({ [THEME_STORAGE_KEY]: "neon" }))).toBe("system");
    expect(readStoredTheme(brokenStorage)).toBe("system");
    expect(readStoredTheme(null)).toBe("system");
    expect(() => storeTheme("dark", brokenStorage)).not.toThrow();
    expect(() => storeTheme("dark", null)).not.toThrow();
  });

  it("prefers the bridge's preference over the local copy", () => {
    vi.stubGlobal("localStorage", memoryStorage({ [THEME_STORAGE_KEY]: "dark" }));
    try {
      expect(effectiveThemePreference({ theme: "light" })).toBe("light");
      expect(effectiveThemePreference({ theme: "system" })).toBe("system");
      expect(effectiveThemePreference({})).toBe("dark");
      expect(effectiveThemePreference(null)).toBe("dark");
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("theme application (renderer)", () => {
  it("reads the OS appearance from prefers-color-scheme", () => {
    expect(systemThemeOf(fakeQuery(true))).toBe("dark");
    expect(systemThemeOf(fakeQuery(false))).toBe("light");
    expect(systemThemeOf(null)).toBe("light");
  });

  it("sets data-theme and the browser theme colour", () => {
    const target = fakeTarget();
    applyTheme("dark", target);
    expect(target.documentElement.dataset.theme).toBe("dark");
    expect(target.documentElement.style.colorScheme).toBe("dark");
    expect(target.meta.content).toBe(THEME_CANVAS.dark);
    applyTheme("light", target);
    expect(target.documentElement.dataset.theme).toBe("light");
    expect(target.meta.content).toBe(THEME_CANVAS.light);
  });

  it("follows OS changes live and stops on unsubscribe", () => {
    const query = fakeQuery(false);
    const seen: Theme[] = [];
    const stop = watchSystemTheme((theme) => seen.push(theme), { query, native: undefined });
    query.flip(true);
    query.flip(false);
    expect(seen).toEqual(["dark", "light"]);
    stop();
    expect(query.listeners).toBe(0);
    query.flip(true);
    expect(seen).toEqual(["dark", "light"]);
  });

  it("also takes the native report (Android night mode) and ignores junk", () => {
    let emit: ((theme: Theme) => void) | null = null;
    const unsubscribe = vi.fn();
    const native = vi.fn((listener: (theme: Theme) => void) => {
      emit = listener;
      return unsubscribe;
    });
    const seen: Theme[] = [];
    const stop = watchSystemTheme((theme) => seen.push(theme), { query: null, native });
    emit!("dark");
    emit!("sepia" as Theme);
    emit!("light");
    expect(seen).toEqual(["dark", "light"]);
    stop();
    expect(unsubscribe).toHaveBeenCalledOnce();
  });

  it("survives a native subscription that throws", () => {
    const query = fakeQuery(false);
    const seen: Theme[] = [];
    const stop = watchSystemTheme((theme) => seen.push(theme), {
      query,
      native: () => {
        throw new Error("plugin missing");
      },
    });
    query.flip(true);
    expect(seen).toEqual(["dark"]);
    expect(stop).not.toThrow();
  });
});
