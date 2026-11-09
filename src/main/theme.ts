import { resolveTheme, THEME_CANVAS, THEME_INK, type Theme, type ThemePreference } from "../../shared/core/theme";

export const TITLE_BAR_HEIGHT = 40;

export type NativeThemeLike = {
  themeSource: "system" | "light" | "dark";
  readonly shouldUseDarkColors: boolean;
  on(event: "updated", listener: () => void): unknown;
  removeListener(event: "updated", listener: () => void): unknown;
};

export type ThemedWindow = {
  isDestroyed(): boolean;
  setBackgroundColor(color: string): void;
  setTitleBarOverlay(options: { color: string; symbolColor: string; height: number }): void;
};

export type WindowChrome = {
  backgroundColor: string;
  titleBarOverlay: { color: string; symbolColor: string; height: number };
};

export function windowChrome(theme: Theme): WindowChrome {
  return {
    backgroundColor: THEME_CANVAS[theme],
    titleBarOverlay: { color: THEME_CANVAS[theme], symbolColor: THEME_INK[theme], height: TITLE_BAR_HEIGHT },
  };
}

export function systemThemeFrom(native: Pick<NativeThemeLike, "shouldUseDarkColors">): Theme {
  return native.shouldUseDarkColors ? "dark" : "light";
}

export class ThemeController {
  private window: ThemedWindow | null = null;
  private readonly onUpdated = () => {
    this.apply();
    this.onSystemTheme?.(this.systemTheme());
  };

  constructor(
    private readonly native: NativeThemeLike,
    private readonly preference: () => ThemePreference | undefined,
    private readonly onSystemTheme?: (theme: Theme) => void,
  ) {
    this.native.themeSource = "system";
    this.native.on("updated", this.onUpdated);
  }

  systemTheme(): Theme {
    return systemThemeFrom(this.native);
  }

  theme(): Theme {
    return resolveTheme(this.preference(), this.systemTheme());
  }

  chrome(): WindowChrome {
    return windowChrome(this.theme());
  }

  attach(window: ThemedWindow | null): void {
    this.window = window;
    this.apply();
  }

  apply(): void {
    const window = this.window;
    if (!window || window.isDestroyed()) return;
    const chrome = this.chrome();
    try {
      window.setBackgroundColor(chrome.backgroundColor);
      window.setTitleBarOverlay(chrome.titleBarOverlay);
    } catch {
    }
  }

  dispose(): void {
    this.native.removeListener("updated", this.onUpdated);
    this.window = null;
  }
}
