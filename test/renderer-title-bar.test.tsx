import { describe, expect, it } from "vitest";
import type { Environment } from "../shared/core/contract";
import { ANDROID_FEATURES, DESKTOP_FEATURES, showsDesktopTitleBar, withFeatures } from "../shared/ui/src/lib/platform";

function environment(platform: string, features?: Environment["features"]): Pick<Environment, "platform" | "features"> {
  return { platform, features: features as Environment["features"] };
}

describe("desktop title bar (window controls area)", () => {
  it("is shown on Windows", () => {
    expect(showsDesktopTitleBar(environment("win32", DESKTOP_FEATURES), "desktop")).toBe(true);
  });

  it("is never shown on Android", () => {
    expect(showsDesktopTitleBar(environment("android", ANDROID_FEATURES), "android")).toBe(false);
    const legacy = withFeatures({ platform: "android" } as Environment);
    expect(legacy.features.desktopWindow).toBe(true);
    expect(showsDesktopTitleBar(legacy, "android")).toBe(false);
    expect(showsDesktopTitleBar(environment("win32", DESKTOP_FEATURES), "android")).toBe(false);
    expect(showsDesktopTitleBar(null, "android")).toBe(false);
  });

  it("follows the guess before the environment is known", () => {
    expect(showsDesktopTitleBar(null, "desktop")).toBe(true);
  });
});
