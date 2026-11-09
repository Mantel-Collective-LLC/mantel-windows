import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

function contrast(a: string, b: string): number {
  const luminance = (hex: string) => {
    const [r, g, bl] = [1, 3, 5].map((index) => parseInt(hex.slice(index, index + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r! + 0.7152 * g! + 0.0722 * bl!;
  };
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (high! + 0.05) / (low! + 0.05);
}

describe("stop colour tokens", () => {
  const css = readFileSync(path.join(__dirname, "../shared/ui/src/styles.css"), "utf8");
  const token = (name: string) => new RegExp(`--color-${name}:\\s*(#[0-9a-f]{6});`).exec(css)?.[1];

  it("white text on the red meets WCAG AA (4.5:1) at rest, hover and pressed", () => {
    expect(token("on-stop")).toBe("#ffffff");
    for (const name of ["stop", "stop-hover", "stop-active"]) {
      const colour = token(name);
      expect(colour, name).toBeDefined();
      expect(contrast(colour!, "#ffffff"), name).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("is the same red in dark mode (not switched like the red ramp)", () => {
    const dark = css.slice(css.indexOf(':root[data-theme="dark"]'));
    expect(dark.slice(0, dark.indexOf("}"))).not.toMatch(/--color-(on-)?stop/);
  });
});
