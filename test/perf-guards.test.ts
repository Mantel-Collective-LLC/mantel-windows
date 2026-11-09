import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = path.join(__dirname, "../shared/ui/src");
function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const file = path.join(dir, name);
    if (statSync(file).isDirectory()) return name === "dev" ? [] : sources(file);
    return /\.(tsx?|css)$/.test(name) ? [file] : [];
  });
}
const read = (relative: string) => readFileSync(path.join(root, relative), "utf8");

describe("renderer performance guards", () => {
  it("uses no backdrop blur (re-blurred on every scroll frame on phones)", () => {
    for (const file of sources(root)) expect(readFileSync(file, "utf8"), file).not.toMatch(/backdrop-blur|backdrop-filter/);
  });

  it("has no `transition: all`", () => {
    for (const file of sources(root)) expect(readFileSync(file, "utf8"), file).not.toMatch(/transition-all\b|transition:\s*all/);
  });

  it("re-rendered-every-tick parts have no layout animations (they measure the DOM on each render)", () => {
    for (const file of ["ui/app-nav.tsx", "screens/home.tsx", "ui/map/world-map.tsx"]) {
      expect(read(file), file).not.toMatch(/\blayoutId=|\blayout\n|\slayout\s/);
    }
    expect(read("ui/primitives.tsx")).toMatch(/translate-x-\[18px\]/);
  });

  it("draws the map's dot grid on a canvas and keeps the map out of status-tick re-renders", () => {
    const map = read("ui/map/world-map.tsx");
    expect(map).toContain("<canvas");
    expect(map).toContain("export const WorldMap = memo(");
    expect(map).not.toMatch(/<path\s+d=\{stridePath/);
  });

  it("keeps the tabs mounted and switches them with a CSS fade", () => {
    const app = read("app.tsx");
    expect(app).toMatch(/<Activity mode=/);
    expect(app).toContain("useDeferredValue(tab)");
    expect(read("styles.css")).toMatch(/@keyframes view-in/);
  });
});
