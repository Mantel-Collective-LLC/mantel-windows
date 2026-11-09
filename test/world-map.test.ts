import { geoEqualEarth } from "d3-geo";
import { describe, expect, it } from "vitest";
import { approximateHome, locationCoordinates } from "../shared/ui/src/lib/geo";
import {
  arcPath,
  focusCamera,
  landBounds,
  project,
  thinDots,
  worldCamera,
  worldDots,
} from "../shared/ui/src/ui/map/projection";
import { WORLD } from "../shared/ui/src/ui/map/world-dots";

describe("world map projection", () => {
  it("matches d3-geo's Equal Earth with the generated scale and offset", () => {
    const reference = geoEqualEarth().scale(WORLD.scale).translate([WORLD.translateX, WORLD.translateY]);
    for (const [lon, lat] of [[0, 0], [8.68, 50.11], [114.17, 22.32], [-74.01, 40.71], [151.21, -33.87], [-21.94, 64.15]] as const) {
      const ours = project({ lat, lon });
      const theirs = reference([lon, lat]);
      expect(theirs).not.toBeNull();
      expect(ours.x).toBeCloseTo(theirs![0], 6);
      expect(ours.y).toBeCloseTo(theirs![1], 6);
    }
  });

  it("decodes the land dots inside the map, and thins them out by stride", () => {
    const dots = worldDots();
    expect(dots.length).toBeGreaterThan(5000);
    for (const dot of dots) {
      expect(dot.x).toBeGreaterThan(0);
      expect(dot.x).toBeLessThan(WORLD.width);
      expect(dot.y).toBeGreaterThan(0);
      expect(dot.y).toBeLessThan(WORLD.height);
    }
    expect(thinDots(dots, 2).length).toBeLessThan(dots.length / 3);
    const frankfurt = project({ lat: 50.11, lon: 8.68 });
    expect(dots.some((dot) => Math.hypot(dot.x - frankfurt.x, dot.y - frankfurt.y) <= WORLD.step)).toBe(true);
  });

  it("keeps the camera's aspect ratio and puts focused points inside the view", () => {
    const bounds = landBounds(worldDots());
    for (const aspect of [0.8, 16 / 9, 2, 3]) {
      const world = worldCamera(bounds, aspect);
      expect(world.width / world.height).toBeCloseTo(aspect, 6);
      const points = [project({ lat: 50.11, lon: 8.68 }), project({ lat: 22.32, lon: 114.17 })];
      const view = focusCamera(bounds, points, aspect, 240);
      expect(view.width / view.height).toBeCloseTo(aspect, 6);
      for (const point of points) {
        expect(point.x).toBeGreaterThanOrEqual(view.x);
        expect(point.x).toBeLessThanOrEqual(view.x + view.width);
        expect(point.y).toBeGreaterThanOrEqual(view.y);
        expect(point.y).toBeLessThanOrEqual(view.y + view.height);
      }
    }
  });

  it("draws an arc between two points and nothing for the same point", () => {
    expect(arcPath({ x: 10, y: 10 }, { x: 200, y: 40 })).toMatch(/^M10 10Q[\d.-]+ [\d.-]+ 200 40$/);
    expect(arcPath({ x: 10, y: 10 }, { x: 10, y: 10 })).toBe("");
  });
});

describe("location coordinates (static table, no lookup service)", () => {
  it("finds cities in German and English spelling, else the country", () => {
    expect(locationCoordinates({ city: "Zürich", country: "CH" })).toEqual({ lat: 47.38, lon: 8.54 });
    expect(locationCoordinates({ city: "Hongkong", country: "HK" })).toEqual(locationCoordinates({ city: "Hong Kong", country: "HK" }));
    expect(locationCoordinates({ city: "Kowloon", country: "HK" })?.lat).toBeCloseTo(22.32, 1);
    expect(locationCoordinates({ city: "Lokaler PQ-Testnode", country: "DE" })).toEqual({ lat: 50.11, lon: 8.68 });
    expect(locationCoordinates({ city: "Nowhere", country: "ZZ" })).toBeNull();
  });

  it("estimates 'you' only from the time zone or the locale region", () => {
    expect(approximateHome("Europe/Berlin", "de-DE")).toEqual({ lat: 52.52, lon: 13.4 });
    expect(approximateHome("Asia/Hong_Kong", undefined)?.lon).toBeCloseTo(114.17, 1);
    expect(approximateHome("Etc/UTC", "de-AT")).toEqual({ lat: 48.21, lon: 16.37 });
    expect(approximateHome(undefined, "en")).toBeNull();
  });
});
