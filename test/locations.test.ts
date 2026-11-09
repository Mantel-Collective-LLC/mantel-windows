import { describe, expect, it } from "vitest";
import type { VpnNode } from "../shared/core/contract";
import {
  availabilityOf,
  countryName,
  favoriteNodes,
  fold,
  groupLocations,
  isSelectable,
  latencyQuality,
  matchesQuery,
  MAX_FAVORITES,
  nextRow,
  parseFavorites,
  pickerRows,
  signalLevel,
  toggleFavorite,
} from "../shared/ui/src/lib/locations";

const node = (id: string, city: string, country: string, extra: Partial<VpnNode> = {}): VpnNode => ({
  id,
  city,
  country,
  endpointHost: "198.51.100.1",
  endpointPort: 51820,
  online: true,
  latencyMs: 10,
  ...extra,
});

const NODES: VpnNode[] = [
  node("ch-zrh", "Zürich", "CH", { latencyMs: 11 }),
  node("de-fra", "Frankfurt", "DE", { latencyMs: 4 }),
  node("is-rkv", "Reykjavík", "IS", { online: false, latencyMs: undefined }),
  node("us-nyc", "New York", "US", { latencyMs: 87 }),
  node("de-ber", "Berlin", "DE", { latencyMs: 7 }),
  node("ch-gva", "Genf", "CH", { status: "full" }),
  node("at-vie", "Wien", "AT", { status: "paused" }),
  node("de-muc", "München", "DE", { status: "upgrading" }),
];

const ids = (nodes: readonly VpnNode[]) => nodes.map((entry) => entry.id);

describe("availability", () => {
  it("is available only when online and without a status; offline wins over a status", () => {
    expect(availabilityOf({ online: true })).toBe("available");
    expect(availabilityOf({ online: true, status: "full" })).toBe("full");
    expect(availabilityOf({ online: false, status: "paused" })).toBe("offline");
    expect(isSelectable({ online: true })).toBe(true);
    expect(isSelectable({ online: true, status: "upgrading" })).toBe(false);
    expect(isSelectable({ online: false })).toBe(false);
  });

  it("maps latency to signal bars", () => {
    expect([undefined, -1, Number.NaN, 0, 40, 41, 100, 101, 900].map(signalLevel)).toEqual([0, 0, 0, 3, 3, 2, 2, 1, 1]);
  });

  it("shows the API's latency band as a rating, never as milliseconds", async () => {
    expect([undefined, Number.NaN, 40, 100, 250].map(latencyQuality)).toEqual([null, null, "fast", "medium", "slow"]);
    const de = (await import("../shared/core/i18n/de.json")).default;
    const en = (await import("../shared/core/i18n/en.json")).default;
    for (const dictionary of [de, en]) {
      expect(JSON.stringify(dictionary.locations)).not.toMatch(/\{ms\}|millisec|Millisek/i);
      expect(Object.keys(dictionary.locations.latency).sort()).toEqual(["fast", "medium", "slow"]);
    }
  });
});

describe("search", () => {
  it("folds case, accents and ß", () => {
    expect(fold("  Zürich  ")).toBe("zurich");
    expect(fold("Reykjavík")).toBe("reykjavik");
    expect(fold("Gießen")).toBe("giessen");
  });

  it("matches word starts of city, country name, code and id, in either umlaut spelling", () => {
    const zurich = NODES[0]!;
    expect(matchesQuery(zurich, "Schweiz", "zur")).toBe(true);
    expect(matchesQuery(zurich, "Schweiz", "ZUERICH")).toBe(true);
    expect(matchesQuery(zurich, "Schweiz", "schw")).toBe(true);
    expect(matchesQuery(zurich, "Schweiz", "ch")).toBe(true);
    expect(matchesQuery(zurich, "Schweiz", "zrh")).toBe(true);
    expect(matchesQuery(zurich, "Schweiz", "rich")).toBe(false);
    expect(matchesQuery(NODES[3]!, "Vereinigte Staaten", "new y")).toBe(true);
    expect(matchesQuery(NODES[3]!, "Vereinigte Staaten", "york new")).toBe(true);
    expect(matchesQuery(NODES[3]!, "Vereinigte Staaten", "new z")).toBe(false);
    expect(matchesQuery(zurich, "Schweiz", "   ")).toBe(true);
  });
});

describe("grouping", () => {
  it("groups by country, sorted by the localized name, available cities first", () => {
    const groups = groupLocations(NODES, { locale: "de-DE" });
    expect(groups.map((group) => group.name)).toEqual(["Deutschland", "Island", "Österreich", "Schweiz", "Vereinigte Staaten"]);
    const germany = groups[0]!;
    expect(ids(germany.nodes)).toEqual(["de-ber", "de-fra", "de-muc"]);
    expect(germany.available).toBe(2);
    expect(ids(groups[3]!.nodes)).toEqual(["ch-zrh", "ch-gva"]);
    expect(groupLocations(NODES, { locale: "en-GB" }).map((group) => group.code)).toEqual(["AT", "DE", "IS", "CH", "US"]);
  });

  it("keeps a whole country when its name matches, otherwise only the matching cities", () => {
    expect(ids(groupLocations(NODES, { locale: "de-DE", query: "deutsch" }).flatMap((group) => group.nodes))).toEqual([
      "de-ber",
      "de-fra",
      "de-muc",
    ]);
    const muenchen = groupLocations(NODES, { locale: "de-DE", query: "muenchen" });
    expect(muenchen.map((group) => group.code)).toEqual(["DE"]);
    expect(ids(muenchen[0]!.nodes)).toEqual(["de-muc"]);
    expect(groupLocations(NODES, { locale: "en-GB", query: "switz" }).map((group) => group.code)).toEqual(["CH"]);
    expect(groupLocations(NODES, { locale: "en-GB", query: "deutschland" }).map((group) => group.code)).toEqual(["DE"]);
    expect(groupLocations(NODES, { locale: "de-DE", query: "germany" }).map((group) => group.code)).toEqual(["DE"]);
    expect(groupLocations(NODES, { locale: "de-DE", query: "atlantis" })).toEqual([]);
  });

  it("falls back to the code for countries Intl does not know", () => {
    expect(countryName("CH", "de-DE")).toBe("Schweiz");
    expect(countryName("XX", "de-DE")).toBe("XX");
  });
});

describe("favourites", () => {
  it("toggles, keeps the order they were added and caps the list", () => {
    expect(toggleFavorite([], "ch-zrh")).toEqual(["ch-zrh"]);
    expect(toggleFavorite(["ch-zrh", "de-fra"], "ch-zrh")).toEqual(["de-fra"]);
    const many = Array.from({ length: MAX_FAVORITES }, (_, index) => `n${index}`);
    const next = toggleFavorite(many, "new");
    expect(next).toHaveLength(MAX_FAVORITES);
    expect(next.at(-1)).toBe("new");
    expect(next[0]).toBe("n1");
  });

  it("parses stored favourites defensively", () => {
    expect(parseFavorites(null)).toEqual([]);
    expect(parseFavorites("{oops")).toEqual([]);
    expect(parseFavorites('{"a":1}')).toEqual([]);
    expect(parseFavorites('["ch-zrh", 7, "../etc", "ch-zrh", "de-fra"]')).toEqual(["ch-zrh", "de-fra"]);
  });

  it("lists favourites that still exist, filtered by the query", () => {
    const favorites = ["us-nyc", "gone", "ch-zrh"];
    expect(ids(favoriteNodes(NODES, favorites, { locale: "de-DE" }))).toEqual(["us-nyc", "ch-zrh"]);
    expect(ids(favoriteNodes(NODES, favorites, { locale: "de-DE", query: "schweiz" }))).toEqual(["ch-zrh"]);
  });
});

describe("keyboard rows", () => {
  it("lists favourites before the countries with distinct keys", () => {
    const groups = groupLocations(NODES, { locale: "de-DE", query: "zur" });
    const rows = pickerRows([NODES[0]!], groups);
    expect(rows.map((row) => row.key)).toEqual(["fav:ch-zrh", "CH:ch-zrh"]);
  });

  it("moves between the search field (-1) and the rows", () => {
    expect(nextRow(3, -1, 1)).toBe(0);
    expect(nextRow(3, 0, -1)).toBe(-1);
    expect(nextRow(3, -1, -1)).toBe(-1);
    expect(nextRow(3, 2, 1)).toBe(2);
    expect(nextRow(3, 1, "first")).toBe(0);
    expect(nextRow(3, 0, "last")).toBe(2);
    expect(nextRow(0, -1, 1)).toBe(-1);
  });
});
