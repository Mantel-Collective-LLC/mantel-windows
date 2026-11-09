import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Flag, hasFlag } from "../shared/ui/src/ui/flag";

const WEBSITE_FLAGS = [
  "DE", "AT", "NL", "LU", "HU", "BG", "EE", "LT", "LV", "RS", "AM", "PL", "UA", "ID", "MC", "ES", "TH", "CO", "FR",
  "IT", "BE", "IE", "RO", "MD", "NG", "MX", "PE", "SE", "FI", "DK", "NO", "IS", "JP", "BD", "CH", "HK", "SG", "TR",
  "CZ", "PT", "CA", "US", "GB", "AU", "BR", "KR", "IN", "IL", "AE", "ZA", "NZ", "TW", "GR",
];

describe("Flag", () => {
  it("draws every country the website draws", () => {
    expect(WEBSITE_FLAGS.filter((code) => !hasFlag(code))).toEqual([]);
  });

  it("draws Hong Kong as an SVG, not as the ISO fallback", () => {
    const html = renderToStaticMarkup(<Flag code="hk" />);
    expect(html).toContain("<svg");
    expect(html).not.toContain(">HK<");
  });

  it("falls back to the ISO code for unknown countries", () => {
    const html = renderToStaticMarkup(<Flag code="xx" />);
    expect(html).not.toContain("<svg");
    expect(html).toContain(">XX<");
  });
});
