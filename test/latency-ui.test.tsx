import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { VpnNode } from "../shared/core/contract";
import { createTranslator } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { Latency, LocationButton } from "../shared/ui/src/ui/location-picker";

const render = (node: React.ReactNode) =>
  renderToStaticMarkup(<I18nProvider translator={createTranslator("de")}>{node}</I18nProvider>);

const node = (latencyMs?: number): VpnNode => ({
  id: "nl-ams",
  city: "Amsterdam",
  country: "NL",
  endpointHost: "198.51.100.4",
  endpointPort: 51820,
  online: true,
  pingPort: 51821,
  latencyMs,
});

describe("speed rating in the picker", () => {
  it("measured: rating, bars and the hint that this device measured it", () => {
    const html = render(<Latency ms={18} />);
    expect(html).toContain("schnell");
    expect(html).toContain('title="gemessen von diesem Gerät"');
    expect(html).toContain('aria-label="Antwortzeit: schnell, gemessen von diesem Gerät"');
    expect(render(<Latency ms={70} />)).toContain("mittel");
    expect(render(<Latency ms={250} />)).toContain("langsam");
  });

  it("unknown: nothing at all (no dash, no empty bars, no separator)", () => {
    expect(render(<Latency ms={undefined} />)).toBe("");
    const button = render(<LocationButton node={node()} nodes={[node()]} loading={false} onOpen={() => undefined} />);
    expect(button).not.toContain("—");
    expect(button).not.toContain("size-0.5");
    expect(button).not.toContain("Antwortzeit");
    const measured = render(<LocationButton node={node(30)} nodes={[node(30)]} loading={false} onOpen={() => undefined} />);
    expect(measured).toContain("size-0.5");
    expect(measured).toContain("schnell");
  });
});
