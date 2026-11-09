import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { MantelBridge, Preferences, TunnelStatus, VpnNode } from "../shared/core/contract";
import de from "../shared/core/i18n/de.json";
import en from "../shared/core/i18n/en.json";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { ConnectCard } from "../shared/ui/src/screens/home";
import { LocationButton } from "../shared/ui/src/ui/location-picker";
import { PqErrorActions, pqErrorOf } from "../shared/ui/src/ui/pq-error-actions";
import { PqSettingRow } from "../shared/ui/src/ui/pq-setting-row";
import { NoQuantumHint, QuantumBadge, QuantumRequired } from "../shared/ui/src/ui/quantum-badge";

function render(language: Language, node: React.ReactNode): string {
  return renderToStaticMarkup(<I18nProvider translator={createTranslator(language)}>{node}</I18nProvider>);
}

const STATUS: TunnelStatus = {
  phase: "connected",
  nodeId: "de-fra",
  connectedAt: 1,
  lastHandshakeAt: 1,
  rxBytes: 0,
  txBytes: 0,
  endpoint: "198.51.100.7:51820",
  addresses: ["10.8.0.2/32"],
  dns: ["10.8.0.1"],
  leakProtection: "wireguard",
  firewallActive: false,
  serviceState: "RUNNING",
  error: null,
  checkedAt: 0,
};

const NODES: VpnNode[] = [
  { id: "de-fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true, postQuantum: true },
  { id: "at-vie", city: "Wien", country: "AT", endpointHost: "198.51.100.8", endpointPort: 51820, online: true },
];

const PREFERENCES: Preferences = { baseUrl: "https://api.example", alwaysOnKillSwitch: false, lastNodeId: null, postQuantum: false };

describe("quantum badge", () => {
  it("shows „Quantengeschützt“ with the tooltip only when active", () => {
    const active = render("de", <QuantumBadge quantum="active" />);
    expect(active).toContain("Quantengeschützt");
    expect(active).toContain("Dieser Tunnel nutzt zusätzlich einen mit ML-KEM-768 vereinbarten Schlüssel.");
    expect(render("en", <QuantumBadge quantum="active" />)).toContain("Quantum-protected");
    expect(render("de", <QuantumBadge quantum="negotiating" />)).toContain("Quantenschutz wird ausgehandelt");
    expect(render("de", <QuantumBadge quantum="off" />)).toBe("");
    expect(render("de", <QuantumBadge quantum={undefined} />)).toBe("");
  });

  it("is part of the connection card", () => {
    const card = (quantum: TunnelStatus["quantum"]) =>
      render("de", <ConnectCard status={{ ...STATUS, quantum }} node={NODES[0]!} busy={false} canConnect error={null} protection={{ android: false, systemLockdown: null }} onToggle={() => undefined} />);
    expect(card("active")).toContain("Quantengeschützt");
    expect(card("off")).not.toContain("Quantengeschützt");
    expect(card(undefined)).not.toContain("Quanten");
  });
});

describe("location hint", () => {
  it("marks locations without PQ only when the setting is on (context from app.tsx)", () => {
    const button = (required: boolean, node: VpnNode) =>
      render(
        "de",
        <QuantumRequired.Provider value={required}>
          <LocationButton node={node} nodes={NODES} loading={false} onOpen={() => undefined} />
        </QuantumRequired.Provider>,
      );
    expect(button(true, NODES[1]!)).toContain("ohne Quantenschutz");
    expect(button(true, NODES[0]!)).not.toContain("ohne Quantenschutz");
    expect(button(false, NODES[1]!)).not.toContain("ohne Quantenschutz");
    expect(render("en", <NoQuantumHint node={NODES[1]!} required />)).toContain("without quantum protection");
    expect(render("en", <NoQuantumHint node={NODES[0]!} required />)).toBe("");
    expect(render("en", <NoQuantumHint node={NODES[1]!} />)).toBe("");
  });
});

describe("settings row", () => {
  const bridge = { setPostQuantum: async () => ({ ok: true, value: PREFERENCES }) } as unknown as MantelBridge;

  it("shows the switch with the allowed wording, off by default", () => {
    const html = render("de", <PqSettingRow bridge={bridge} preferences={PREFERENCES} onPreferences={() => undefined} />);
    expect(html).toContain("Quantenresistenter Tunnel");
    expect(html).toContain(de.pq.settingDescription);
    expect(html).toContain("Beta");
    expect(html).toContain('aria-checked="false"');
    expect(html).not.toContain(de.pq.lockdownHint);
    const on = render("de", <PqSettingRow bridge={bridge} preferences={{ ...PREFERENCES, postQuantum: true }} onPreferences={() => undefined} lockdownHint />);
    expect(on).toContain('aria-checked="true"');
    expect(on).toContain("Verbindungen ohne VPN blockieren");
  });

  it("is hidden when the bridge cannot store the setting", () => {
    expect(render("de", <PqSettingRow bridge={{} as MantelBridge} preferences={PREFERENCES} onPreferences={() => undefined} />)).toBe("");
  });
});

describe("error actions (fail closed, one tap out)", () => {
  const bridge = { setPostQuantum: async () => ({ ok: true, value: PREFERENCES }) } as unknown as MantelBridge;
  const actions = (error: Parameters<typeof PqErrorActions>[0]["error"], postQuantum = true, language: Language = "de") =>
    render(
      language,
      <PqErrorActions
        error={error}
        bridge={bridge}
        preferences={{ ...PREFERENCES, postQuantum }}
        onPreferences={() => undefined}
        onPickLocation={() => undefined}
        onConnect={async () => undefined}
      />,
    );

  it("finds the PQ error from the result code or the pushed status message", () => {
    expect(pqErrorOf("pq_unsupported", null, de.errors)).toBe("pq_unsupported");
    expect(pqErrorOf(null, de.errors.pqFailed, de.errors)).toBe("pq_failed");
    expect(pqErrorOf(null, en.errors.pqNotActive, en.errors)).toBe("pq_not_active");
    expect(pqErrorOf("network", "Something else", de.errors)).toBeNull();
    expect(pqErrorOf(null, null, de.errors)).toBeNull();
  });

  it("offers another location for pq_unsupported and classic connect for every PQ error", () => {
    const unsupported = actions("pq_unsupported");
    expect(unsupported).toContain("Anderen Standort wählen");
    expect(unsupported).toContain("Ohne Quantenschutz verbinden");
    expect(unsupported).toContain('role="group"');
    const failed = actions("pq_failed");
    expect(failed).not.toContain("Anderen Standort wählen");
    expect(failed).toContain("Ohne Quantenschutz verbinden");
    expect(actions("pq_unsupported", true, "en")).toContain("Choose another location");
  });

  it("shows nothing without a PQ error, with the setting off or without bridge support", () => {
    expect(actions(null)).toBe("");
    expect(actions("pq_failed", false)).toBe("");
    expect(
      render("de", <PqErrorActions error="pq_failed" bridge={{} as MantelBridge} preferences={{ ...PREFERENCES, postQuantum: true }} onPreferences={() => undefined} onPickLocation={() => undefined} onConnect={async () => undefined} />),
    ).toBe("");
  });
});

describe("wording and tokens", () => {
  const texts = (dictionary: typeof de) => [...Object.values(dictionary.pq), dictionary.errors.pqUnsupported, dictionary.errors.pqFailed, dictionary.errors.pqMismatch, dictionary.errors.pqNotActive];

  it("never uses forbidden claims (1.3)", () => {
    const forbidden = /quantensicher|quantum-proof|quantum-safe|unknackbar|100\s?%|Post-Quanten-Verschlüsselung|post-quantum encryption|militär|military/i;
    for (const text of [...texts(de), ...texts(en as typeof de)]) expect(text).not.toMatch(forbidden);
  });

  it("keeps the spec texts verbatim", () => {
    expect(de.pq.settingDescription).toBe(
      "Zusätzlicher Schlüsselaustausch mit ML-KEM-768. Schützt aufgezeichneten Datenverkehr gegen spätere Entschlüsselung durch Quantencomputer. Der Verbindungsaufbau dauert etwas länger.",
    );
    expect(de.errors.pqUnsupported).toBe(
      "Dieser Standort unterstützt den quantenresistenten Tunnel noch nicht. Wähle einen anderen Standort oder schalte die Option in den Einstellungen aus.",
    );
    expect(de.errors.pqFailed).toBe("Der quantenresistente Schlüsselaustausch ist fehlgeschlagen. Es wurde keine Verbindung ohne Quantenschutz aufgebaut.");
    expect(en.pq.badge).toBe("Quantum-protected");
  });
});
