import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { MantelBridge, Preferences, TunnelStatus } from "../shared/core/contract";
import { createTranslator, DICTIONARIES, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import type { BlockReason } from "../shared/ui/src/lib/protection";
import { ConnectCard } from "../shared/ui/src/screens/home";
import { KillSwitchBanner, liftBlock } from "../shared/ui/src/ui/tunnel-controls";

const PREFS: Preferences = { baseUrl: "https://example.test", alwaysOnKillSwitch: false, lastNodeId: null };

function bridge(overrides: Partial<MantelBridge> = {}): MantelBridge {
  return {
    disconnect: vi.fn(async () => ({ ok: true as const, value: {} as TunnelStatus })),
    setAlwaysOnKillSwitch: vi.fn(async () => ({ ok: true as const, value: { ...PREFS } })),
    ...overrides,
  } as unknown as MantelBridge;
}

function banner(language: Language, reason: BlockReason, options: { reconnect?: boolean; target?: MantelBridge } = {}): string {
  return renderToStaticMarkup(
    <I18nProvider translator={createTranslator(language)}>
      <KillSwitchBanner bridge={options.target ?? bridge()} reason={reason} onReconnect={options.reconnect ? async () => undefined : undefined} />
    </I18nProvider>,
  );
}

describe("KillSwitchBanner", () => {
  it.each(["de", "en"] as const)("%s: title, reason, sign-in page hint and both actions", (language) => {
    const home = DICTIONARIES[language].home;
    const html = banner(language, "alwaysOn", { reconnect: true });
    for (const text of [home.blockedTitle, home.blockedAlwaysOn, home.blockedCaptive, home.blockedReconnect, home.blockedLift]) {
      expect(html).toContain(text);
    }
    expect(html).toContain('role="alert"');
  });

  it("without a location only offers lifting; Android points to its own settings", () => {
    const html = banner("en", "leftover");
    expect(html).toContain(DICTIONARIES.en.home.blockedLeftover);
    expect(html).not.toContain(DICTIONARIES.en.home.blockedReconnect);
    const android = banner("en", "android", { target: bridge({ openSystemVpnSettings: async () => undefined }) });
    expect(android).toContain(DICTIONARIES.en.home.blockedAndroid);
    expect(android).toContain(DICTIONARIES.en.settings.openAndroidSettings);
    expect(android).not.toContain(DICTIONARIES.en.home.blockedCaptive);
  });

  it("lifting: disconnect for the tunnel's rules, switch off the permanent kill switch, Android settings", async () => {
    const target = bridge({ openSystemVpnSettings: vi.fn(async () => undefined) });
    const onPreferences = vi.fn();
    expect(await liftBlock(target, "lost")).toBeNull();
    expect(await liftBlock(target, "leftover")).toBeNull();
    expect(target.disconnect).toHaveBeenCalledTimes(2);
    expect(await liftBlock(target, "alwaysOn", onPreferences)).toBeNull();
    expect(target.setAlwaysOnKillSwitch).toHaveBeenCalledWith(false);
    expect(onPreferences).toHaveBeenCalledOnce();
    await liftBlock(target, "android");
    expect(target.openSystemVpnSettings).toHaveBeenCalledOnce();
    const failing = bridge({ disconnect: async () => ({ ok: false, error: "nope", code: "internal" }) });
    expect(await liftBlock(failing, "lost")).toBe("nope");
  });
});

describe("connect card", () => {
  const status = (phase: TunnelStatus["phase"]): TunnelStatus => ({
    phase,
    nodeId: "fra",
    connectedAt: null,
    lastHandshakeAt: null,
    rxBytes: 0,
    txBytes: 0,
    endpoint: null,
    addresses: [],
    dns: [],
    leakProtection: "none",
    firewallActive: true,
    serviceState: null,
    error: null,
    checkedAt: 0,
  });
  const card = (phase: TunnelStatus["phase"], blocked = false) =>
    renderToStaticMarkup(
      <I18nProvider translator={createTranslator("de")}>
        <ConnectCard
          status={status(phase)}
          node={null}
          busy={false}
          canConnect
          error={null}
          blocked={blocked}
          protection={{ android: false, systemLockdown: null }}
          onToggle={() => undefined}
        />
      </I18nProvider>,
    );

  it("offers 'Abbrechen' while connecting, so nobody has to wait out a hanging attempt", () => {
    expect(card("connecting")).toContain(`>${DICTIONARIES.de.home.cancelConnect}<`);
    expect(card("connected")).not.toContain(`>${DICTIONARIES.de.home.cancelConnect}<`);
  });

  it("leaves the explanation to the banner when it is shown", () => {
    expect(card("stale")).toContain(DICTIONARIES.de.home.staleWarning);
    expect(card("stale", true)).not.toContain(DICTIONARIES.de.home.staleWarning);
    expect(card("disconnected", true)).not.toContain(DICTIONARIES.de.home.noteFirewallLockdown);
  });
});
