import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { TunnelStatus, VpnNode } from "../shared/core/contract";
import de from "../shared/core/i18n/de.json";
import en from "../shared/core/i18n/en.json";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { ConnectCard } from "../shared/ui/src/screens/home";
import {
  INITIAL_REFRESH_STATE,
  REFRESH_NOTICE_AFTER,
  nextRefreshState,
  type RefreshOutcome,
  type RefreshState,
} from "../shared/ui/src/refresh-state";

const NETWORK: RefreshOutcome = { ok: false, code: "network", error: de.errors.apiUnreachable };
const NOTICE = { noticeText: de.app.refreshFailed };

function run(outcomes: RefreshOutcome[], hasData: boolean, start: RefreshState = INITIAL_REFRESH_STATE): RefreshState {
  return outcomes.reduce((state, outcome) => nextRefreshState(state, outcome, { hasData, ...NOTICE }), start);
}

describe("nextRefreshState", () => {
  it("stays quiet on single failures while account and locations are on screen", () => {
    for (let n = 1; n < REFRESH_NOTICE_AFTER; n += 1) {
      expect(run(Array(n).fill(NETWORK), true)).toEqual({ failures: n, message: null });
    }
  });

  it("shows only a neutral notice after repeated failures, never the red network error", () => {
    const state = run(Array(REFRESH_NOTICE_AFTER).fill(NETWORK), true);
    expect(state.message).toEqual({ tone: "notice", text: de.app.refreshFailed });
  });

  it("clears the counter and the notice on the next successful round", () => {
    const failed = run(Array(REFRESH_NOTICE_AFTER + 2).fill(NETWORK), true);
    expect(nextRefreshState(failed, { ok: true }, { hasData: true, ...NOTICE })).toEqual(INITIAL_REFRESH_STATE);
    expect(run([NETWORK, { ok: true }, NETWORK], true)).toEqual({ failures: 1, message: null });
  });

  it("shows the real error at once when there is no data yet (first load)", () => {
    expect(run([NETWORK], false)).toEqual({ failures: 1, message: { tone: "error", text: de.errors.apiUnreachable } });
  });

  it("leaves an expired session to the session logic", () => {
    const unauthorized: RefreshOutcome = { ok: false, code: "unauthorized", error: "401" };
    expect(run([unauthorized, unauthorized], true)).toEqual(INITIAL_REFRESH_STATE);
    expect(run([unauthorized], false)).toEqual(INITIAL_REFRESH_STATE);
  });
});

const CONNECTED: TunnelStatus = {
  phase: "connected",
  nodeId: "hk-1",
  connectedAt: 1,
  lastHandshakeAt: 1,
  rxBytes: 0,
  txBytes: 0,
  endpoint: "198.51.100.7:51820",
  addresses: ["10.8.0.4/32"],
  dns: ["10.8.0.1"],
  leakProtection: "wireguard",
  firewallActive: false,
  serviceState: "RUNNING",
  error: null,
  checkedAt: 0,
};
const NODE: VpnNode = { id: "hk-1", city: "Kowloon", country: "HK", endpointHost: "198.51.100.7", endpointPort: 51820, online: true };

function card(language: Language, props: { error: string | null; notice: string | null }): string {
  return renderToStaticMarkup(
    <I18nProvider translator={createTranslator(language)}>
      <ConnectCard
        status={CONNECTED}
        node={NODE}
        busy={false}
        canConnect
        error={props.error}
        notice={props.notice}
        protection={{ android: true, systemLockdown: null }}
        onToggle={() => {}}
      />
    </I18nProvider>,
  );
}

describe("ConnectCard notice", () => {
  it("renders the refresh notice neutral (role=status, no red, no alert)", () => {
    const html = card("en", { error: null, notice: en.app.refreshFailed });
    expect(html).toContain(en.app.refreshFailed);
    expect(html).toMatch(/role="status"[^>]*text-zinc-500/);
    expect(html).not.toContain('role="alert"');
  });

  it("a real error wins over the notice", () => {
    const html = card("de", { error: de.errors.apiUnreachable, notice: de.app.refreshFailed });
    expect(html).toContain('role="alert"');
    expect(html).toContain(de.errors.apiUnreachable);
    expect(html).not.toContain(de.app.refreshFailed);
  });

  it("network error text no longer asks to check the server address (fixed at build time)", () => {
    expect(de.errors.apiUnreachable).toBe("Server nicht erreichbar. Prüfe deine Verbindung.");
    expect(en.errors.apiUnreachable).toBe("Server not reachable. Check your connection.");
  });

  it("no error text asks to change the server address in the settings (not changeable in the app)", () => {
    for (const text of Object.values(de.errors)) expect(text).not.toMatch(/Server-Adresse in den Einstellungen/);
    for (const text of Object.values(en.errors)) expect(text).not.toMatch(/server address in the settings/i);
  });
});
