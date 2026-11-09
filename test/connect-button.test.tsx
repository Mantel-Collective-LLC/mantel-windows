import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { TunnelPhase, TunnelStatus, VpnNode } from "../shared/core/contract";
import { createTranslator, type Language } from "../shared/core/i18n";
import { I18nProvider } from "../shared/ui/src/i18n/context";
import { ConnectCard } from "../shared/ui/src/screens/home";
import { buttonClasses } from "../shared/ui/src/ui/primitives";

const NODE: VpnNode = { id: "hk-hkg", city: "Hongkong", country: "HK", endpointHost: "203.0.113.60", endpointPort: 51820, online: true };

function status(phase: TunnelPhase): TunnelStatus {
  const live = phase === "connected" || phase === "stale";
  return {
    phase,
    nodeId: phase === "disconnected" ? null : NODE.id,
    connectedAt: live ? 1 : null,
    lastHandshakeAt: live ? 1 : null,
    rxBytes: 0,
    txBytes: 0,
    endpoint: null,
    addresses: live ? ["10.8.0.4/32"] : [],
    dns: [],
    leakProtection: "wireguard",
    firewallActive: false,
    serviceState: null,
    error: null,
    checkedAt: 0,
  };
}

function bigButton(phase: TunnelPhase, options: { busy?: boolean; canConnect?: boolean; language?: Language } = {}) {
  const html = renderToStaticMarkup(
    <I18nProvider translator={createTranslator(options.language ?? "de")}>
      <ConnectCard
        status={status(phase)}
        node={NODE}
        busy={options.busy ?? false}
        canConnect={options.canConnect ?? true}
        error={null}
        protection={{ android: false, systemLockdown: null }}
        onToggle={() => undefined}
      />
    </I18nProvider>,
  );
  const match = /<button[^>]*aria-pressed="(?:true|false)"[^>]*>(.*?)<\/button>/.exec(html);
  expect(match).not.toBeNull();
  const tag = match![0].slice(0, match![0].indexOf(">") + 1);
  const label = match![1]!.replace(/<[^>]+>/g, "");
  const classes = /class="([^"]*)"/.exec(tag)![1]!.split(" ");
  return { tag, html: match![0], label, classes, disabled: / disabled=""/.test(tag) };
}

describe("connect button colours", () => {
  it("disconnected: solid green 'Verbinden'", () => {
    const button = bigButton("disconnected");
    expect(button.label).toBe("Verbinden");
    expect(button.classes).toContain("bg-accent-strong");
    expect(button.classes).not.toContain("bg-stop");
    expect(button.disabled).toBe(false);
  });

  it("connected and interrupted: solid red 'Verbindung trennen' at rest, darker on hover and press", () => {
    for (const phase of ["connected", "stale"] as const) {
      const button = bigButton(phase);
      expect(button.label).toBe("Verbindung trennen");
      expect(button.tag).toContain('aria-label="Verbindung trennen"');
      expect(button.classes).toEqual(expect.arrayContaining(["bg-stop", "text-on-stop", "hover:bg-stop-hover", "active:bg-stop-active"]));
      expect(button.classes).not.toContain("bg-surface");
      expect(button.classes.some((name) => name.startsWith("border"))).toBe(false);
      expect(button.classes).toContain("focus-visible:ring-stop");
    }
    expect(bigButton("connected", { language: "en" }).label).toBe("Disconnect");
  });

  it("in between: the colour of the step that runs, muted, with a spinner and aria-busy", () => {
    const connecting = bigButton("connecting");
    expect(connecting.label).toBe("Verbinde …");
    expect(connecting.classes).toEqual(expect.arrayContaining(["bg-accent-strong", "opacity-75"]));
    expect(connecting.tag).toContain('aria-busy="true"');
    expect(connecting.html).toContain("animate-spin");

    const disconnecting = bigButton("disconnecting");
    expect(disconnecting.label).toBe("Trenne …");
    expect(disconnecting.classes).toEqual(expect.arrayContaining(["bg-stop", "opacity-75"]));
    expect(disconnecting.tag).toContain('aria-busy="true"');

    expect(bigButton("disconnected", { busy: true }).classes).toContain("bg-accent-strong");
    expect(bigButton("connected", { busy: true }).classes).toContain("bg-stop");
    for (const button of [connecting, disconnecting]) {
      expect(button.classes).not.toContain("disabled:bg-zinc-200");
    }
  });

  it("cannot connect (no admin rights, no location): greyed out, not muted green", () => {
    const button = bigButton("disconnected", { canConnect: false });
    expect(button.disabled).toBe(true);
    expect(button.classes).toContain("disabled:bg-zinc-200");
    expect(button.classes).not.toContain("opacity-75");
  });

  it("keeps the focus ring width and offset with the red ring colour", () => {
    const classes = buttonClasses("stop", "xl").split(" ");
    expect(classes).toEqual(expect.arrayContaining(["focus-visible:ring-2", "focus-visible:ring-offset-2", "focus-visible:ring-stop"]));
    expect(classes).not.toContain("focus-visible:ring-accent");
  });
});
