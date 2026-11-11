import { describe, expect, it } from "vitest";
import { createTauriBridge, type Invoke, type Listen } from "../src/bridge";
import { tauriKeyStore, tauriTicketTransport } from "../src/support";
import type { SupportService } from "../../shared/core/support";

const on: Listen = () => () => undefined;

describe("Tauri support tickets", () => {
  it("keeps the device key in Rust and reuses it", async () => {
    let stored: string | null = null;
    const calls: string[] = [];
    const call: Invoke = async (command, args) => {
      calls.push(command);
      if (command === "support_key_load") return stored;
      if (command === "support_key_save") stored = String(args?.pkcs8);
      if (command === "support_key_clear") stored = null;
      return null;
    };
    const keys = tauriKeyStore(call);
    expect(await keys.load()).toBeNull();
    const created = await keys.create();
    expect(stored).toMatch(/^[A-Za-z0-9_-]+$/);
    const loaded = await keys.load();
    expect(loaded?.keyId).toBe(created.keyId);
    expect(loaded?.privateKey.extractable).toBe(false);
    await keys.clear();
    expect(stored).toBeNull();
    expect(calls).toContain("support_key_save");
  });

  it("sends ticket requests through Rust, never with extra headers", async () => {
    const seen: unknown[] = [];
    const call: Invoke = async (command, args) => {
      seen.push([command, args]);
      return { status: 200, body: { ok: true } };
    };
    const transport = tauriTicketTransport(call);
    expect(await transport({ method: "GET", path: "", query: { key: "a".repeat(32) } })).toEqual({ status: 200, body: { ok: true } });
    expect(seen[0]).toEqual(["support_request", { method: "GET", path: "", query: { key: "a".repeat(32) }, body: null }]);
    await expect(transport({ method: "POST", path: "team/grant", headers: { "x-proof": "1" } })).rejects.toThrow();
  });

  it("checks input, maps errors and unregisters the key before logging out", async () => {
    const order: string[] = [];
    const support = {
      unregister: async () => void order.push("unregister"),
      forget: async () => void order.push("forget"),
      ticket: async () => {
        throw new Error("never");
      },
      create: async () => ({ id: "x", number: 1 }),
    } as unknown as SupportService;
    const call: Invoke = async (command) => {
      if (command === "preferences") return { language: "en" };
      order.push(command);
      return null;
    };
    const bridge = createTauriBridge(call, on, [], support);
    expect(await bridge.supportTicket!("../x")).toMatchObject({ ok: false, code: "invalid" });
    expect(await bridge.supportCreate!("nope" as never, "hi")).toMatchObject({ ok: false, code: "invalid" });
    expect(await bridge.supportCreate!("app", "hi")).toEqual({ ok: true, value: { id: "x", number: 1 } });
    await bridge.logout();
    expect(order).toEqual(["unregister", "logout", "forget"]);
    expect(typeof bridge.supportOverview).toBe("function");
  });
});
