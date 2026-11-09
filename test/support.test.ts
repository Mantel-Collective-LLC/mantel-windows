import { describe, expect, it, vi } from "vitest";
import type { Secrets } from "../src/main/store";
import {
  describeSupportError,
  isSupportText,
  newDeviceKey,
  supportRoute,
  supportRouteTemplate,
  SupportKeyError,
  SupportService,
  type DeviceKey,
  type TicketTransport,
} from "../shared/core/support";
import { routeTemplate } from "../src/main/api/client";
// @ts-expect-error plain .mjs without types (the mock API's ticket endpoints)
import { handleTickets } from "../dev/mock-tickets.mjs";

vi.mock("electron", () => ({
  safeStorage: { isEncryptionAvailable: () => true, encryptString: (text: string) => Buffer.from(text), decryptString: (data: Buffer) => data.toString() },
}));

type Account = { id: string };

function mockTransport(account: Account): { transport: TicketTransport; requests: { method: string; path: string; body: unknown }[] } {
  const requests: { method: string; path: string; body: unknown }[] = [];
  const transport: TicketTransport = async (request) => {
    requests.push({ method: request.method, path: request.path, body: request.body });
    const url = new URL(`http://mock${supportRoute(request)}`);
    let result: { status: number; body: unknown } = { status: 500, body: null };
    handleTickets({
      method: request.method,
      path: url.pathname,
      url,
      body: request.body,
      account,
      send: (status: number, body: unknown) => {
        result = { status, body: body ?? null };
      },
      fail: (status: number, code: string, error: string, params?: unknown) => {
        result = { status, body: { code, error, ...(params ? { params } : {}) } };
      },
    });
    return result;
  };
  return { transport, requests };
}

function memoryKeys() {
  let key: DeviceKey | null = null;
  return {
    load: async () => key,
    create: async () => (key = await newDeviceKey(false)),
    clear: async () => {
      key = null;
    },
  };
}

describe("SupportService", () => {
  it("creates a ticket, gets the team's encrypted answer, replies, closes; never sends plaintext fields", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout"] });
    try {
      const { transport, requests } = mockTransport({ id: `acc-${Math.random()}` });
      const service = new SupportService({ transport, keys: memoryKeys(), platform: "windows" });
      const overview = await service.overview();
      expect(overview).toMatchObject({ available: true, unread: 0, tickets: [] });
      const secret = "Mein Tunnel bricht nach 5 Minuten ab";
      const created = await service.create("connection", secret);
      expect(created.number).toBeGreaterThan(0);
      await vi.advanceTimersByTimeAsync(2_000);
      const listed = await service.overview();
      expect(listed.unread).toBe(1);
      expect(listed.tickets[0]).toMatchObject({ id: created.id, title: secret, readable: true, status: "waiting", unread: 1 });
      const thread = await service.ticket(created.id);
      expect(thread.messages.map((message) => message.role)).toEqual(["user", "team"]);
      expect(thread.messages[0]!.text).toBe(secret);
      expect(thread.messages[1]!.text).toMatch(/automatische Antwort/);
      expect(thread.unread).toBe(0);
      expect((await service.unread()).unread).toBe(0);
      const replied = await service.reply(created.id, "Danke!");
      expect(replied.messages.at(-1)).toMatchObject({ role: "user", text: "Danke!", seq: 3 });
      expect((await service.setClosed(created.id, true)).status).toBe("closed");
      expect((await service.setClosed(created.id, false)).status).not.toBe("closed");
      expect(JSON.stringify(requests)).not.toContain("Tunnel bricht");
      expect(JSON.stringify(requests)).not.toContain("Danke!");
    } finally {
      vi.useRealTimers();
    }
  });

  it("a second device of the account cannot read old tickets until the first one re-wraps them", async () => {
    const account = { id: `acc-${Math.random()}` };
    const first = new SupportService({ transport: mockTransport(account).transport, keys: memoryKeys(), platform: "windows" });
    await first.overview();
    const created = await first.create("app", "Auf dem PC erstellt");
    const second = new SupportService({ transport: mockTransport(account).transport, keys: memoryKeys(), platform: "android" });
    const before = await second.overview();
    expect(before.tickets[0]).toMatchObject({ id: created.id, readable: false, title: null });
    await first.overview();
    await new Promise((resolve) => setTimeout(resolve, 50));
    const after = await second.overview();
    expect(after.tickets[0]).toMatchObject({ readable: true, title: "Auf dem PC erstellt" });
  });

  it("logout unregisters the key at the server and forgets it locally", async () => {
    const { transport, requests } = mockTransport({ id: `acc-${Math.random()}` });
    const keys = memoryKeys();
    const service = new SupportService({ transport, keys, platform: "macos" });
    await service.overview();
    const key = await keys.load();
    expect(key).not.toBeNull();
    await service.logout();
    expect(await keys.load()).toBeNull();
    expect(requests.some((request) => request.method === "DELETE" && request.path === `keys/${key!.keyId}`)).toBe(true);
  });

  it("rejects empty and too long messages before anything is sent", async () => {
    const { transport, requests } = mockTransport({ id: `acc-${Math.random()}` });
    const service = new SupportService({ transport, keys: memoryKeys(), platform: "windows" });
    await expect(service.create("other", "   ")).rejects.toMatchObject({ reason: "empty" });
    await expect(service.create("other", "x".repeat(4001))).rejects.toMatchObject({ reason: "too_long" });
    expect(requests.filter((request) => request.method === "POST" && request.path === "")).toHaveLength(0);
    expect(isSupportText("x".repeat(4000))).toBe(true);
    expect(isSupportText("x".repeat(4001))).toBe(false);
    expect(isSupportText(42)).toBe(false);
  });
});

describe("desktop key storage", () => {
  it("stores the key only through safeStorage (secrets.bin) and refuses without OS encryption", async () => {
    const { desktopKeyStore } = await import("../src/main/support");
    let secrets: Secrets = { token: "t", accountId: "a", paidUntil: null, device: null, ticketKey: null };
    const store = { getSecrets: () => secrets, setSecrets: (next: Secrets) => void (secrets = next), encryptionAvailable: true };
    const keys = desktopKeyStore(store);
    expect(await keys.load()).toBeNull();
    const created = await keys.create();
    expect(secrets.ticketKey).toMatch(/^[A-Za-z0-9_-]{100,400}$/);
    const loaded = await desktopKeyStore(store).load();
    expect(loaded?.keyId).toBe(created.keyId);
    await keys.clear();
    expect(secrets.ticketKey).toBeNull();
    const locked = desktopKeyStore({ ...store, encryptionAvailable: false });
    await expect(locked.create()).rejects.toBeInstanceOf(SupportKeyError);
  });
});

describe("request log and errors", () => {
  it("never shows ticket ids, key ids or query strings in the request log", () => {
    const id = "a".repeat(32);
    expect(supportRouteTemplate(`/${id}/messages`)).toBe("/api/v1/tickets/:id/messages");
    expect(routeTemplate(`/api/v1/tickets/${id}?key=${"b".repeat(32)}`)).toBe("/api/v1/tickets/:id");
    expect(routeTemplate(`/api/v1/tickets/keys/${id}`)).toBe("/api/v1/tickets/keys/:id");
    expect(supportRoute({ path: "", query: { key: "k" } })).toBe("/api/v1/tickets?key=k");
  });

  it("maps ticket errors to the apps' messages", async () => {
    const { TicketApiError, TicketInputError } = await import("../shared/ticket/ticket-client");
    const limit = describeSupportError(new TicketApiError(409, "ticket_limit_reached", "x", { code: "ticket_limit_reached", error: "x", params: { max: 5 } }));
    expect(limit?.message).toMatchObject({ key: "apiTicketLimit", params: { max: 5 } });
    expect(describeSupportError(new TicketInputError("empty"))?.code).toBe("invalid");
    expect(describeSupportError(new SupportKeyError())).toMatchObject({ code: "internal", message: { key: "supportKeyStorage" } });
    expect(describeSupportError(new Error("network"))).toBeNull();
  });
});
