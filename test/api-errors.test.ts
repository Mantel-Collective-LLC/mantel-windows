import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApiClient, ApiError, type ApiRequestRecord } from "../src/main/api/client";
import { errorSchema } from "../src/main/api/schemas";
import {
  API_ERROR_MESSAGES,
  describeApiError,
  endsSession,
  parseApiErrorPayload,
  type ApiErrorPayload,
} from "../shared/core/api-errors";
import { errorMessage, translate, type LocalizedMessage } from "../shared/core/i18n";


const SAMPLE_PARAMS = { city: "Zürich", max: 5, retryAfterSeconds: 60, key: "ipv6", field: "x", ports: "51820" };

function text(message: string | LocalizedMessage, language: "de" | "en"): string {
  return typeof message === "string" ? message : translate(language, message);
}

describe("API error codes → localized messages", () => {

  it("maps codes to the app's texts and ErrorCodes", () => {
    const unknown = describeApiError(401, { code: "unknown_code", error: "This account number does not exist." });
    expect(text(unknown.message, "de")).toBe("Diese Kontonummer kennen wir nicht.");
    expect(text(unknown.message, "en")).toBe("We don’t know this account number.");
    expect(unknown).toMatchObject({ code: "unauthorized", apiCode: "unknown_code", serverMessage: "This account number does not exist." });

    const totp = describeApiError(401, { code: "totp_required", error: "x" });
    expect(totp).toMatchObject({ code: "totp_required", apiCode: "totp_required" });
    expect(text(totp.message, "en")).toBe("Enter the code from your authenticator app.");
    expect(describeApiError(401, { code: "totp_invalid", error: "x" }).code).toBe("invalid");
    expect(describeApiError(403, { error: "Two-factor authentication is on for this account." }).message).toBe("Two-factor authentication is on for this account.");

    const minute = describeApiError(429, { code: "rate_limited", error: "x", params: { retryAfterSeconds: 60 } });
    expect(text(minute.message, "de")).toBe("Zu viele Versuche. Warte eine Minute.");
    expect(text(minute.message, "en")).toBe("Too many attempts. Wait a minute.");
    expect(minute.code).toBe("rate_limited");
    const longer = describeApiError(429, { code: "rate_limited", error: "x", params: { retryAfterSeconds: 600 } });
    expect(text(longer.message, "de")).toBe("Zu viele Versuche. Bitte warte 10 Minuten.");
    const day = describeApiError(429, { code: "rate_limited", error: "x", params: { retryAfterSeconds: 86_340 } });
    expect(text(day.message, "en")).toBe("Too many attempts. Please wait 24 hours.");
    const noWait = describeApiError(429, { code: "rate_limited", error: "x" });
    expect(text(noWait.message, "de")).toBe("Zu viele Versuche. Bitte warte kurz.");

    const blocked = describeApiError(403, { code: "tickets_blocked", error: "x" });
    expect(text(blocked.message, "de")).toBe("Support-Tickets sind für dieses Konto gerade nicht verfügbar.");
    const reopen = describeApiError(409, { code: "ticket_reopen_expired", error: "x", params: { days: 14 } });
    expect(text(reopen.message, "en")).toBe("This ticket was closed more than 14 days ago. Please open a new ticket.");

    const offline = describeApiError(503, { code: "node_unavailable", error: "x", params: { city: "Zürich" } });
    expect(text(offline.message, "de")).toBe(
      "Zürich ist gerade nicht erreichbar. Versuch es gleich noch einmal oder wähle einen anderen Standort.",
    );
    expect(offline.code).toBe("server");
    const noCity = describeApiError(503, { code: "node_unavailable", error: "x" });
    expect(text(noCity.message, "en")).toBe("This location is not available right now. Choose another location.");

    const limit = describeApiError(409, { code: "device_limit_reached", error: "x", params: { max: 5 } });
    expect(text(limit.message, "de")).toBe("Maximal 5 Geräte pro Konto. Entferne zuerst eins.");
    expect(text(limit.message, "en")).toBe("At most 5 devices per account. Remove one first.");

    const json = describeApiError(400, { code: "invalid_json", error: "The request body is not valid JSON." });
    expect(text(json.message, "de")).toBe("Der Server hat die Anfrage abgelehnt (HTTP 400).");
    expect(json.code).toBe("invalid");
  });

  it("shows the generic text of the status class for unknown codes; English text only in the debug flavor", () => {
    const payload: ApiErrorPayload = { code: "brand_new_code", error: "Something new went wrong." };
    const prod = describeApiError(422, payload);
    expect(text(prod.message, "de")).toBe("Der Server hat die Anfrage abgelehnt (HTTP 422).");
    expect(text(prod.message, "en")).not.toContain("Something new");
    expect(text(describeApiError(503, payload).message, "en")).toBe("Server error (503).");
    expect(text(describeApiError(429, payload).message, "de")).toBe("Zu viele Versuche. Bitte warte kurz.");
    expect(describeApiError(429, payload).code).toBe("rate_limited");

    const debug = describeApiError(422, payload, { debug: true });
    expect(text(debug.message, "de")).toBe(
      "Der Server hat die Anfrage abgelehnt (HTTP 422). [brand_new_code: Something new went wrong.]",
    );
    expect(text(debug.message, "en")).toBe("The server rejected the request (HTTP 422). [brand_new_code: Something new went wrong.]");
    expect(text(describeApiError(401, { code: "unknown_code", error: "x" }, { debug: true }).message, "de")).toBe(
      "Diese Kontonummer kennen wir nicht.",
    );
  });

  it("keeps old servers working: no code → their own text, ErrorCode and session handling by status", () => {
    const old = describeApiError(401, { error: "Diese Kontonummer kennen wir nicht." });
    expect(old.message).toBe("Diese Kontonummer kennen wir nicht.");
    expect(old.code).toBe("unauthorized");
    expect(old.apiCode).toBeUndefined();
    expect(text(describeApiError(409, {}).message, "en")).toBe("Conflict with the current state.");
    expect(text(describeApiError(500, null).message, "de")).toBe("Serverfehler (500).");
  });

  it("ends the session by code (unauthorized, account_not_found), for old servers on any 401", () => {
    expect(endsSession(401, "unauthorized")).toBe(true);
    expect(endsSession(401, "account_not_found")).toBe(true);
    expect(endsSession(401, "unknown_code")).toBe(false);
    expect(endsSession(401, undefined)).toBe(true);
    expect(endsSession(403, undefined)).toBe(false);
    expect(endsSession(null, "unauthorized")).toBe(false);
  });

  it("parses error bodies leniently (schema and dependency-free parser agree)", () => {
    const bodies: unknown[] = [
      { code: "rate_limited", error: "Too many", params: { retryAfterSeconds: 60 } },
      { error: "Alt" },
      { code: "Not Snake", error: "x" },
      { code: "x", error: "y".repeat(600) },
      { code: "x", params: { nested: { a: 1 }, ok: 1 } },
    ];
    expect(errorSchema.parse(bodies[0])).toEqual(bodies[0]);
    expect(parseApiErrorPayload(bodies[0])).toEqual(bodies[0]);
    expect(errorSchema.parse(bodies[1])).toEqual({ error: "Alt" });
    expect(errorSchema.parse(bodies[2])).toEqual({ error: "x" });
    expect(parseApiErrorPayload(bodies[2])).toEqual({ error: "x" });
    expect(errorSchema.parse(bodies[3])).toEqual({ code: "x" });
    expect(parseApiErrorPayload(bodies[3])).toEqual({ code: "x" });
    expect(parseApiErrorPayload(bodies[4])).toEqual({ code: "x", params: { ok: 1 } });
    expect(errorSchema.safeParse(null).success).toBe(false);
    expect(parseApiErrorPayload([1])).toBeNull();
  });
});

describe("ApiClient with coded error responses", () => {
  let server: Server;
  let base = "";
  const replies = new Map<string, { status: number; body: unknown }>([
    ["/api/v1/auth/login", { status: 401, body: { code: "unknown_code", error: "This account number does not exist." } }],
    ["/api/v1/nodes", { status: 418, body: { code: "teapot", error: "I am a teapot." } }],
    ["/api/v1/account", { status: 401, body: { code: "unauthorized", error: "Not signed in or the session has expired." } }],
    ["/api/v1/auth/register", { status: 429, body: { error: "Zu viele neue Konten in kurzer Zeit. Versuch es später erneut." } }],
    ["/api/v1/settings", { status: 401, body: { error: "Bitte melde dich an." } }],
  ]);

  beforeAll(async () => {
    server = createServer((request, response) => {
      const reply = replies.get(request.url ?? "") ?? { status: 404, body: { code: "not_found", error: "Not found." } };
      response.writeHead(reply.status, { "content-type": "application/json" });
      response.end(JSON.stringify(reply.body));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("localizes by code, records the server code and decides session end by code", async () => {
    const records: ApiRequestRecord[] = [];
    const api = new ApiClient(() => base, () => "t".repeat(32));
    api.onRequest = (record) => records.push(record);

    const login = (await api.login("9999999999999999").catch((error: unknown) => error)) as ApiError;
    expect(login).toBeInstanceOf(ApiError);
    expect(login.message).toBe("Diese Kontonummer kennen wir nicht.");
    expect(errorMessage(login, "en")).toBe("We don’t know this account number.");
    expect(login).toMatchObject({ code: "unauthorized", status: 401, apiCode: "unknown_code", sessionEnded: false });
    expect(login.serverMessage).toBe("This account number does not exist.");

    const account = (await api.account().catch((error: unknown) => error)) as ApiError;
    expect(account.sessionEnded).toBe(true);
    expect(errorMessage(account, "de")).toBe("Deine Sitzung ist abgelaufen. Bitte melde dich erneut an.");

    const teapot = (await api.nodes().catch((error: unknown) => error)) as ApiError;
    expect(errorMessage(teapot, "de")).toBe("Der Server hat die Anfrage abgelehnt (HTTP 418).");
    expect(errorMessage(teapot, "en")).not.toContain("teapot");

    expect(records.map((record) => [record.route, record.status, record.code, record.apiCode])).toEqual([
      ["/api/v1/auth/login", 401, "unauthorized", "unknown_code"],
      ["/api/v1/account", 401, "unauthorized", "unauthorized"],
      ["/api/v1/nodes", 418, "invalid", "teapot"],
    ]);
  });

  it("debug flavor: unknown codes carry the server's code and English text", async () => {
    const api = new ApiClient(() => base, () => null, undefined, undefined, { debug: true });
    const teapot = await api.nodes().catch((error: unknown) => error);
    expect(errorMessage(teapot, "en")).toBe("The server rejected the request (HTTP 418). [teapot: I am a teapot.]");
  });

  it("old server without codes: shows its own text, 401 still ends the session", async () => {
    const api = new ApiClient(() => base, () => "t".repeat(32));
    const register = (await api.register().catch((error: unknown) => error)) as ApiError;
    expect(register).toMatchObject({ code: "rate_limited", status: 429 });
    expect(register.apiCode).toBeUndefined();
    expect(errorMessage(register, "en")).toBe("Zu viele neue Konten in kurzer Zeit. Versuch es später erneut.");
    const settings = (await api.updateSettings({ ipv6: true }).catch((error: unknown) => error)) as ApiError;
    expect(settings.sessionEnded).toBe(true);
  });
});
