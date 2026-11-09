import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApiClient } from "../src/main/api/client";
import { loginsSchema } from "../src/main/api/schemas";

describe("schema", () => {
  it("only kind of app and method; unknown values from a newer server degrade, extra fields (a time) are dropped", () => {
    const parsed = loginsSchema.parse({
      logins: [
        { client: "vision-os", method: "magic", at: "2026-11-04T13:00:00.000Z" },
        { client: "android", method: "passkey" },
      ],
    });
    expect(parsed).toEqual({ logins: [{ client: "app", method: "code" }, { client: "android", method: "passkey" }] });
    expect(loginsSchema.safeParse({ logins: "nope" }).success).toBe(false);
  });
});

describe("api client", () => {
  let server: Server;
  let base = "";
  const seen: string[] = [];

  beforeAll(async () => {
    server = createServer((request, response) => {
      let body = "";
      request.on("data", (chunk: Buffer) => (body += chunk));
      request.on("end", () => {
        seen.push(`${request.method} ${request.url} ${request.headers.authorization ?? "-"} ${body}`);
        if (request.method === "GET") {
          response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ logins: [{ client: "browser", method: "passkey" }] }));
          return;
        }
        response.writeHead(204).end();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("GET /account/logins, POST /account/logins/seen and POST /auth/logout-others with the session", async () => {
    const client = new ApiClient(() => base, () => "token-0123456789abcdef");
    expect(await client.logins()).toEqual({ logins: [{ client: "browser", method: "passkey" }] });
    await client.loginsSeen();
    await client.logoutOthers();
    expect(seen).toEqual([
      "GET /api/v1/account/logins Bearer token-0123456789abcdef ",
      "POST /api/v1/account/logins/seen Bearer token-0123456789abcdef {}",
      "POST /api/v1/auth/logout-others Bearer token-0123456789abcdef {}",
    ]);
  });
});
