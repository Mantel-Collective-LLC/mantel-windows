import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApiClient } from "../src/main/api/client";
import { nodesSchema, portForwardingSchema } from "../src/main/api/schemas";
import { describeApiError } from "../shared/core/api-errors";
import { translate } from "../shared/core/i18n";

describe("schemas", () => {
  it("nodes: portForwarding is optional, anything but a boolean is dropped", () => {
    const base = { id: "nl-ams", city: "Amsterdam", country: "NL", endpointHost: "198.51.100.4", endpointPort: 51820, online: true };
    const parsed = nodesSchema.parse([{ ...base, portForwarding: true }, base, { ...base, portForwarding: "yes" }]);
    expect(parsed.map((node) => node.portForwarding)).toEqual([true, undefined, undefined]);
  });

  it("port forwarding: strict ports and hosts, unknown reasons count as unsupported", () => {
    const body = { deviceId: "0123456789abcdef", nodeId: "nl-ams", city: "Amsterdam", country: "NL", available: false, reason: "maintenance", max: 1, forwards: [] };
    expect(portForwardingSchema.parse(body).reason).toBe("unsupported");
    expect(portForwardingSchema.safeParse({ ...body, forwards: [{ port: 80, host: "198.51.100.4" }] }).success).toBe(false);
    expect(portForwardingSchema.safeParse({ ...body, forwards: [{ port: 41234, host: "not a host!" }] }).success).toBe(false);
    expect(portForwardingSchema.parse({ ...body, reason: null, available: true }).reason).toBeNull();
  });

  it("port forwarding: localPort (agent 2.13) optional and tolerant; older servers send none", () => {
    const body = { deviceId: "0123456789abcdef", nodeId: "nl-ams", city: "Amsterdam", country: "NL", available: true, reason: null, max: 1 };
    const old = portForwardingSchema.parse({ ...body, forwards: [{ port: 41234, host: "198.51.100.4" }] });
    expect(old.localPort).toBe(false);
    expect(old.forwards[0]?.localPort).toBeNull();
    const current = portForwardingSchema.parse({ ...body, localPort: true, forwards: [{ port: 41234, host: "198.51.100.4", localPort: 3000 }] });
    expect(current.localPort).toBe(true);
    expect(current.forwards[0]?.localPort).toBe(3000);
    expect(portForwardingSchema.parse({ ...body, localPort: "yes", forwards: [{ port: 41234, host: "198.51.100.4", localPort: 0 }] })).toMatchObject({
      localPort: false,
      forwards: [{ localPort: null }],
    });
  });
});

describe("api errors", () => {
  it("translates the port forwarding codes with their params", () => {
    const message = (code: string, params?: Record<string, string | number>) => {
      const described = describeApiError(503, { code, error: "x", params });
      return typeof described.message === "string" ? described.message : translate("de", described.message);
    };
    expect(message("port_forwarding_unavailable", { city: "Amsterdam" })).toBe("Amsterdam bietet gerade keine Portweiterleitung an.");
    expect(message("port_forwarding_unavailable")).toBe("Dieser Standort bietet gerade keine Portweiterleitung an.");
    expect(message("port_forward_limit_reached", { max: 1 })).toBe("Höchstens 1 weitergeleitete Ports. Schalte zuerst einen ab.");
    expect(message("port_forwarding_full", { city: "Amsterdam" })).toContain("keine freien Ports");
    expect(message("port_forward_not_found")).toContain("weitergeleiteten Port");
    expect(message("invalid_local_port")).toContain("1 bis 65535");
    expect(message("local_port_unsupported", { city: "Amsterdam" })).toContain("Amsterdam kann noch nicht");
    expect(message("local_port_unsupported")).toContain("Dieser Standort");
  });
});

describe("api client", () => {
  let server: Server;
  let base = "";
  const seen: string[] = [];

  beforeAll(async () => {
    server = createServer((request, response) => {
      seen.push(`${request.method} ${request.url} ${request.headers.authorization ?? "-"}`);
      let body = "";
      request.on("data", (chunk) => (body += chunk));
      request.on("end", () => {
        seen.push(`body ${body || "-"}`);
        const sent = body ? (JSON.parse(body) as { localPort?: number | null }) : {};
        const local = sent.localPort ?? null;
        const forwards = request.method === "POST" || request.method === "PATCH" ? [{ port: 41234, host: "198.51.100.4", protocols: ["tcp", "udp"], localPort: local }] : [];
        if (request.method === "POST" && body !== "{}" && local === null) {
          response.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ code: "unknown_field", error: "x" }));
          return;
        }
        response
          .writeHead(request.method === "POST" ? 201 : 200, { "content-type": "application/json" })
          .end(JSON.stringify({ deviceId: "0123456789abcdef", nodeId: "nl-ams", city: "Amsterdam", country: "NL", available: true, reason: null, max: 1, localPort: true, forwards }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("GET, POST {} and DELETE on /devices/:id/port-forwarding with the session", async () => {
    const client = new ApiClient(() => base, () => "token-0123456789abcdef");
    expect(await client.portForwarding("0123456789abcdef")).toEqual({ nodeId: "nl-ams", city: "Amsterdam", available: true, reason: null, max: 1, localPort: true, forwards: [] });
    const on = await client.portForwarding("0123456789abcdef", "enable");
    expect(on.forwards).toEqual([{ port: 41234, host: "198.51.100.4", localPort: null }]);
    expect((await client.portForwarding("0123456789abcdef", "disable")).forwards).toEqual([]);
    expect(seen).toEqual([
      "GET /api/v1/devices/0123456789abcdef/port-forwarding Bearer token-0123456789abcdef",
      "body -",
      "POST /api/v1/devices/0123456789abcdef/port-forwarding Bearer token-0123456789abcdef",
      "body {}",
      "DELETE /api/v1/devices/0123456789abcdef/port-forwarding Bearer token-0123456789abcdef",
      "body -",
    ]);
    seen.length = 0;
    expect((await client.portForwarding("0123456789abcdef", { addLocalPort: 3000 })).forwards).toEqual([{ port: 41234, host: "198.51.100.4", localPort: 3000 }]);
    expect((await client.portForwarding("0123456789abcdef", { addLocalPort: null })).forwards[0]?.localPort).toBeNull();
    expect((await client.portForwarding("0123456789abcdef", { port: 41234, localPort: 8080 })).forwards[0]?.localPort).toBe(8080);
    expect(seen).toEqual([
      "POST /api/v1/devices/0123456789abcdef/port-forwarding Bearer token-0123456789abcdef",
      'body {"localPort":3000}',
      "POST /api/v1/devices/0123456789abcdef/port-forwarding Bearer token-0123456789abcdef",
      "body {}",
      "PATCH /api/v1/devices/0123456789abcdef/port-forwarding/41234 Bearer token-0123456789abcdef",
      'body {"localPort":8080}',
    ]);
  });
});
