import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { describeApiError } from "../shared/core/api-errors";
import { translate } from "../shared/core/i18n";
import { ApiClient } from "../src/main/api/client";
import { accountSchema, nodesSchema } from "../src/main/api/schemas";

describe("api", () => {
  it("schemas: tor fields optional, invalid values dropped", () => {
    const base = { id: "nl-ams", city: "Amsterdam", country: "NL", endpointHost: "198.51.100.4", endpointPort: 51820, online: true };
    const nodes = nodesSchema.parse([{ ...base, tor: "ready" }, base, { ...base, tor: "warp" }]);
    expect(nodes.map((node) => node.tor)).toEqual(["ready", undefined, "unavailable"]);
    const device = { id: "dev1", name: "PC", nodeId: "nl-ams", ipv4: "10.8.0.5", createdOn: "2026-10-01T00:00:00.000Z" };
    const account = accountSchema.parse({
      id: "acc",
      paidUntil: "2027-01-01T00:00:00.000Z",
      settings: { killSwitch: true, lanAccess: false, ipv6: true, dns: { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false } },
      devices: [device, { ...device, id: "dev2", tor: true, torSocks: "10.8.0.1:9050" }, { ...device, id: "dev3", tor: "yes", torSocks: "bad host!" }],
    });
    expect(account.devices.map((entry) => [entry.tor, entry.torSocks])).toEqual([
      [undefined, undefined],
      [true, "10.8.0.1:9050"],
      [undefined, null],
    ]);
  });

  it("translates the tor error codes", () => {
    const message = (status: number, code: string, params?: Record<string, string | number>) => {
      const described = describeApiError(status, { code, error: "x", params });
      return typeof described.message === "string" ? described.message : translate("de", described.message);
    };
    expect(message(409, "tor_unavailable", { city: "Amsterdam" })).toBe("Amsterdam bietet Tor gerade nicht an.");
    expect(message(409, "tor_unavailable")).toBe("Dieser Standort bietet Tor gerade nicht an.");
    expect(message(503, "node_unavailable", { city: "Amsterdam" })).toContain("Amsterdam");
  });
});

describe("api client", () => {
  let server: Server;
  let base = "";
  const seen: string[] = [];

  beforeAll(async () => {
    server = createServer((request, response) => {
      let body = "";
      request.on("data", (chunk) => (body += chunk));
      request.on("end", () => {
        seen.push(`${request.method} ${request.url} ${request.headers.authorization ?? "-"} ${body}`);
        const enabled = (JSON.parse(body) as { enabled: boolean }).enabled;
        response.writeHead(200, { "content-type": "application/json" }).end(
          JSON.stringify({
            id: "0123456789abcdef",
            name: "PC",
            nodeId: "nl-ams",
            ipv4: "10.8.0.5",
            createdOn: "2026-10-01T00:00:00.000Z",
            tor: enabled,
            torSocks: enabled ? "10.8.0.1:9050" : null,
          }),
        );
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("PUT /devices/:id/tor with {enabled} and the session, answer = the device", async () => {
    const client = new ApiClient(() => base, () => "token-0123456789abcdef");
    const device = await client.setDeviceTor("0123456789abcdef", true);
    expect([device.tor, device.torSocks]).toEqual([true, "10.8.0.1:9050"]);
    expect(seen).toEqual(['PUT /api/v1/devices/0123456789abcdef/tor Bearer token-0123456789abcdef {"enabled":true}']);
  });
});
