import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiClient, ApiError, routeTemplate } from "../src/main/api/client";
import { proxyListSchema } from "../src/main/api/schemas";
import { isTelegramProxyLink, parseProxyCreate, parseProxyPatch, proxyUrl } from "../shared/core/proxy";

const PROXY = {
  id: "px_1",
  name: "Browser",
  nodeId: "nl-ams",
  host: "198.51.100.4",
  port: 31080,
  protocol: "socks5",
  exit: "tor",
  username: "u-7f3a",
  enabled: true,
  status: "active",
};

const FORWARDS = { deviceId: "0123456789abcdef", nodeId: "nl-ams", city: "Amsterdam", country: "NL", available: true, reason: null, max: 2 };

describe("proxy contract helpers", () => {
  it("parses create bodies strictly and cleans the name", () => {
    expect(parseProxyCreate({ name: "  Mein\u200b  Browser ", nodeId: "nl-ams", protocol: "http", exit: "direct" })).toEqual({
      name: "Mein Browser",
      nodeId: "nl-ams",
      protocol: "http",
      exit: "direct",
    });
    expect(parseProxyCreate({ name: "", nodeId: "nl-ams", protocol: "http", exit: "direct" })).toBeNull();
    expect(parseProxyCreate({ name: "x", nodeId: "nl ams", protocol: "http", exit: "direct" })).toBeNull();
    expect(parseProxyCreate({ name: "x", nodeId: "nl-ams", protocol: "socks4", exit: "direct" })).toBeNull();
    expect(parseProxyCreate({ name: "x".repeat(41), nodeId: "nl-ams", protocol: "http", exit: "tor" })).toBeNull();
  });

  it("parses patches: known fields only, flags only as true, never empty", () => {
    expect(parseProxyPatch({ enabled: false })).toEqual({ enabled: false });
    expect(parseProxyPatch({ rotatePassword: true, newCircuit: true })).toEqual({ rotatePassword: true, newCircuit: true });
    expect(parseProxyPatch({ rotatePassword: false })).toBeNull();
    expect(parseProxyPatch({ port: 1080 })).toBeNull();
    expect(parseProxyPatch({})).toBeNull();
    expect(parseProxyPatch({ exit: "vpn" })).toBeNull();
  });

  it("builds the copy URL with encoded credentials and bracketed IPv6", () => {
    expect(proxyUrl({ protocol: "socks5", host: "198.51.100.4", port: 31080, username: "u-7f3a" }, "p@ss:word")).toBe(
      "socks5://u-7f3a:p%40ss%3Aword@198.51.100.4:31080",
    );
    expect(proxyUrl({ protocol: "http", host: "2001:db8::4", port: 8080, username: "u" }, "p")).toBe("http://u:p@[2001:db8::4]:8080");
  });

  it("list schema: unknown status counts as unavailable, bad hosts are refused", () => {
    expect(proxyListSchema.parse({ proxies: [{ ...PROXY, status: "migrating" }] }).proxies[0]?.status).toBe("unavailable");
    expect(proxyListSchema.safeParse({ proxies: [{ ...PROXY, host: "not a host!" }] }).success).toBe(false);
  });

  it("mtproto: secret and matching Telegram links instead of a username; only t.me proxy links open", () => {
    const secret = `ee${"ab".repeat(16)}${Buffer.from("www.cloudflare.com").toString("hex")}`;
    const query = `server=198.51.100.4&port=10001&secret=${secret}`;
    const mtproto = { ...PROXY, protocol: "mtproto", username: "", secret, link: `tg://proxy?${query}`, webLink: `https://t.me/proxy?${query}` };
    expect(proxyListSchema.parse({ proxies: [mtproto] }).proxies[0]?.webLink).toBe(mtproto.webLink);
    expect(proxyListSchema.safeParse({ proxies: [{ ...mtproto, link: "tg://proxy?server=evil&port=1&secret=" + secret }] }).success).toBe(false);
    expect(proxyListSchema.safeParse({ proxies: [{ ...mtproto, webLink: undefined }] }).success).toBe(false);
    expect(proxyListSchema.safeParse({ proxies: [{ ...PROXY, username: "" }] }).success).toBe(false);
    expect(proxyListSchema.safeParse({ proxies: [{ ...PROXY, link: mtproto.link }] }).success).toBe(false);
    expect(parseProxyCreate({ name: "Chat", nodeId: "nl-ams", protocol: "mtproto", exit: "direct" })?.protocol).toBe("mtproto");
    expect(isTelegramProxyLink(mtproto.webLink)).toBe(true);
    for (const bad of [mtproto.link, "https://evil.example/proxy?" + query, `${mtproto.webLink}&x=1`, "javascript:alert(1)"]) {
      expect(isTelegramProxyLink(bad)).toBe(false);
    }
  });

  it("debug log never shows proxy or device ids", () => {
    expect(routeTemplate("/api/v1/proxies/px_1")).toBe("/api/v1/proxies/:id");
    expect(routeTemplate("/api/v1/devices/0123456789abcdef/port-forwarding/41234")).toBe("/api/v1/devices/:id/port-forwarding/41234");
  });
});

describe("api client", () => {
  let server: Server;
  let base = "";
  const seen: string[] = [];
  let proxiesExist = true;

  beforeAll(async () => {
    server = createServer((request, response) => {
      let body = "";
      request.on("data", (chunk) => (body += chunk));
      request.on("end", () => {
        seen.push(`${request.method} ${request.url} ${body}`);
        const send = (status: number, payload?: unknown) => {
          response.writeHead(status, { "content-type": "application/json" }).end(payload === undefined ? undefined : JSON.stringify(payload));
        };
        const url = request.url ?? "";
        if (url.startsWith("/api/v1/proxies") && !proxiesExist) return send(404, { code: "not_found", error: "Not found." });
        if (request.method === "GET" && url === "/api/v1/proxies") return send(200, { proxies: [PROXY] });
        if (request.method === "POST" && url === "/api/v1/proxies") return send(201, { proxy: { ...PROXY, ...JSON.parse(body) }, password: "secret-1" });
        if (request.method === "PATCH" && url === "/api/v1/proxies/px_1") {
          const patch = JSON.parse(body) as Record<string, unknown>;
          if (patch.name === "taken") return send(429, { code: "rate_limited", error: "x", params: { retryAfterSeconds: 30 } });
          return send(200, { proxy: { ...PROXY, ...patch }, ...(patch.rotatePassword ? { password: "secret-2" } : {}) });
        }
        if (request.method === "DELETE" && url === "/api/v1/proxies/px_1") return send(204);
        if (request.method === "PATCH" && url === "/api/v1/devices/0123456789abcdef") {
          return send(200, { id: "0123456789abcdef", nodeId: "nl-ams", ipv4: "10.8.0.7", createdOn: "2026-10-01", ...JSON.parse(body) });
        }
        if (request.method === "DELETE" && url === "/api/v1/devices/0123456789abcdef/port-forwarding/41234") {
          return send(200, { ...FORWARDS, forwards: [{ port: 41235, host: "198.51.100.4", protocols: ["tcp", "udp"] }] });
        }
        send(404, { code: "not_found", error: "Not found." });
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  beforeEach(() => {
    seen.length = 0;
    proxiesExist = true;
  });

  const client = () => new ApiClient(() => base, () => "t".repeat(32));

  it("lists proxies, and a server without the route answers null (Bald verfügbar)", async () => {
    expect(await client().proxies()).toEqual([PROXY]);
    proxiesExist = false;
    expect(await client().proxies()).toBeNull();
  });

  it("only the list treats 404 as 'not offered': a gone proxy is an error", async () => {
    proxiesExist = false;
    await expect(client().deleteProxy("px_1")).rejects.toBeInstanceOf(ApiError);
  });

  it("create returns the password once; patch only when renewed", async () => {
    const created = await client().createProxy({ name: "TV", nodeId: "nl-ams", protocol: "http", exit: "direct" });
    expect(created.password).toBe("secret-1");
    expect(created.proxy.protocol).toBe("http");
    expect(seen[0]).toBe('POST /api/v1/proxies {"name":"TV","nodeId":"nl-ams","protocol":"http","exit":"direct"}');
    expect((await client().updateProxy("px_1", { rotatePassword: true })).password).toBe("secret-2");
    const toggled = await client().updateProxy("px_1", { enabled: false });
    expect(toggled.password).toBeUndefined();
    expect(toggled.proxy.enabled).toBe(false);
    await client().deleteProxy("px_1");
    expect(seen.at(-1)).toBe("DELETE /api/v1/proxies/px_1 ");
  });

  it("passes API error codes through", async () => {
    const error = await client().updateProxy("px_1", { name: "taken" }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe("rate_limited");
  });

  it("renames a device and releases a single forwarded port", async () => {
    expect((await client().renameDevice("0123456789abcdef", "Wohnzimmer")).name).toBe("Wohnzimmer");
    const state = await client().portForwarding("0123456789abcdef", { removePort: 41234 });
    expect(state.forwards).toEqual([{ port: 41235, host: "198.51.100.4", localPort: null }]);
    expect(seen.at(-1)).toBe("DELETE /api/v1/devices/0123456789abcdef/port-forwarding/41234 ");
  });
});
