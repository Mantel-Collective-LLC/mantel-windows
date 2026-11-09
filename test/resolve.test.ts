import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import path from "node:path";
import tls, { type TLSSocket } from "node:tls";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../src/main/api/client";
import { httpRequest } from "../src/main/api/http";
import { HostResolver, MAX_CACHED_ADDRESSES, pinnedLookup, UnresolvedHostError, type AddressCache } from "../src/main/net/resolve";

function memoryCache(initial: Record<string, string[]> = {}): AddressCache & { data: Record<string, string[]> } {
  const data = { ...initial };
  return { data, read: (host) => data[host] ?? [], write: (host, addresses) => (data[host] = addresses) };
}

function failingLookup() {
  return vi.fn(async (host: string): Promise<string[]> => {
    throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: "ENOTFOUND" });
  });
}

describe("HostResolver", () => {
  it("passes IP literals through without DNS", async () => {
    const lookup = failingLookup();
    const resolver = new HostResolver({ cache: memoryCache(), dnsBlocked: () => true, lookup });
    expect(await resolver.resolve("203.0.113.5")).toEqual(["203.0.113.5"]);
    expect(await resolver.resolve("[2001:db8::5]")).toEqual(["2001:db8::5"]);
    expect(lookup).not.toHaveBeenCalled();
  });

  it("remembers successful lookups and reports changes", async () => {
    const cache = memoryCache();
    const onChange = vi.fn();
    const resolver = new HostResolver({
      cache,
      dnsBlocked: () => false,
      lookup: async () => ["198.51.100.10", "2001:db8::10"],
      onChange,
    });
    expect(await resolver.resolve("VPN.Example.COM.")).toEqual(["198.51.100.10", "2001:db8::10"]);
    expect(cache.data["vpn.example.com"]).toEqual(["198.51.100.10", "2001:db8::10"]);
    expect(onChange).toHaveBeenCalledTimes(1);
    await resolver.resolve("vpn.example.com");
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it("falls back to remembered addresses when the lookup fails", async () => {
    const cache = memoryCache({ "vpn.example.com": ["198.51.100.10"] });
    const resolver = new HostResolver({ cache, dnsBlocked: () => false, lookup: failingLookup() });
    expect(await resolver.resolve("vpn.example.com")).toEqual(["198.51.100.10"]);
  });

  it("does not wait for DNS while the kill switch blocks it and addresses are known", async () => {
    const lookup = failingLookup();
    const cache = memoryCache({ "vpn.example.com": ["198.51.100.10"] });
    const resolver = new HostResolver({ cache, dnsBlocked: () => true, lookup });
    expect(await resolver.resolve("vpn.example.com")).toEqual(["198.51.100.10"]);
    expect(lookup).not.toHaveBeenCalled();
  });

  it("gives up on a hanging lookup after the timeout", async () => {
    const resolver = new HostResolver({
      cache: memoryCache({ "vpn.example.com": ["198.51.100.10"] }),
      dnsBlocked: () => false,
      lookup: () => new Promise<string[]>(() => undefined),
      timeoutMs: 20,
    });
    expect(await resolver.resolve("vpn.example.com")).toEqual(["198.51.100.10"]);
  });

  it("keeps older addresses next to new ones, newest first, capped", async () => {
    const cache = memoryCache({ "vpn.example.com": ["198.51.100.1", "198.51.100.2", "198.51.100.3"] });
    const resolver = new HostResolver({ cache, dnsBlocked: () => false, lookup: async () => ["198.51.100.9", "198.51.100.2"] });
    const result = await resolver.resolve("vpn.example.com");
    expect(result).toEqual(["198.51.100.9", "198.51.100.2", "198.51.100.1", "198.51.100.3"].slice(0, MAX_CACHED_ADDRESSES));
  });

  it("explains a blocked, unknown host in German", async () => {
    const resolver = new HostResolver({ cache: memoryCache(), dnsBlocked: () => true, lookup: failingLookup() });
    expect(await resolver.resolve("vpn.example.com")).toEqual([]);
    const error = await resolver.require("vpn.example.com").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(UnresolvedHostError);
    expect((error as UnresolvedHostError).dnsBlocked).toBe(true);
    expect((error as Error).message).toContain("Kill Switch");
  });
});

describe("pinnedLookup", () => {
  const lookup = pinnedLookup("api.mantel.test", async () => ["192.0.2.7", "2001:db8::7"]);
  const call = (host: string, options: Parameters<typeof lookup>[1]) =>
    new Promise<{ address: unknown; family?: number }>((resolve, reject) =>
      lookup(host, options, (error, address, family) => (error ? reject(error) : resolve({ address, family }))),
    );

  it("answers the API host from the pinned addresses", async () => {
    expect(await call("api.mantel.test", {})).toEqual({ address: "192.0.2.7", family: 4 });
    expect(await call("API.mantel.test", { family: 6 })).toEqual({ address: "2001:db8::7", family: 6 });
    expect((await call("api.mantel.test", { all: true })).address).toEqual([
      { address: "192.0.2.7", family: 4 },
      { address: "2001:db8::7", family: 6 },
    ]);
  });

  it("leaves every other name to the system resolver", async () => {
    const result = await call("localhost", { family: 4 });
    expect(result.address).toBe("127.0.0.1");
  });
});

describe("pinned connections", () => {
  const fixtures = path.join(__dirname, "fixtures", "tls");
  const ca = readFileSync(path.join(fixtures, "ca.pem"), "utf8");
  let plain: http.Server;
  let secure: https.Server;
  const seen: Array<{ host?: string; servername?: string | false | null }> = [];
  const json = (response: http.ServerResponse) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end("[]");
  };

  beforeAll(async () => {
    plain = http.createServer((request, response) => {
      seen.push({ host: request.headers.host });
      json(response);
    });
    secure = https.createServer(
      { cert: readFileSync(path.join(fixtures, "server.pem")), key: readFileSync(path.join(fixtures, "server-key.pem")) },
      (request, response) => {
        seen.push({ host: request.headers.host, servername: (request.socket as TLSSocket).servername });
        json(response);
      },
    );
    await new Promise<void>((resolve) => plain.listen(0, "127.0.0.1", resolve));
    await new Promise<void>((resolve) => secure.listen(0, "127.0.0.1", resolve));
  });
  afterAll(() => {
    plain.close();
    secure.close();
    tls.setDefaultCACertificates(tls.getCACertificates("bundled"));
  });

  const port = (server: http.Server | https.Server) => (server.address() as AddressInfo).port;
  const toLoopback = async () => ["127.0.0.1"];

  it("connects to the pinned address but keeps the host name in the Host header", async () => {
    const api = new ApiClient(() => `http://api.mantel.test:${port(plain)}`, () => null, toLoopback);
    expect(await api.nodes()).toEqual([]);
    expect(seen.at(-1)?.host).toBe(`api.mantel.test:${port(plain)}`);
  });

  it("turns a blocked, unknown API host into a clear message", async () => {
    const api = new ApiClient(
      () => "https://api.mantel.test",
      () => null,
      async (host) => {
        throw new UnresolvedHostError(host, true);
      },
    );
    await expect(api.nodes()).rejects.toMatchObject({ code: "network", message: expect.stringContaining("Kill Switch") });
  });

  it("still validates the certificate against the host name (untrusted CA is refused)", async () => {
    const url = new URL(`https://api.mantel.test:${port(secure)}/`);
    await expect(
      httpRequest(url, { method: "GET", headers: {}, timeoutMs: 5_000, maxBytes: 1024, lookup: pinnedLookup("api.mantel.test", toLoopback) }),
    ).rejects.toMatchObject({ code: expect.stringMatching(/CERT|SIGNED|ISSUER|VERIFY/) });
  });

  it("uses SNI and checks the name once the CA is trusted", async () => {
    tls.setDefaultCACertificates([...tls.getCACertificates("bundled"), ca]);
    const good = new URL(`https://api.mantel.test:${port(secure)}/`);
    const response = await httpRequest(good, {
      method: "GET",
      headers: {},
      timeoutMs: 5_000,
      maxBytes: 1024,
      lookup: pinnedLookup("api.mantel.test", toLoopback),
    });
    expect(response.status).toBe(200);
    expect(seen.at(-1)).toEqual({ host: `api.mantel.test:${port(secure)}`, servername: "api.mantel.test" });

    const wrong = new URL(`https://other.mantel.test:${port(secure)}/`);
    await expect(
      httpRequest(wrong, { method: "GET", headers: {}, timeoutMs: 5_000, maxBytes: 1024, lookup: pinnedLookup("other.mantel.test", toLoopback) }),
    ).rejects.toMatchObject({ code: "ERR_TLS_CERT_ALTNAME_INVALID" });
  });
});

describe.runIf(process.env.MANTEL_NET_TEST === "1")("pinned TLS against a real HTTPS host", () => {
  it("connects to a resolved IP with the original host name and a valid certificate", async () => {
    const { lookup } = await import("node:dns/promises");
    const [entry] = await lookup("example.com", { all: true, family: 4 });
    const response = await httpRequest(new URL("https://example.com/"), {
      method: "GET",
      headers: {},
      timeoutMs: 10_000,
      maxBytes: 1024 * 1024,
      lookup: pinnedLookup("example.com", async () => [entry!.address]),
    });
    expect(response.status).toBe(200);
    await expect(
      httpRequest(new URL("https://example.com/"), {
        method: "GET",
        headers: {},
        timeoutMs: 10_000,
        maxBytes: 1024 * 1024,
        lookup: pinnedLookup("example.com", async () => ["8.8.8.8"]),
      }),
    ).rejects.toMatchObject({ code: "ERR_TLS_CERT_ALTNAME_INVALID" });
  });
});
