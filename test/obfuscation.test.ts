import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { accountSchema, deviceSchema, nodeSchema } from "../src/main/api/schemas";
import { collectHostAllowances, nodeEndpointsOf } from "../src/main/firewall/hosts";
import { buildKillSwitchRules } from "../src/main/firewall/rules";
import { cidrRanges, mergeRanges, parseAddress } from "../src/main/net/ip";
import { networkFingerprint } from "../src/main/net/network-id";
import { parseEvent, sidecarRelay } from "../src/main/obfs/relay";
import { allowedIpsBypassing, buildTunnelConfig, type ServerTunnelConfig } from "../src/main/wireguard/config";

const PIN = "q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJq80=";
const server: ServerTunnelConfig = {
  address: ["10.64.0.7/32", "fd00:6d61:6e74::7/128"],
  dns: ["10.64.0.1", "fd00:6d61:6e74::1"],
  serverPublicKey: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
  endpoint: "198.51.100.7:51820",
  allowedIps: ["0.0.0.0/0", "::/0"],
};
const privateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

const covers = (cidrs: string[], address: string) => {
  const parsed = parseAddress(address)!;
  return cidrRanges(cidrs).some((range) => range.family === parsed.family && parsed.value >= range.start && parsed.value <= range.end);
};

describe("AllowedIPs of an obfuscated tunnel", () => {
  it("everything except the node, no /0 left (v4 and v6 node)", () => {
    for (const node of ["198.51.100.7", "2001:db8::7"]) {
      const routes = allowedIpsBypassing(["0.0.0.0/0", "::/0"], node);
      expect(routes).not.toContain("0.0.0.0/0");
      expect(routes).not.toContain("::/0");
      expect(covers(routes, node)).toBe(false);
      for (const other of ["1.1.1.1", "198.51.100.6", "198.51.100.8", "255.255.255.255", "2606:4700::1111", "::1"]) {
        if (other !== node) expect(covers(routes, other), other).toBe(true);
      }
      const total = mergeRanges(cidrRanges(routes)).reduce((sum, range) => sum + (range.end - range.start + 1n), 0n);
      expect(total).toBe(2n ** 32n + 2n ** 128n - 1n);
    }
  });

  it("LAN mode and the split default keep their gaps and lose the node too", () => {
    const lan = allowedIpsBypassing(["0.0.0.0/5", "8.0.0.0/7", "192.169.0.0/16", "198.51.100.0/24"], "198.51.100.7");
    expect(covers(lan, "198.51.100.7")).toBe(false);
    expect(covers(lan, "192.168.1.1")).toBe(false);
    expect(covers(lan, "198.51.100.8")).toBe(true);
  });

  it("buildTunnelConfig: endpoint 127.0.0.1, keepalive 25, the full tunnel's leak protection moves to the firewall", () => {
    const tunnel = buildTunnelConfig({
      privateKey,
      server,
      endpoint: { host: "127.0.0.1", port: 41000 },
      settings: { killSwitch: true, lanAccess: false, ipv6: true },
      bypassHost: "198.51.100.7",
    });
    expect(tunnel.text).toMatch(/^Endpoint = 127\.0\.0\.1:41000$/m);
    expect(tunnel.text).toMatch(/^PersistentKeepalive = 25$/m);
    expect(tunnel.allowedIps).not.toContain("0.0.0.0/0");
    expect(tunnel).toMatchObject({ leakProtection: "firewall", firewallRequired: true });
    const plain = buildTunnelConfig({ privateKey, server, endpoint: { host: "198.51.100.7", port: 51820 }, settings: { killSwitch: false, lanAccess: false, ipv6: false } });
    const obfuscated = buildTunnelConfig({
      privateKey,
      server,
      endpoint: { host: "127.0.0.1", port: 41000 },
      settings: { killSwitch: false, lanAccess: false, ipv6: false },
      bypassHost: "198.51.100.7",
    });
    expect(obfuscated.leakProtection).toBe(plain.leakProtection);
    expect(obfuscated.firewallRequired).toBe(false);
  });
});

describe("kill switch exception for the relay", () => {
  const nodes = [
    { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true, obfuscation: { version: 1, port: 443, pin: PIN } },
    { id: "ams", city: "Amsterdam", country: "NL", endpointHost: "203.0.113.20", endpointPort: 51820, online: true },
  ];

  it("TCP only to the offering node and only on its obfuscation port; nothing else opens", async () => {
    const endpoints = nodeEndpointsOf(nodes);
    expect(endpoints.find((entry) => entry.host === "198.51.100.7")?.tcpPort).toBe(443);
    expect(endpoints.find((entry) => entry.host === "203.0.113.20")?.tcpPort).toBeUndefined();
    const { hosts } = await collectHostAllowances({
      resolver: { resolve: async (host: string) => (host === "vpn.example.com" ? ["192.0.2.80"] : [host]) },
      baseUrl: "https://vpn.example.com",
      nodeEndpoints: endpoints,
      currentEndpoint: null,
    });
    const rules = buildKillSwitchRules({ hosts, tunnelAddresses: ["10.64.0.7/32"], allowLan: false });
    const fra = rules.find((rule) => rule.protocol === "TCP" && rule.remoteAddress.includes("198.51.100.7"));
    expect(fra?.remotePort).toEqual(["1-442", "444-65535"]);
    const ams = rules.find((rule) => rule.protocol === "TCP" && rule.remoteAddress.includes("203.0.113.20"));
    expect(ams?.remotePort).toEqual([]);
  });
});

describe("API schemas", () => {
  it("obfuscation of a node: only version 1 with a valid port and pin, anything else counts as not offered", () => {
    const base = { id: "fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true };
    expect(nodeSchema.parse({ ...base, obfuscation: { version: 1, port: 443, pin: PIN } }).obfuscation).toEqual({ version: 1, port: 443, pin: PIN });
    for (const obfuscation of [{ version: 2, port: 443, pin: PIN }, { version: 1, port: 0, pin: PIN }, { version: 1, port: 443, pin: "short" }, "yes"]) {
      expect(nodeSchema.parse({ ...base, obfuscation }).obfuscation).toBeUndefined();
    }
    expect(nodeSchema.parse(base).obfuscation).toBeUndefined();
  });

  it("device token: optional, header-safe characters only", () => {
    const device = { id: "dev1", name: "Windows AB12", nodeId: "fra", ipv4: "10.8.0.2", createdOn: "2026-11-05" };
    expect(deviceSchema.parse({ ...device, obfsToken: "abc_DEF-123.~+/=" }).obfsToken).toBe("abc_DEF-123.~+/=");
    expect(deviceSchema.parse({ ...device, obfsToken: "a b\r\nX: 1" }).obfsToken).toBeUndefined();
    expect(deviceSchema.parse(device).obfsToken).toBeUndefined();
    const account = accountSchema.parse({
      id: "acc1",
      paidUntil: "2030-01-01T00:00:00.000Z",
      settings: { killSwitch: true, lanAccess: false, ipv6: false, dns: { ads: false, trackers: false, malware: false, gambling: false, adult: false, social: false } },
      devices: [{ ...device, obfsToken: "tok-1" }],
    });
    expect(account.devices[0]?.obfsToken).toBe("tok-1");
  });
});

describe("relay process (mantel-obfs protocol)", () => {
  it("parses only the expected events", () => {
    expect(parseEvent('{"event":"listening","port":41000}')).toEqual({ event: "listening", port: 41000 });
    expect(parseEvent('{"event":"state","state":"retrying","reason":"pin","error":"x"}')).toEqual({ event: "state", state: "retrying", reason: "pin" });
    expect(parseEvent('{"event":"state","state":"connected"}')).toEqual({ event: "state", state: "connected" });
    for (const line of ["", "nope", "[]", '{"event":"listening","port":0}', '{"event":"listening","port":70000}', '{"event":"state","state":"weird"}']) {
      expect(parseEvent(line), line).toBeNull();
    }
  });

  const directory = mkdtempSync(path.join(tmpdir(), "mantel-relay-"));
  afterAll(() => rmSync(directory, { recursive: true, force: true }));
  const script = path.join(directory, "fake-obfs.cjs");
  writeFileSync(
    script,
    [
      "const lines = require('node:readline').createInterface({ input: process.stdin });",
      "lines.once('line', (line) => {",
      "  const config = JSON.parse(line);",
      "  if (config.server === 'bad') { console.log(JSON.stringify({ event: 'error', error: 'invalid server' })); process.exit(2); }",
      "  console.log(JSON.stringify({ event: 'listening', port: 41234 }));",
      "  console.log(JSON.stringify({ event: 'state', state: config.token === 'refused' ? 'retrying' : 'connected', reason: 'rejected' }));",
      "});",
      "process.stdin.on('end', () => process.exit(0));",
      "process.argv.includes('--die') && setTimeout(() => process.exit(1), 300);",
    ].join("\n"),
  );

  it("passes the config over stdin (not argv), resolves with the port, reports states, stops when asked", async () => {
    const start = sidecarRelay(process.execPath, [script]);
    const relay = await start({ server: "198.51.100.7:443", pin: PIN, token: "secret-token" });
    expect(relay.port).toBe(41234);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(relay.state()).toBe("connected");
    expect(relay.failure()).toBeNull();
    let exits = 0;
    relay.onExit(() => exits++);
    relay.stop();
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(exits).toBe(0);

    const refused = await start({ server: "198.51.100.7:443", pin: PIN, token: "refused" });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(refused.failure()).toBe("rejected");
    refused.stop();
  });

  it("an unexpected exit is reported; a refused config or a missing binary is an error", async () => {
    const dying = await sidecarRelay(process.execPath, [script, "--die"])({ server: "198.51.100.7:443", pin: PIN, token: "t" });
    await new Promise<void>((resolve) => dying.onExit(resolve));
    await expect(sidecarRelay(process.execPath, [script])({ server: "bad", pin: PIN, token: "t" })).rejects.toThrow(/invalid server/);
    await expect(sidecarRelay(path.join(directory, "missing.exe"))({ server: "198.51.100.7:443", pin: PIN, token: "t" })).rejects.toThrow();
  });
});

describe("this network (Auto memory)", () => {
  it("physical IPv4 addresses only, without the tunnel's own, independent of order", () => {
    const wlan = { address: "192.168.1.20", netmask: "255.255.255.0", family: "IPv4" as const, mac: "00:00:00:00:00:01", internal: false, cidr: "192.168.1.20/24" };
    const loopback = { ...wlan, address: "127.0.0.1", cidr: "127.0.0.1/8", internal: true };
    const tunnel = { ...wlan, address: "10.8.0.2", cidr: "10.8.0.2/32" };
    const v6 = { ...wlan, family: "IPv6" as const, address: "fe80::1", cidr: "fe80::1/64", scopeid: 1 };
    const a = networkFingerprint({ WLAN: [wlan, v6], lo: [loopback], mantel: [tunnel] }, ["10.8.0.2/32"]);
    const b = networkFingerprint({ mantel: [tunnel], WLAN: [v6, wlan] }, ["10.8.0.2/32"]);
    expect(a).toBe("WLAN=192.168.1.20/24");
    expect(b).toBe(a);
    expect(networkFingerprint({ WLAN: [{ ...wlan, address: "192.168.2.20", cidr: "192.168.2.20/24" }] }, [])).not.toBe(a);
  });
});
