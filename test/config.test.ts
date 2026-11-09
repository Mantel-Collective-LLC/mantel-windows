import { describe, expect, it } from "vitest";
import { buildTunnelConfig, parseEndpoint, planRouting, redactConfig, type ServerTunnelConfig } from "../src/main/wireguard/config";
import { generateKeyPair } from "../src/main/wireguard/keys";

const server: ServerTunnelConfig = {
  address: ["10.64.0.7/32", "fd00:6d61:6e74::7/128"],
  dns: ["10.64.0.1", "fd00:6d61:6e74::1"],
  serverPublicKey: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
  presharedKey: "XgPRso34lnrSAx8nJtdj1/zlF7CoNj7B64LPElYdOGs=",
  endpoint: "198.51.100.7:51820",
  allowedIps: ["0.0.0.0/0", "::/0"],
  mtu: 1420,
};

const privateKey = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const endpoint = { host: "198.51.100.7", port: 51820 };

describe("routing plan", () => {
  it("uses exactly 0.0.0.0/0, ::/0 when the kill switch is on and LAN is off", () => {
    const plan = planRouting({ killSwitch: true, lanAccess: false }, ["10.64.0.1"]);
    expect(plan.allowedIps).toEqual(["0.0.0.0/0", "::/0"]);
    expect(plan.leakProtection).toBe("wireguard");
    expect(plan.firewallRequired).toBe(false);
  });

  it("avoids /0 without kill switch so WireGuard does not install its firewall", () => {
    const plan = planRouting({ killSwitch: false, lanAccess: false }, ["10.64.0.1"]);
    expect(plan.allowedIps).toEqual(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
    expect(plan.leakProtection).toBe("none");
  });

  it("excludes LAN, re-adds tunnel DNS and requires the firewall with kill switch plus LAN", () => {
    const plan = planRouting({ killSwitch: true, lanAccess: true }, ["10.64.0.1"]);
    expect(plan.firewallRequired).toBe(true);
    expect(plan.leakProtection).toBe("firewall");
    expect(plan.allowedIps).toContain("10.64.0.1/32");
    expect(plan.allowedIps.some((cidr) => cidr.endsWith("/0"))).toBe(false);
    expect(plan.allowedIps).not.toContain("192.168.0.0/16");
    expect(plan.allowedIps.some((cidr) => cidr.includes(":"))).toBe(true);
  });
});

describe("tunnel config", () => {
  it("renders a wg-quick config with kill switch routes", () => {
    const config = buildTunnelConfig({ privateKey, server, endpoint, settings: { killSwitch: true, lanAccess: false, ipv6: true } });
    expect(config.text).toBe(
      [
        "[Interface]",
        `PrivateKey = ${privateKey}`,
        "Address = 10.64.0.7/32, fd00:6d61:6e74::7/128",
        "DNS = 10.64.0.1, fd00:6d61:6e74::1",
        "MTU = 1420",
        "",
        "[Peer]",
        "PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
        "PresharedKey = XgPRso34lnrSAx8nJtdj1/zlF7CoNj7B64LPElYdOGs=",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "Endpoint = 198.51.100.7:51820",
        "PersistentKeepalive = 25",
        "",
      ].join("\r\n"),
    );
    expect(config.text).not.toMatch(/PreUp|PostUp|PreDown|PostDown|Table/);
  });

  it("drops IPv6 addresses and DNS but still routes ::/0 when IPv6 is off", () => {
    const config = buildTunnelConfig({ privateKey, server, endpoint, settings: { killSwitch: true, lanAccess: false, ipv6: false } });
    expect(config.addresses).toEqual(["10.64.0.7/32"]);
    expect(config.dns).toEqual(["10.64.0.1"]);
    expect(config.allowedIps).toContain("::/0");
  });

  it("brackets IPv6 endpoints and refuses unresolved hostnames", () => {
    const config = buildTunnelConfig({ privateKey, server, endpoint: { host: "2001:db8::31", port: 51820 }, settings: { killSwitch: true, lanAccess: false, ipv6: true } });
    expect(config.text).toContain("Endpoint = [2001:db8::31]:51820");
    expect(() =>
      buildTunnelConfig({ privateKey, server, endpoint: { host: "node.example", port: 51820 }, settings: { killSwitch: true, lanAccess: false, ipv6: true } }),
    ).toThrow();
  });

  it("refuses keys that could inject lines", () => {
    expect(() =>
      buildTunnelConfig({ privateKey: `${privateKey}\nPostUp = calc`, server, endpoint, settings: { killSwitch: true, lanAccess: false, ipv6: true } }),
    ).toThrow();
  });

  it("uses a freshly generated key pair", () => {
    const keys = generateKeyPair();
    const config = buildTunnelConfig({ privateKey: keys.privateKey, server, endpoint, settings: { killSwitch: true, lanAccess: false, ipv6: true } });
    expect(config.text).toContain(keys.privateKey);
    expect(redactConfig(config.text)).not.toContain(keys.privateKey);
  });

  it("quantum-resistant tunnel: no Endpoint in the file (inert until phase 1), routes unchanged", () => {
    const classic = buildTunnelConfig({ privateKey, server, endpoint, settings: { killSwitch: true, lanAccess: false, ipv6: true } });
    const pq = buildTunnelConfig({ privateKey, server, endpoint, settings: { killSwitch: true, lanAccess: false, ipv6: true }, postQuantum: true });
    expect(pq.text).not.toMatch(/^Endpoint/m);
    expect(pq.text).toContain("PersistentKeepalive = 25");
    expect(pq.text).toContain(`PresharedKey = ${server.presharedKey}`);
    expect(pq.text.replace(/\r\n/g, "\n")).toBe(classic.text.replace(/\r\n/g, "\n").replace("Endpoint = 198.51.100.7:51820\n", ""));
    expect(pq.allowedIps).toEqual(classic.allowedIps);
    expect(pq.endpoint).toEqual(endpoint);
  });

  it("quantum-resistant tunnel: 10.8.255.1 is routed through the tunnel in every routing mode", () => {
    const covers = (allowedIps: string[]) =>
      allowedIps.some((cidr) => ["0.0.0.0/0", "0.0.0.0/1", "10.8.255.1/32"].includes(cidr));
    for (const killSwitch of [true, false]) {
      for (const lanAccess of [true, false]) {
        const settings = { killSwitch, lanAccess, ipv6: false };
        const pq = buildTunnelConfig({ privateKey, server, endpoint, settings, postQuantum: true });
        expect(covers(pq.allowedIps), JSON.stringify(settings)).toBe(true);
        if (lanAccess) {
          expect(pq.allowedIps).toContain("10.8.255.1/32");
          expect(buildTunnelConfig({ privateKey, server, endpoint, settings }).allowedIps).not.toContain("10.8.255.1/32");
        }
      }
    }
  });

  it("parses endpoints", () => {
    expect(parseEndpoint("198.51.100.7:51820")).toEqual({ host: "198.51.100.7", port: 51820 });
    expect(parseEndpoint("[2001:db8::1]:443")).toEqual({ host: "2001:db8::1", port: 443 });
    expect(parseEndpoint("zrh.mantel.net:51820")).toEqual({ host: "zrh.mantel.net", port: 51820 });
    expect(parseEndpoint("1.2.3.4:70000")).toBeNull();
    expect(parseEndpoint("a b:1")).toBeNull();
  });
});
