import { describe, expect, it } from "vitest";
import { parseProfileBackup, serializeRules } from "../src/main/firewall/apply";
import { collectHostAllowances, nodeEndpointsOf } from "../src/main/firewall/hosts";
import { buildKillSwitchRules, portComplement, type FirewallRule } from "../src/main/firewall/rules";
import { HostResolver } from "../src/main/net/resolve";
import { parseAddress, parseCidr } from "../src/main/net/ip";

function parseEntry(entry: string) {
  if (entry.includes("-")) {
    const [start = "", end = ""] = entry.split("-");
    const from = parseAddress(start);
    const to = parseAddress(end);
    return from && to ? { family: from.family, start: from.value, end: to.value } : null;
  }
  return parseCidr(entry);
}

function inList(list: string[], address: string): boolean {
  if (list.length === 0) return true;
  const parsed = parseAddress(address);
  if (!parsed) return false;
  return list.some((entry) => {
    const range = parseEntry(entry);
    return range !== null && range.family === parsed.family && parsed.value >= range.start && parsed.value <= range.end;
  });
}

function portMatches(rule: FirewallRule, port: number): boolean {
  if (rule.remotePort.length === 0) return true;
  return rule.remotePort.some((entry) => {
    const [from, to] = entry.split("-").map(Number);
    return port >= (from ?? 0) && port <= (to ?? from ?? 0);
  });
}

function blocked(
  rules: FirewallRule[],
  packet: { local: string; remote: string; protocol: "TCP" | "UDP" | "ICMPv4" | "ICMPv6"; port?: number },
): boolean {
  return rules.some((rule) => {
    if (rule.protocol !== "Any" && rule.protocol !== packet.protocol) return false;
    if (!inList(rule.remoteAddress, packet.remote)) return false;
    if (!inList(rule.localAddress, packet.local)) return false;
    if (packet.port !== undefined && (packet.protocol === "TCP" || packet.protocol === "UDP") && !portMatches(rule, packet.port)) return false;
    return true;
  });
}

const physical = "192.168.178.23";
const physical6 = "2a02:8070:1:2::23";
const tunnel = "10.64.0.7";
const tunnel6 = "fd00:6d61:6e74::7";

const base = {
  hosts: [
    { address: "198.51.100.7", tcpPorts: [], udpPorts: [51820] },
    { address: "10.10.10.114", tcpPorts: [3001], udpPorts: [] },
  ],
  tunnelAddresses: [`${tunnel}/32`, `${tunnel6}/128`],
};

describe("always-on kill switch rules without LAN", () => {
  const rules = buildKillSwitchRules({ ...base, allowLan: false });

  it("blocks the internet outside the tunnel", () => {
    expect(blocked(rules, { local: physical, remote: "1.1.1.1", protocol: "TCP", port: 443 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "8.8.8.8", protocol: "UDP", port: 53 })).toBe(true);
    expect(blocked(rules, { local: physical6, remote: "2606:4700::1111", protocol: "TCP", port: 443 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "192.168.178.1", protocol: "UDP", port: 53 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "192.168.178.40", protocol: "TCP", port: 445 })).toBe(true);
  });

  it("lets tunnel traffic, the WireGuard endpoint, the API and DHCP through", () => {
    expect(blocked(rules, { local: tunnel, remote: "1.1.1.1", protocol: "TCP", port: 443 })).toBe(false);
    expect(blocked(rules, { local: tunnel6, remote: "2606:4700::1111", protocol: "TCP", port: 443 })).toBe(false);
    expect(blocked(rules, { local: tunnel, remote: "10.64.0.1", protocol: "UDP", port: 53 })).toBe(false);
    expect(blocked(rules, { local: physical, remote: "198.51.100.7", protocol: "UDP", port: 51820 })).toBe(false);
    expect(blocked(rules, { local: physical, remote: "10.10.10.114", protocol: "TCP", port: 3001 })).toBe(false);
    expect(blocked(rules, { local: physical, remote: "255.255.255.255", protocol: "UDP", port: 67 })).toBe(false);
    expect(blocked(rules, { local: physical, remote: "192.168.178.1", protocol: "UDP", port: 67 })).toBe(false);
    expect(blocked(rules, { local: "fe80::1", remote: "ff02::1:2", protocol: "UDP", port: 547 })).toBe(false);
    expect(blocked(rules, { local: "fe80::1", remote: "ff02::1", protocol: "ICMPv6" })).toBe(false);
  });

  it("only opens the exact ports of allowed hosts", () => {
    expect(blocked(rules, { local: physical, remote: "198.51.100.7", protocol: "TCP", port: 22 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "198.51.100.7", protocol: "UDP", port: 53 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "10.10.10.114", protocol: "TCP", port: 22 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "10.10.10.114", protocol: "UDP", port: 3001 })).toBe(true);
  });

  it("blocks everything when no tunnel address is known yet", () => {
    const fresh = buildKillSwitchRules({ hosts: base.hosts, tunnelAddresses: [], allowLan: false });
    expect(blocked(fresh, { local: tunnel, remote: "1.1.1.1", protocol: "TCP", port: 443 })).toBe(true);
  });
});

describe("kill switch rules with LAN access", () => {
  const rules = buildKillSwitchRules({ ...base, allowLan: true });

  it("allows LAN services but not LAN DNS", () => {
    expect(blocked(rules, { local: physical, remote: "192.168.178.40", protocol: "TCP", port: 445 })).toBe(false);
    expect(blocked(rules, { local: physical, remote: "239.255.255.250", protocol: "UDP", port: 1900 })).toBe(false);
    expect(blocked(rules, { local: physical, remote: "192.168.178.1", protocol: "UDP", port: 53 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "192.168.178.1", protocol: "TCP", port: 53 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "1.1.1.1", protocol: "TCP", port: 443 })).toBe(true);
  });

  it("never emits IPv6 addresses New-NetFirewallRule rejects (unspecified, loopback, multicast)", () => {
    const rejected = (value: string) => {
      const [start = "", end = start] = value.split("-");
      return [start, end].some((edge) => edge === "::" || edge === "::1" || edge.toLowerCase().startsWith("ff"));
    };
    for (const allowLan of [false, true]) {
      const withLoopbackApi = buildKillSwitchRules({
        ...base,
        hosts: [...base.hosts, { address: "::1", tcpPorts: [3000], udpPorts: [] }, { address: "127.0.0.1", tcpPorts: [3000], udpPorts: [] }],
        allowLan,
      });
      for (const rule of withLoopbackApi) {
        for (const value of [...rule.remoteAddress, ...rule.localAddress]) {
          expect(rejected(value), `${rule.key}: ${value}`).toBe(false);
        }
      }
      expect(blocked(withLoopbackApi, { local: physical6, remote: "2001:db8::1", protocol: "TCP", port: 443 })).toBe(true);
      expect(blocked(withLoopbackApi, { local: physical6, remote: "::2", protocol: "TCP", port: 443 })).toBe(true);
    }
  });

  it("keeps multicast and broadcast out of the LAN DNS rules (Windows rejects them)", () => {
    const dns = rules.filter((rule) => rule.key.includes("lan-dns"));
    expect(dns).toHaveLength(4);
    for (const rule of dns) {
      for (const value of rule.remoteAddress) {
        expect(value).not.toMatch(/^ff|^22[4-9]\.|^23\d\.|^255\.255\.255\.255/);
      }
    }
    expect(blocked(rules, { local: physical6, remote: "fd12::1", protocol: "UDP", port: 53 })).toBe(true);
    expect(blocked(rules, { local: physical6, remote: "fe80::1", protocol: "TCP", port: 53 })).toBe(true);
    expect(blocked(rules, { local: physical6, remote: "ff02::fb", protocol: "UDP", port: 5353 })).toBe(false);
  });
});

describe("rule serialization", () => {
  it("names rules with a generation prefix and refuses unexpected characters", () => {
    const rules = buildKillSwitchRules({ ...base, allowLan: false });
    const json = JSON.parse(serializeRules(rules, "Mantel-KS-abcd-")) as { rules: Array<{ name: string }> };
    expect(json.rules[0]?.name).toBe("Mantel-KS-abcd-00");
    expect(() =>
      serializeRules([{ key: "x", protocol: "Any", remoteAddress: ["1.1.1.1'; Remove-Item"], localAddress: [], remotePort: [] }], "p-"),
    ).toThrow();
  });

  it("computes port complements", () => {
    expect(portComplement([67, 547])).toEqual(["1-66", "68-546", "548-65535"]);
    expect(portComplement([1, 65535])).toEqual(["2-65534"]);
    expect(portComplement([51820])).toEqual(["1-51819", "51821-65535"]);
  });

  it("validates the firewall profile backup", () => {
    const backup = parseProfileBackup(
      '[{"Name":"Domain","Enabled":"True","DefaultOutboundAction":"NotConfigured","DefaultInboundAction":"NotConfigured"}]',
    );
    expect(backup[0]?.Name).toBe("Domain");
    expect(() => parseProfileBackup('[{"Name":"Domain; calc","Enabled":"True","DefaultOutboundAction":"Allow","DefaultInboundAction":"Block"}]')).toThrow();
  });
});

describe("exceptions for the API and all node endpoints", () => {
  const nodes = [
    { id: "de-fra", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true },
    { id: "nl-ams", city: "Amsterdam", country: "NL", endpointHost: "203.0.113.20", endpointPort: 51820, online: true },
    { id: "se-sto", city: "Stockholm", country: "SE", endpointHost: "2001:db8:5::20", endpointPort: 51821, online: false },
    { id: "ch-zrh", city: "Zürich", country: "CH", endpointHost: "zrh.nodes.example", endpointPort: 4500, online: true },
    { id: "de-fra2", city: "Frankfurt", country: "DE", endpointHost: "198.51.100.7", endpointPort: 51820, online: true },
  ];

  const blockedResolver = () =>
    new HostResolver({
      cache: {
        read: (host) => ({ "vpn.example.com": ["192.0.2.80"], "zrh.nodes.example": ["192.0.2.90"] })[host] ?? [],
        write: () => undefined,
      },
      dnsBlocked: () => true,
      lookup: async () => {
        throw new Error("ENOTFOUND");
      },
    });

  async function lockdownRules(baseUrl = "https://vpn.example.com") {
    const { hosts, unresolvedApiHost } = await collectHostAllowances({
      resolver: blockedResolver(),
      baseUrl,
      nodeEndpoints: nodeEndpointsOf(nodes),
      currentEndpoint: null,
    });
    return { rules: buildKillSwitchRules({ hosts, tunnelAddresses: [], allowLan: false }), unresolvedApiHost };
  }

  it("deduplicates node endpoints", () => {
    expect(nodeEndpointsOf(nodes)).toHaveLength(4);
  });

  it("keeps the API exception from remembered addresses when the lookup fails", async () => {
    const { rules, unresolvedApiHost } = await lockdownRules();
    expect(unresolvedApiHost).toBeNull();
    expect(blocked(rules, { local: physical, remote: "192.0.2.80", protocol: "TCP", port: 443 })).toBe(false);
    expect(blocked(rules, { local: physical, remote: "192.0.2.80", protocol: "TCP", port: 80 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "192.0.2.80", protocol: "UDP", port: 443 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "1.1.1.1", protocol: "UDP", port: 53 })).toBe(true);
  });

  it("reports an API host without any known address and still blocks everything else", async () => {
    const { rules, unresolvedApiHost } = await lockdownRules("https://unknown.example.com");
    expect(unresolvedApiHost).toBe("unknown.example.com");
    expect(blocked(rules, { local: physical, remote: "1.1.1.1", protocol: "TCP", port: 443 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "203.0.113.20", protocol: "UDP", port: 51820 })).toBe(false);
  });

  it("allows every node endpoint only on its own UDP port", async () => {
    const { rules } = await lockdownRules();
    for (const [remote, port] of [
      ["198.51.100.7", 51820],
      ["203.0.113.20", 51820],
      ["2001:db8:5::20", 51821],
      ["192.0.2.90", 4500],
    ] as const) {
      const local = remote.includes(":") ? physical6 : physical;
      expect(blocked(rules, { local, remote, protocol: "UDP", port }), `${remote} udp ${port}`).toBe(false);
      expect(blocked(rules, { local, remote, protocol: "UDP", port: port + 1 }), `${remote} udp other`).toBe(true);
      expect(blocked(rules, { local, remote, protocol: "TCP", port }), `${remote} tcp`).toBe(true);
      expect(blocked(rules, { local, remote, protocol: "TCP", port: 443 }), `${remote} tcp 443`).toBe(true);
    }
    expect(blocked(rules, { local: physical6, remote: "2001:db8:5::20", protocol: "UDP", port: 51820 })).toBe(true);
  });

  it("also allows the latency echo port of nodes that have one, nothing else", async () => {
    const withEcho = nodes.map((node) => (node.id === "nl-ams" ? { ...node, pingPort: 51821 } : node));
    const endpoints = nodeEndpointsOf(withEcho);
    expect(endpoints.find((endpoint) => endpoint.host === "203.0.113.20")?.pingPort).toBe(51821);
    expect(endpoints.find((endpoint) => endpoint.host === "198.51.100.7")?.pingPort).toBeUndefined();
    const { hosts } = await collectHostAllowances({ resolver: blockedResolver(), baseUrl: "https://vpn.example.com", nodeEndpoints: endpoints, currentEndpoint: null });
    const rules = buildKillSwitchRules({ hosts, tunnelAddresses: [], allowLan: false });
    expect(blocked(rules, { local: physical, remote: "203.0.113.20", protocol: "UDP", port: 51821 })).toBe(false);
    expect(blocked(rules, { local: physical, remote: "203.0.113.20", protocol: "UDP", port: 51822 })).toBe(true);
    expect(blocked(rules, { local: physical, remote: "198.51.100.7", protocol: "UDP", port: 51821 })).toBe(true);
  });

  it("groups hosts with the same ports into one rule pair", async () => {
    const { rules } = await lockdownRules();
    const hostRules = rules.filter((rule) => rule.key.startsWith("v4-hosts"));
    expect(hostRules).toHaveLength(6);
    const many = Array.from({ length: 200 }, (_, index) => ({
      address: `203.0.${Math.floor(index / 250)}.${(index % 250) + 1}`,
      tcpPorts: [],
      udpPorts: [51820],
    }));
    const big = buildKillSwitchRules({ hosts: many, tunnelAddresses: ["10.64.0.7/32"], allowLan: false });
    expect(big.filter((rule) => rule.key.startsWith("v4-hosts"))).toHaveLength(2);
    expect(serializeRules(big, "Mantel-KS-abcdef01-").length).toBeLessThan(32_000);
  });
});
