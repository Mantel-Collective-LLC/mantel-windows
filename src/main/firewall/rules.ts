import {
  cidrRanges,
  complementRanges,
  formatRange,
  hostRange,
  mergeRanges,
  parseAddress,
  stripPrefix,
  subtractRanges,
  type Family,
  type IpRange,
} from "../net/ip";
import { IDENTITY } from "../flavor";
import { DHCP_SERVER_PORTS, DNS_PORT, LAN_V4, LAN_V6, LOOPBACK, NON_UNICAST } from "../net/ranges";

export const FIREWALL_GROUP = IDENTITY.firewallGroup;

export type FirewallProtocol = "Any" | "TCP" | "UDP" | "ICMPv4";

export type HostAllowance = {
  address: string;
  tcpPorts: number[];
  udpPorts: number[];
};

export type KillSwitchInput = {
  hosts: HostAllowance[];
  tunnelAddresses: string[];
  allowLan: boolean;
};

export type FirewallRule = {
  key: string;
  protocol: FirewallProtocol;
  remoteAddress: string[];
  localAddress: string[];
  remotePort: string[];
};

const FAMILIES: readonly Family[] = [4, 6];

function lanFor(family: Family): IpRange[] {
  return cidrRanges(family === 4 ? LAN_V4 : LAN_V6);
}

function loopbackFor(family: Family): IpRange[] {
  return cidrRanges(LOOPBACK).filter((range) => range.family === family);
}

export function portComplement(ports: readonly number[]): string[] {
  const sorted = [...new Set(ports)].filter((port) => port >= 1 && port <= 65535).sort((a, b) => a - b);
  const ranges: string[] = [];
  let cursor = 1;
  for (const port of sorted) {
    if (port > cursor) ranges.push(port - 1 === cursor ? String(cursor) : `${cursor}-${port - 1}`);
    cursor = port + 1;
  }
  if (cursor <= 65535) ranges.push(cursor === 65535 ? "65535" : `${cursor}-65535`);
  return ranges;
}

function normalizePorts(ports: readonly number[]): number[] {
  return [...new Set(ports)].filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535).sort((a, b) => a - b);
}

function mergeHosts(hosts: readonly HostAllowance[], family: Family): HostAllowance[] {
  const byAddress = new Map<string, HostAllowance>();
  for (const host of hosts) {
    const parsed = parseAddress(host.address);
    if (!parsed || parsed.family !== family) continue;
    const key = parsed.value.toString();
    const existing = byAddress.get(key);
    byAddress.set(key, {
      address: host.address,
      tcpPorts: [...(existing?.tcpPorts ?? []), ...host.tcpPorts],
      udpPorts: [...(existing?.udpPorts ?? []), ...host.udpPorts],
    });
  }
  return [...byAddress.values()];
}

function inside(ranges: readonly IpRange[], address: string): boolean {
  const parsed = parseAddress(address);
  if (!parsed) return false;
  return ranges.some(
    (range) => range.family === parsed.family && parsed.value >= range.start && parsed.value <= range.end,
  );
}

const WINDOWS_REJECTED = cidrRanges(["::/127", "ff00::/8"]);

function format(ranges: readonly IpRange[]): string[] {
  return mergeRanges(subtractRanges(ranges, WINDOWS_REJECTED)).map(formatRange);
}

function acceptedByWindows(address: string): boolean {
  const range = hostRange(address);
  return range !== null && format([range]).length > 0;
}

function rulesForFamily(family: Family, input: KillSwitchInput): FirewallRule[] {
  const lan = lanFor(family);
  const hosts = mergeHosts(input.hosts, family);
  const hostRanges = hosts.map((host) => hostRange(host.address)).filter((range): range is IpRange => range !== null);
  const tunnel = input.tunnelAddresses
    .map((address) => hostRange(stripPrefix(address)))
    .filter((range): range is IpRange => range !== null && range.family === family);
  const localAddress = tunnel.length > 0 ? format(complementRanges(family, tunnel)) : [];
  const tag = `v${family}`;
  const rules: FirewallRule[] = [];

  const publicRanges = complementRanges(family, [...loopbackFor(family), ...lan, ...hostRanges]);
  rules.push({ key: `${tag}-public`, protocol: "Any", remoteAddress: format(publicRanges), localAddress, remotePort: [] });

  const groups = new Map<string, { tcpPorts: number[]; udpPorts: number[]; addresses: string[] }>();
  for (const host of hosts) {
    if (input.allowLan && inside(lan, host.address)) continue;
    if (inside(loopbackFor(family), host.address) || !acceptedByWindows(host.address)) continue;
    const tcpPorts = normalizePorts(host.tcpPorts);
    const udpPorts = normalizePorts(host.udpPorts);
    const signature = `${tcpPorts.join(",")}/${udpPorts.join(",")}`;
    const group = groups.get(signature) ?? { tcpPorts, udpPorts, addresses: [] };
    group.addresses.push(host.address);
    groups.set(signature, group);
  }
  [...groups.values()].forEach((group, index) => {
    rules.push({
      key: `${tag}-hosts${index}-tcp`,
      protocol: "TCP",
      remoteAddress: group.addresses,
      localAddress,
      remotePort: group.tcpPorts.length > 0 ? portComplement(group.tcpPorts) : [],
    });
    rules.push({
      key: `${tag}-hosts${index}-udp`,
      protocol: "UDP",
      remoteAddress: group.addresses,
      localAddress,
      remotePort: group.udpPorts.length > 0 ? portComplement(group.udpPorts) : [],
    });
  });

  if (!input.allowLan) {
    const lanWithoutHosts = format(subtractRanges(lan, hostRanges));
    rules.push({ key: `${tag}-lan-tcp`, protocol: "TCP", remoteAddress: lanWithoutHosts, localAddress, remotePort: [] });
    rules.push({
      key: `${tag}-lan-udp`,
      protocol: "UDP",
      remoteAddress: lanWithoutHosts,
      localAddress,
      remotePort: portComplement(DHCP_SERVER_PORTS),
    });
    if (family === 4) {
      rules.push({ key: `${tag}-lan-icmp`, protocol: "ICMPv4", remoteAddress: lanWithoutHosts, localAddress, remotePort: [] });
    }
  }

  if (input.allowLan) {
    const lanUnicast = format(subtractRanges(lan, cidrRanges(NON_UNICAST)));
    const dnsPort = [String(DNS_PORT)];
    rules.push({ key: `${tag}-lan-dns-udp`, protocol: "UDP", remoteAddress: lanUnicast, localAddress, remotePort: dnsPort });
    rules.push({ key: `${tag}-lan-dns-tcp`, protocol: "TCP", remoteAddress: lanUnicast, localAddress, remotePort: dnsPort });
  }

  return rules.filter((rule) => rule.remoteAddress.length > 0);
}

export function buildKillSwitchRules(input: KillSwitchInput): FirewallRule[] {
  return FAMILIES.flatMap((family) => rulesForFamily(family, input));
}
