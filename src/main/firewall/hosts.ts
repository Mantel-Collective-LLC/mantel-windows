import type { VpnNode } from "../../../shared/core/contract";
import { isIpLiteral } from "../net/ip";
import { normalizeHost, type HostResolver } from "../net/resolve";
import type { Endpoint } from "../wireguard/config";
import type { HostAllowance } from "./rules";

export type NodeEndpoint = {
  host: string;
  port: number;
  pingPort?: number;
  tcpPort?: number;
};

export const MAX_NODE_ENDPOINTS = 200;

export function nodeEndpointsOf(nodes: readonly VpnNode[]): NodeEndpoint[] {
  const seen = new Map<string, NodeEndpoint>();
  for (const node of nodes) {
    const endpoint: NodeEndpoint = { host: normalizeHost(node.endpointHost), port: node.endpointPort };
    if (endpoint.host.length === 0) continue;
    const key = `${endpoint.host}|${endpoint.port}`;
    const pingPort = node.pingPort ?? seen.get(key)?.pingPort;
    if (pingPort !== undefined && pingPort !== endpoint.port) endpoint.pingPort = pingPort;
    const tcpPort = node.obfuscation?.port ?? seen.get(key)?.tcpPort;
    if (tcpPort !== undefined) endpoint.tcpPort = tcpPort;
    seen.set(key, endpoint);
  }
  return [...seen.values()]
    .sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port)
    .slice(0, MAX_NODE_ENDPOINTS);
}

export function sameEndpoints(a: readonly NodeEndpoint[], b: readonly NodeEndpoint[]): boolean {
  return (
    a.length === b.length &&
    a.every(
      (entry, index) =>
        entry.host === b[index]?.host &&
        entry.port === b[index]?.port &&
        entry.pingPort === b[index]?.pingPort &&
        entry.tcpPort === b[index]?.tcpPort,
    )
  );
}

export async function collectHostAllowances(input: {
  resolver: Pick<HostResolver, "resolve">;
  baseUrl: string;
  nodeEndpoints: readonly NodeEndpoint[];
  currentEndpoint: Endpoint | null;
}): Promise<{ hosts: HostAllowance[]; unresolvedApiHost: string | null }> {
  const url = new URL(input.baseUrl);
  const apiPort = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  const apiHost = normalizeHost(url.hostname);
  const [apiAddresses = [], ...endpointAddresses] = await Promise.all([
    input.resolver.resolve(apiHost),
    ...input.nodeEndpoints.map((endpoint) => input.resolver.resolve(endpoint.host)),
  ]);
  const hosts: HostAllowance[] = apiAddresses.map((address) => ({ address, tcpPorts: [apiPort], udpPorts: [] }));
  input.nodeEndpoints.forEach((endpoint, index) => {
    const udpPorts = endpoint.pingPort ? [endpoint.port, endpoint.pingPort] : [endpoint.port];
    const tcpPorts = endpoint.tcpPort ? [endpoint.tcpPort] : [];
    for (const address of endpointAddresses[index] ?? []) hosts.push({ address, tcpPorts, udpPorts });
  });
  if (input.currentEndpoint && isIpLiteral(input.currentEndpoint.host)) {
    hosts.push({ address: input.currentEndpoint.host, tcpPorts: [], udpPorts: [input.currentEndpoint.port] });
  }
  return { hosts, unresolvedApiHost: apiAddresses.length === 0 ? apiHost : null };
}
