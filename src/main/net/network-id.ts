import { networkInterfaces, type NetworkInterfaceInfo } from "node:os";

export function networkFingerprint(
  interfaces: NodeJS.Dict<NetworkInterfaceInfo[]>,
  tunnelAddresses: readonly string[],
): string {
  const tunnel = new Set(tunnelAddresses.map((address) => address.split("/")[0]));
  const entries: string[] = [];
  for (const [name, infos] of Object.entries(interfaces)) {
    for (const info of infos ?? []) {
      if (info.internal || info.family !== "IPv4" || tunnel.has(info.address)) continue;
      entries.push(`${name}=${info.cidr ?? info.address}`);
    }
  }
  return entries.sort().join(",");
}

export function currentNetwork(tunnelAddresses: readonly string[]): string {
  return networkFingerprint(networkInterfaces(), tunnelAddresses);
}
