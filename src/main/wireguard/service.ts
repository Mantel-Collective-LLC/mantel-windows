import { LocalizedError } from "../../../shared/core/i18n";
import { IDENTITY } from "../flavor";
import { run, system32 } from "../system/exec";
import type { WireGuardPaths } from "../system/environment";
import { parseScQuery, parseWgShow, SERVICE_DOES_NOT_EXIST, type InterfaceStatus, type ServiceState } from "./parse";

export const TUNNEL_NAME = IDENTITY.tunnelName;
export const SERVICE_NAME = `WireGuardTunnel$${TUNNEL_NAME}`;

export type ServiceQuery = { exists: false } | { exists: true; state: ServiceState | null };

const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export async function queryService(): Promise<ServiceQuery> {
  const result = await run(system32("sc.exe"), ["query", SERVICE_NAME], { timeoutMs: 10_000 });
  if (result.code === SERVICE_DOES_NOT_EXIST) return { exists: false };
  if (result.code !== 0) return { exists: true, state: null };
  return { exists: true, state: parseScQuery(result.stdout) };
}

export async function waitForService(
  predicate: (query: ServiceQuery) => boolean,
  timeoutMs: number,
): Promise<ServiceQuery> {
  const deadline = Date.now() + timeoutMs;
  let last = await queryService();
  while (!predicate(last) && Date.now() < deadline) {
    await wait(300);
    last = await queryService();
  }
  return last;
}

function describeFailure(stdout: string, stderr: string, code: number): string {
  const detail = `${stderr} ${stdout}`.replace(/\s+/g, " ").trim();
  return detail.length > 0 ? `${detail} (Code ${code})` : `Code ${code}`;
}

export async function installTunnel(paths: WireGuardPaths, configPath: string): Promise<void> {
  const existing = await queryService();
  if (existing.exists) await uninstallTunnel(paths);
  const result = await run(paths.wireguardExe, ["/installtunnelservice", configPath], { timeoutMs: 60_000 });
  if (result.code !== 0) {
    throw new LocalizedError("tunnelInstallFailed", { details: describeFailure(result.stdout, result.stderr, result.code) });
  }
}

export async function uninstallTunnel(paths: WireGuardPaths): Promise<void> {
  const before = await queryService();
  if (!before.exists) return;
  const result = await run(paths.wireguardExe, ["/uninstalltunnelservice", TUNNEL_NAME], { timeoutMs: 60_000 });
  if (result.code !== 0) {
    throw new LocalizedError("tunnelUninstallFailed", { details: describeFailure(result.stdout, result.stderr, result.code) });
  }
  const after = await waitForService((query) => !query.exists, 20_000);
  if (after.exists) throw new LocalizedError("serviceRemoveTimeout");
}

export async function readInterfaceStatus(paths: WireGuardPaths): Promise<InterfaceStatus | null> {
  const show = async (what: string) => {
    const result = await run(paths.wgExe, ["show", TUNNEL_NAME, what], { timeoutMs: 10_000 });
    return result.code === 0 ? result.stdout : null;
  };
  const [publicKey, latestHandshakes, transfer, endpoints] = await Promise.all(
    ["public-key", "latest-handshakes", "transfer", "endpoints"].map(show),
  );
  if (publicKey == null || latestHandshakes == null) return null;
  return parseWgShow({ publicKey, latestHandshakes, transfer: transfer ?? "", endpoints: endpoints ?? "" });
}
