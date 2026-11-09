import { existsSync } from "node:fs";
import path from "node:path";
import { run, system32 } from "./exec";

export type WireGuardSource = "managed" | "system";

export type WireGuardPaths = {
  directory: string;
  wireguardExe: string;
  wgExe: string;
  source: WireGuardSource;
};

function programFilesCandidates(): string[] {
  const candidates = [process.env.ProgramW6432, process.env.ProgramFiles, "C:\\Program Files"];
  return [...new Set(candidates.filter((entry): entry is string => Boolean(entry) && path.win32.isAbsolute(entry ?? "")))];
}

function pathsIn(directory: string, source: WireGuardSource, exists: (file: string) => boolean): WireGuardPaths | null {
  const wireguardExe = path.win32.join(directory, "wireguard.exe");
  const wgExe = path.win32.join(directory, "wg.exe");
  return exists(wireguardExe) && exists(wgExe) ? { directory, wireguardExe, wgExe, source } : null;
}

export function detectWireGuard(exists: (file: string) => boolean = existsSync): WireGuardPaths | null {
  const managed = pathsIn(managedWireGuardDirectory(), "managed", exists);
  if (managed) return managed;
  for (const base of programFilesCandidates()) {
    const system = pathsIn(path.win32.join(base, "WireGuard"), "system", exists);
    if (system) return system;
  }
  return null;
}

let elevatedCache: boolean | null = null;

export async function isElevated(): Promise<boolean> {
  if (process.platform !== "win32") return false;
  if (elevatedCache !== null) return elevatedCache;
  const result = await run(system32("net.exe"), ["session"], { timeoutMs: 10_000 });
  elevatedCache = result.code === 0;
  return elevatedCache;
}

export function programDataDirectory(): string {
  const base = process.env.ProgramData;
  const root = base && path.win32.isAbsolute(base) ? base : "C:\\ProgramData";
  return path.win32.join(root, "Mantel");
}

export function managedWireGuardDirectory(): string {
  return path.win32.join(programDataDirectory(), "wireguard");
}
