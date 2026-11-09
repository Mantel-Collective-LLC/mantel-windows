import { randomBytes } from "node:crypto";
import { lstat, mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { LocalizedError } from "../../../shared/core/i18n";
import { POWERSHELL, run, system32 } from "./exec";

export const SYSTEM_SID = "S-1-5-18";
export const ADMINISTRATORS_SID = "S-1-5-32-544";
const ALLOWED_SIDS = new Set([SYSTEM_SID, ADMINISTRATORS_SID]);

export type AclEntry = { sid: string; rights: string; inherited: boolean; type: string };

async function icacls(args: readonly string[]): Promise<void> {
  const result = await run(system32("icacls.exe"), args, { timeoutMs: 30_000 });
  if (result.code !== 0) {
    const details = `${result.stdout.trim()} ${result.stderr.trim()}`.trim();
    throw new LocalizedError("icaclsFailed", { code: result.code, details });
  }
}

async function assertNotReparsePoint(target: string): Promise<void> {
  const stats = await lstat(target);
  if (stats.isSymbolicLink()) throw new LocalizedError("pathIsLink", { path: target });
}

export async function lockDirectory(directory: string, options: { setOwner: boolean }): Promise<void> {
  await mkdir(directory, { recursive: true });
  await assertNotReparsePoint(directory);
  if (options.setOwner) {
    await icacls([directory, "/setowner", `*${ADMINISTRATORS_SID}`, "/T", "/Q"]);
  }
  await icacls([
    directory,
    "/inheritance:r",
    "/grant:r",
    `*${SYSTEM_SID}:(OI)(CI)F`,
    `*${ADMINISTRATORS_SID}:(OI)(CI)F`,
    "/Q",
  ]);
}

export async function lockFile(file: string): Promise<void> {
  await assertNotReparsePoint(file);
  await icacls([file, "/inheritance:r", "/grant:r", `*${SYSTEM_SID}:F`, `*${ADMINISTRATORS_SID}:F`, "/Q"]);
}

const READ_ACL_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$acl = Get-Acl -LiteralPath $env:MANTEL_ACL_TARGET",
  "$rows = foreach ($rule in $acl.Access) {",
  "  $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value",
  "  [pscustomobject]@{ sid = $sid; rights = [string]$rule.FileSystemRights; inherited = [bool]$rule.IsInherited; type = [string]$rule.AccessControlType }",
  "}",
  "ConvertTo-Json -InputObject @($rows) -Compress",
].join("\n");

export async function readAcl(target: string): Promise<AclEntry[]> {
  const result = await run(
    POWERSHELL(),
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", READ_ACL_SCRIPT],
    { timeoutMs: 30_000, env: { MANTEL_ACL_TARGET: target } },
  );
  if (result.code !== 0) throw new LocalizedError("aclUnreadable", { details: result.stderr.trim() });
  const parsed: unknown = JSON.parse(result.stdout.trim() || "[]");
  if (!Array.isArray(parsed)) return [];
  return parsed.map((entry) => {
    const record = entry as Record<string, unknown>;
    return {
      sid: String(record.sid),
      rights: String(record.rights),
      inherited: Boolean(record.inherited),
      type: String(record.type),
    };
  });
}

export function isLockedAcl(entries: readonly AclEntry[]): boolean {
  if (entries.length === 0) return false;
  return entries.every((entry) => ALLOWED_SIDS.has(entry.sid) && !entry.inherited);
}

export async function assertLocked(target: string): Promise<void> {
  const entries = await readAcl(target);
  if (!isLockedAcl(entries)) {
    const holders = entries.map((entry) => entry.sid).join(", ");
    throw new LocalizedError("aclNotLocked", { path: target, holders });
  }
}

export async function writeLockedFile(
  directory: string,
  name: string,
  content: string,
  options: { setOwner: boolean },
): Promise<string> {
  await lockDirectory(directory, options);
  await assertLocked(directory);
  const finalPath = path.win32.join(directory, name);
  const temporary = path.win32.join(directory, `.${name}.${randomBytes(6).toString("hex")}.tmp`);
  await writeFile(temporary, "", { flag: "wx" });
  try {
    await lockFile(temporary);
    await assertLocked(temporary);
    await writeFile(temporary, content, { encoding: "utf8", flag: "r+" });
    await rename(temporary, finalPath);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
  return finalPath;
}
