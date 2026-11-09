import { randomBytes } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import path from "node:path";
import { LocalizedError } from "../../../shared/core/i18n";
import { IDENTITY } from "../flavor";
import { writeLockedFile } from "../system/acl";
import { programDataDirectory } from "../system/environment";
import { POWERSHELL, run } from "../system/exec";
import { FIREWALL_GROUP, type FirewallRule } from "./rules";

export type ProfileBackup = {
  Name: "Domain" | "Private" | "Public";
  Enabled: "True" | "False" | "NotConfigured";
  DefaultOutboundAction: "Allow" | "Block" | "NotConfigured";
  DefaultInboundAction: "Allow" | "Block" | "NotConfigured";
};

const PROFILE_NAMES = new Set(["Domain", "Private", "Public"]);
const BOOL_VALUES = new Set(["True", "False", "NotConfigured"]);
const ACTION_VALUES = new Set(["Allow", "Block", "NotConfigured"]);
const BACKUP_FILE = IDENTITY.firewallBackupFile;
const SPEC_FILE = IDENTITY.firewallSpecFile;
const MAX_ENV_SPEC = 30_000;

export const ENABLE_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$group = $env:MANTEL_FW_GROUP",
  "$json = if ($env:MANTEL_FW_SPEC_FILE) { Get-Content -Raw -Encoding UTF8 -LiteralPath $env:MANTEL_FW_SPEC_FILE } else { $env:MANTEL_FW_SPEC }",
  "$spec = $json | ConvertFrom-Json",
  "foreach ($rule in $spec.rules) {",
  "  $params = @{ Name = $rule.name; DisplayName = $group; Group = $group; Description = $rule.key; Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'; Enabled = 'True'; Protocol = $rule.protocol; RemoteAddress = [string[]]@($rule.remoteAddress) }",
  "  if (@($rule.localAddress).Count -gt 0) { $params.LocalAddress = [string[]]@($rule.localAddress) }",
  "  if (@($rule.remotePort).Count -gt 0) { $params.RemotePort = [string[]]@($rule.remotePort) }",
  "  New-NetFirewallRule @params | Out-Null",
  "}",
  "Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Where-Object { -not $_.Name.StartsWith($spec.prefix) } | Remove-NetFirewallRule",
  "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
  "Write-Output 'ok'",
].join("\n");

const BACKUP_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$rows = Get-NetFirewallProfile -PolicyStore PersistentStore | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled; DefaultOutboundAction = [string]$_.DefaultOutboundAction; DefaultInboundAction = [string]$_.DefaultInboundAction } }",
  "ConvertTo-Json -InputObject @($rows) -Compress",
].join("\n");

const DISABLE_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$group = $env:MANTEL_FW_GROUP",
  "Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
  "& (Join-Path $env:SystemRoot 'System32\\netsh.exe') advfirewall firewall delete rule \"name=$group\" | Out-Null",
  "if ($env:MANTEL_FW_BACKUP) {",
  "  foreach ($entry in ($env:MANTEL_FW_BACKUP | ConvertFrom-Json)) {",
  "    Set-NetFirewallProfile -Name $entry.Name -Enabled $entry.Enabled -DefaultOutboundAction $entry.DefaultOutboundAction -DefaultInboundAction $entry.DefaultInboundAction",
  "  }",
  "}",
  "Write-Output 'ok'",
].join("\n");

const COUNT_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "Write-Output (@(Get-NetFirewallRule -Group $env:MANTEL_FW_GROUP -ErrorAction SilentlyContinue).Count)",
].join("\n");

async function powershell(script: string, env: Record<string, string>): Promise<string> {
  const result = await run(
    POWERSHELL(),
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    { timeoutMs: 120_000, env: { MANTEL_FW_GROUP: FIREWALL_GROUP, ...env } },
  );
  if (result.code !== 0) {
    throw new LocalizedError("firewallCommand", { details: result.stderr.replace(/\s+/g, " ").trim().slice(0, 400) });
  }
  return result.stdout.trim();
}

export function parseProfileBackup(text: string): ProfileBackup[] {
  const parsed: unknown = JSON.parse(text);
  if (!Array.isArray(parsed)) throw new LocalizedError("firewallBackupInvalid");
  return parsed.map((entry) => {
    const record = entry as Record<string, unknown>;
    const name = String(record.Name);
    const enabled = String(record.Enabled);
    const outbound = String(record.DefaultOutboundAction);
    const inbound = String(record.DefaultInboundAction);
    if (!PROFILE_NAMES.has(name) || !BOOL_VALUES.has(enabled) || !ACTION_VALUES.has(outbound) || !ACTION_VALUES.has(inbound)) {
      throw new LocalizedError("firewallBackupUnexpected");
    }
    return {
      Name: name as ProfileBackup["Name"],
      Enabled: enabled as ProfileBackup["Enabled"],
      DefaultOutboundAction: outbound as ProfileBackup["DefaultOutboundAction"],
      DefaultInboundAction: inbound as ProfileBackup["DefaultInboundAction"],
    };
  });
}

function backupPath(): string {
  return path.win32.join(programDataDirectory(), BACKUP_FILE);
}

async function readBackup(): Promise<ProfileBackup[] | null> {
  try {
    return parseProfileBackup(await readFile(backupPath(), "utf8"));
  } catch {
    return null;
  }
}

const SAFE_VALUE = /^[0-9a-fA-F:.-]+$/;

export function serializeRules(rules: readonly FirewallRule[], prefix: string): string {
  const named = rules.map((rule, index) => {
    for (const value of [...rule.remoteAddress, ...rule.localAddress, ...rule.remotePort]) {
      if (!SAFE_VALUE.test(value)) throw new LocalizedError("firewallInvalidValue", { value });
    }
    return { ...rule, name: `${prefix}${String(index).padStart(2, "0")}` };
  });
  return JSON.stringify({ prefix, rules: named });
}

export async function enableFirewallKillSwitch(rules: readonly FirewallRule[]): Promise<void> {
  if (rules.length === 0) throw new LocalizedError("firewallNoRules");
  const existingBackup = await readBackup();
  if (!existingBackup) {
    const snapshot = await powershell(BACKUP_SCRIPT, {});
    parseProfileBackup(snapshot);
    await writeLockedFile(programDataDirectory(), BACKUP_FILE, snapshot, { setOwner: true });
  }
  const prefix = `${IDENTITY.firewallRulePrefix}${randomBytes(4).toString("hex")}-`;
  const spec = serializeRules(rules, prefix);
  if (spec.length <= MAX_ENV_SPEC) {
    await powershell(ENABLE_SCRIPT, { MANTEL_FW_SPEC: spec });
    return;
  }
  const specPath = await writeLockedFile(programDataDirectory(), SPEC_FILE, spec, { setOwner: true });
  try {
    await powershell(ENABLE_SCRIPT, { MANTEL_FW_SPEC_FILE: specPath });
  } finally {
    await rm(specPath, { force: true }).catch(() => undefined);
  }
}

export async function disableFirewallKillSwitch(): Promise<void> {
  const backup = await readBackup();
  await powershell(DISABLE_SCRIPT, backup ? { MANTEL_FW_BACKUP: JSON.stringify(backup) } : {});
  await rm(backupPath(), { force: true });
}

export async function firewallRuleCount(): Promise<number> {
  const output = await powershell(COUNT_SCRIPT, {});
  const count = Number.parseInt(output, 10);
  return Number.isFinite(count) ? count : 0;
}
