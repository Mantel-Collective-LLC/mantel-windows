import { access } from "node:fs/promises";
import { run } from "../../system/exec";
import { VpnError } from "../../vpn-error";

const OSASCRIPT = "/usr/bin/osascript";

export const INSTALL_SCRIPT = [
  "on run argv",
  'do shell script (quoted form of (item 1 of argv)) & " install --flavor " & (quoted form of (item 2 of argv)) & " --uid " & (quoted form of (item 3 of argv)) with prompt (item 4 of argv) with administrator privileges',
  "end run",
];

export function installArguments(input: { helperBinary: string; flavor: "prod" | "debug"; uid: number; prompt: string }): string[] {
  if (!Number.isInteger(input.uid) || input.uid < 500) throw new VpnError("helperInstallFailed", "internal", { details: "no user id" });
  if (!input.helperBinary.startsWith("/") || /[\0\n]/.test(input.helperBinary)) {
    throw new VpnError("helperInstallFailed", "internal", { details: "helper path" });
  }
  return [...INSTALL_SCRIPT.flatMap((line) => ["-e", line]), input.helperBinary, input.flavor, String(input.uid), input.prompt.replace(/[\0\n]/g, " ")];
}

export async function installHelper(input: { helperBinary: string; flavor: "prod" | "debug"; uid: number; prompt: string }): Promise<void> {
  const args = installArguments(input);
  try {
    await access(input.helperBinary);
  } catch {
    throw new VpnError("helperInstallFailed", "internal", { details: "mantel-helper missing in the app" });
  }
  const result = await run(OSASCRIPT, args, { timeoutMs: 5 * 60_000 });
  if (result.code === 0) return;
  if (/\(-128\)|User canceled|abgebrochen/i.test(result.stderr)) throw new VpnError("helperInstallCanceled", "invalid");
  throw new VpnError("helperInstallFailed", "internal", { details: result.stderr.replace(/\s+/g, " ").trim().slice(0, 300) });
}
