import type { WifiSecurity } from "../../../shared/core/contract";
import { run, system32 } from "../system/exec";

const OPEN_AUTH = /^(open|offen)$/i;
const NO_CIPHER = /^(none|keine)$/i;

export function parseNetshInterfaces(text: string): WifiSecurity {
  let found: WifiSecurity = "none";
  for (const block of text.split(/^\s*Name\s*:/m).slice(1)) {
    const auth = block.match(/^\s*(?:Authentication|Authentifizierung)\s*:\s*(.+?)\s*$/im)?.[1];
    if (!auth) continue;
    const cipher = block.match(/^\s*(?:Cipher|Verschl\S*sselung)\s*:\s*(.+?)\s*$/im)?.[1];
    if (OPEN_AUTH.test(auth) && cipher === undefined) return "unknown";
    if (OPEN_AUTH.test(auth) && NO_CIPHER.test(cipher ?? "")) return "open";
    found = "secured";
  }
  return found;
}

export function parseAirportProfile(json: string): WifiSecurity {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    return "unknown";
  }
  const sections = (data as { SPAirPortDataType?: unknown }).SPAirPortDataType;
  if (!Array.isArray(sections)) return "unknown";
  let found: WifiSecurity = "none";
  for (const section of sections) {
    const interfaces = (section as { spairport_airport_interfaces?: unknown }).spairport_airport_interfaces;
    if (!Array.isArray(interfaces)) continue;
    for (const entry of interfaces) {
      const network = (entry as { spairport_current_network_information?: unknown }).spairport_current_network_information;
      if (!network || typeof network !== "object") continue;
      const mode = (network as { spairport_security_mode?: unknown }).spairport_security_mode;
      if (mode === "spairport_security_mode_none") return "open";
      found = typeof mode === "string" ? "secured" : "unknown";
    }
  }
  return found;
}

export async function readWindowsWifi(): Promise<WifiSecurity> {
  const result = await run(system32("netsh.exe"), ["wlan", "show", "interfaces"], { timeoutMs: 5_000 });
  return result.code === 0 ? parseNetshInterfaces(result.stdout) : "none";
}

export async function readMacWifi(): Promise<WifiSecurity> {
  const result = await run("/usr/sbin/system_profiler", ["SPAirPortDataType", "-json"], { timeoutMs: 15_000 });
  return result.code === 0 ? parseAirportProfile(result.stdout) : "unknown";
}
