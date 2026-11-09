import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildKillSwitchRules } from "../src/main/firewall/rules";
import { ENABLE_SCRIPT, serializeRules } from "../src/main/firewall/apply";
describe.runIf(process.platform === "win32")("New-NetFirewallRule parameter binding", () => {
it("accepts every generated rule with -WhatIf (nothing is applied)", () => {
  const rules = buildKillSwitchRules({ hosts: [{ address: "198.51.100.7", tcpPorts: [], udpPorts: [51820] }, { address: "10.10.10.114", tcpPorts: [3001], udpPorts: [] }], tunnelAddresses: ["10.64.0.7/32", "fd00:6d61:6e74::7/128"], allowLan: false });
  const spec = serializeRules(rules, "Mantel-KS-test-");
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "$group = 'Mantel Kill Switch'",
    "$spec = $env:MANTEL_FW_SPEC | ConvertFrom-Json",
    "$n = 0",
    "foreach ($rule in $spec.rules) {",
    "  $params = @{ Name = $rule.name; DisplayName = $group; Group = $group; Description = $rule.key; Direction = 'Outbound'; Action = 'Block'; Profile = 'Any'; Enabled = 'True'; Protocol = $rule.protocol; RemoteAddress = [string[]]@($rule.remoteAddress) }",
    "  if (@($rule.localAddress).Count -gt 0) { $params.LocalAddress = [string[]]@($rule.localAddress) }",
    "  if (@($rule.remotePort).Count -gt 0) { $params.RemotePort = [string[]]@($rule.remotePort) }",
    "  New-NetFirewallRule @params -WhatIf | Out-Null; $n++",
    "}",
    "Write-Output \"rules=$n\"",
  ].join("\n");
  const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { env: { ...process.env, MANTEL_FW_SPEC: spec }, encoding: "utf8" });
  expect(out).toContain(`rules=${rules.length}`);
});
});

describe.runIf(process.platform === "win32")("large rule sets via spec file", () => {
  it("reads the spec from a file and binds many grouped endpoint addresses (-WhatIf)", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "mantel-fw-"));
    try {
      const hosts = Array.from({ length: 800 }, (_, i) => ({
        address: `${((i * 37) % 200) + 11}.${(i * 91) % 250}.${i % 250}.${((i * 13) % 250) + 1}`,
        tcpPorts: [],
        udpPorts: [51820],
      }));
      const rules = buildKillSwitchRules({ hosts, tunnelAddresses: ["10.64.0.7/32"], allowLan: false });
      const spec = serializeRules(rules, "Mantel-KS-test-");
      expect(spec.length).toBeGreaterThan(32_767);
      const file = path.join(dir, "firewall-rules.json");
      writeFileSync(file, spec, "utf8");
      const script = ENABLE_SCRIPT.split("\n")
        .filter((line) => !line.includes("Remove-NetFirewallRule") && !line.includes("Set-NetFirewallProfile"))
        .join("\n")
        .replace("New-NetFirewallRule @params | Out-Null", "New-NetFirewallRule @params -WhatIf | Out-Null; $n++")
        .replace("Write-Output 'ok'", "Write-Output \"rules=$n\"");
      const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", `$n = 0\n${script}`], {
        env: { ...process.env, MANTEL_FW_GROUP: "Mantel Kill Switch", MANTEL_FW_SPEC_FILE: file },
        encoding: "utf8",
      });
      expect(out).toContain(`rules=${rules.length}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
