import os from "node:os";
import type { AutostartState, QuitAction, TunnelPhase } from "../../shared/core/contract";
import { POWERSHELL, run, system32, type ExecResult } from "./system/exec";

export const AUTOSTART_FLAG = "--autostart";

export type LoginLauncher = {
  supported: boolean;
  isEnabled: () => Promise<boolean>;
  setEnabled: (enabled: boolean) => Promise<void>;
};

export async function autostartState(launcher: LoginLauncher): Promise<AutostartState> {
  if (!launcher.supported) return { supported: false, enabled: false };
  return { supported: true, enabled: await launcher.isEnabled().catch(() => false) };
}

function xmlText(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function autostartTaskXml(input: { exe: string; user: string; description: string }): string {
  const user = xmlText(input.user);
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>${xmlText(input.description)}</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>${user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>${user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>"${xmlText(input.exe)}"</Command><Arguments>${AUTOSTART_FLAG}</Arguments></Exec></Actions>
</Task>`;
}

const REGISTER_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "Register-ScheduledTask -TaskName $env:MANTEL_TASK -TaskPath '\\' -Xml $env:MANTEL_TASK_XML -Force | Out-Null",
  "Write-Output 'ok'",
].join("\n");

type Runner = (file: string, args: readonly string[], options?: { timeoutMs?: number; env?: Record<string, string> }) => Promise<ExecResult>;

export function currentWindowsUser(): string {
  const name = os.userInfo().username;
  const domain = process.env.USERDOMAIN;
  return domain ? `${domain}\\${name}` : name;
}

export function windowsLauncher(input: {
  packaged: boolean;
  exe: string;
  taskName: string;
  description: string;
  user?: () => string;
  runner?: Runner;
}): LoginLauncher {
  const runner = input.runner ?? run;
  const schtasks = system32("schtasks.exe");
  const isEnabled = async () => (await runner(schtasks, ["/Query", "/TN", input.taskName], { timeoutMs: 15_000 })).code === 0;
  return {
    supported: input.packaged,
    isEnabled,
    setEnabled: async (enabled) => {
      if (enabled) {
        const xml = autostartTaskXml({ exe: input.exe, user: (input.user ?? currentWindowsUser)(), description: input.description });
        const result = await runner(POWERSHELL(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", REGISTER_SCRIPT], {
          timeoutMs: 60_000,
          env: { MANTEL_TASK: input.taskName, MANTEL_TASK_XML: xml },
        });
        if (result.code !== 0) throw new Error(result.stderr.replace(/\s+/g, " ").trim().slice(0, 300) || "Register-ScheduledTask");
        return;
      }
      await runner(schtasks, ["/Delete", "/TN", input.taskName, "/F"], { timeoutMs: 15_000 });
      if (await isEnabled()) throw new Error(`schtasks /Delete ${input.taskName}`);
    },
  };
}

export type LoginItemApp = {
  getLoginItemSettings: () => { openAtLogin: boolean };
  setLoginItemSettings: (settings: { openAtLogin: boolean }) => void;
};

export function macLauncher(app: LoginItemApp, packaged: boolean): LoginLauncher {
  return {
    supported: packaged,
    isEnabled: async () => app.getLoginItemSettings().openAtLogin,
    setEnabled: async (enabled) => app.setLoginItemSettings({ openAtLogin: enabled }),
  };
}

export async function connectAtLogin(deps: {
  ready: () => { loggedIn: boolean; nodeId: string | null; tunnelActive: boolean };
  connect: (nodeId: string) => Promise<unknown>;
  retryable: (error: unknown) => boolean;
  sleep?: (ms: number) => Promise<void>;
  attempts?: number;
  delayMs?: number;
}): Promise<boolean> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const attempts = deps.attempts ?? 6;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const state = deps.ready();
    if (!state.loggedIn || !state.nodeId || state.tunnelActive) return false;
    try {
      await deps.connect(state.nodeId);
      return true;
    } catch (error) {
      if (!deps.retryable(error) || attempt === attempts) return false;
    }
    await sleep(deps.delayMs ?? 15_000);
  }
  return false;
}

export function quitPlan(phase: TunnelPhase, remembered: QuitAction | undefined, obfuscated = false): "quit" | "ask" | "keep" | "disconnect" {
  if (phase === "disconnected") return "quit";
  if (obfuscated && remembered === "keep") return "ask";
  if (phase === "connected" && remembered && remembered !== "ask") return remembered;
  return "ask";
}
