import { execFile } from "node:child_process";
import path from "node:path";

export type ExecResult = {
  code: number;
  stdout: string;
  stderr: string;
};

export function systemRoot(): string {
  const root = process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows";
  return path.win32.isAbsolute(root) ? root : "C:\\Windows";
}

export function system32(binary: string): string {
  return path.win32.join(systemRoot(), "System32", binary);
}

export const POWERSHELL = (): string =>
  path.win32.join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

export function run(
  file: string,
  args: readonly string[],
  options: { timeoutMs?: number; input?: string; env?: Record<string, string> } = {},
): Promise<ExecResult> {
  return new Promise((resolve) => {
    const child = execFile(
      file,
      [...args],
      {
        windowsHide: true,
        shell: false,
        timeout: options.timeoutMs ?? 30_000,
        maxBuffer: 4 * 1024 * 1024,
        encoding: "utf8",
        env: { ...process.env, NODE_OPTIONS: undefined, ...options.env },
      },
      (error, stdout, stderr) => {
        const failure = error as (NodeJS.ErrnoException & { code?: number | string }) | null;
        const code = failure === null ? 0 : typeof failure.code === "number" ? failure.code : -1;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) || (failure?.message ?? "") });
      },
    );
    if (options.input !== undefined) {
      child.stdin?.end(options.input);
    }
  });
}
