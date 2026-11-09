import { randomBytes } from "node:crypto";
import { open, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { assertLocked, lockDirectory } from "../system/acl";
import { run, type ExecResult } from "../system/exec";
import type { UapiDevice, UapiEntry, UapiPeer, WireGuardControl } from "./uapi";

export type WgRunner = (args: readonly string[]) => Promise<ExecResult>;

export function execWgRunner(wgExe: string, timeoutMs = 10_000): WgRunner {
  return (args) => run(wgExe, args, { timeoutMs });
}

export type WgFailure = "missing" | "access" | "no_tunnel" | "rejected" | "output";

export class WgExeError extends Error {
  constructor(
    readonly failure: WgFailure,
    readonly detail: string,
  ) {
    super(`wg.exe ${failure}: ${detail}`);
  }
}

const KEY_LIKE = [/[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=/g, /\b[0-9a-fA-F]{64}\b/g];

export function scrubWgOutput(text: string): string {
  let out = text;
  for (const pattern of KEY_LIKE) out = out.replace(pattern, "<key>");
  out = out.replace(/\s+/g, " ").trim();
  return out.length > 300 ? `${out.slice(0, 300)}…` : out;
}

export function classifyWgResult(result: ExecResult): WgExeError | null {
  if (result.code === 0) return null;
  const detail = scrubWgOutput(`${result.stderr} ${result.stdout}`) || `exit ${result.code}`;
  if (result.code === -1 && /ENOENT|EACCES|not recognized|cannot find the (file|path)/i.test(result.stderr)) {
    return new WgExeError("missing", detail);
  }
  if (/access is denied|permission denied|operation not permitted|EPERM|EACCES/i.test(detail)) return new WgExeError("access", detail);
  if (/no such (device|file)|cannot find|not found|does not exist|ENODEV|ENOENT/i.test(detail)) return new WgExeError("no_tunnel", detail);
  return new WgExeError("rejected", detail);
}

const B64 = Buffer.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
const SECRET_SUFFIX = ".key";

export function base64Line(bytes: Uint8Array): Buffer {
  const out = Buffer.alloc(Math.ceil(bytes.length / 3) * 4 + 1);
  let o = 0;
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out[o++] = B64[a >> 2]!;
    out[o++] = B64[((a & 3) << 4) | (b >> 4)]!;
    out[o++] = i + 1 < bytes.length ? B64[((b & 15) << 2) | (c >> 6)]! : 0x3d;
    out[o++] = i + 2 < bytes.length ? B64[c & 63]! : 0x3d;
  }
  out[o] = 0x0a;
  return out;
}

export type SecretFiles = {
  write: (secret: Uint8Array) => Promise<string>;
  remove: (file: string) => Promise<void>;
};

async function wipe(file: string): Promise<void> {
  try {
    const handle = await open(file, "r+");
    try {
      const { size } = await handle.stat();
      if (size > 0) await handle.write(Buffer.alloc(size), 0, size, 0);
      await handle.sync().catch(() => undefined);
    } finally {
      await handle.close();
    }
  } catch {
  }
  await rm(file, { force: true }).catch(() => undefined);
}

export async function sweepSecretFiles(directory: string): Promise<number> {
  let names: string[];
  try {
    names = await readdir(directory);
  } catch {
    return 0;
  }
  const stale = names.filter((name) => name.endsWith(SECRET_SUFFIX));
  await Promise.all(stale.map((name) => wipe(path.join(directory, name))));
  return stale.length;
}

async function lockSecretDirectory(directory: string): Promise<void> {
  await lockDirectory(directory, { setOwner: true });
  await assertLocked(directory);
}

export function lockedSecretFiles(directory: string, options: { lock?: (directory: string) => Promise<void> } = {}): SecretFiles {
  const lock = options.lock ?? lockSecretDirectory;
  let ready: Promise<void> | null = null;
  const prepare = () => {
    ready ??= (async () => {
      await lock(directory);
      await sweepSecretFiles(directory);
    })().catch((error: unknown) => {
      ready = null;
      throw error;
    });
    return ready;
  };
  return {
    async write(secret) {
      await prepare();
      const file = path.join(directory, `${randomBytes(12).toString("hex")}${SECRET_SUFFIX}`);
      const content = base64Line(secret);
      try {
        const handle = await open(file, "wx", 0o600);
        try {
          await handle.write(content, 0, content.length, 0);
        } finally {
          await handle.close();
        }
      } catch (error) {
        await wipe(file);
        throw error;
      } finally {
        content.fill(0);
      }
      return file;
    },
    remove: wipe,
  };
}

const TUNNEL_NAME = /^[A-Za-z0-9_=+.-]{1,32}$/;
const ENDPOINT = /^(?:\[[0-9A-Fa-f:.]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):[0-9]{1,5}$/;
const CIDR = /^[0-9A-Fa-f:.]{2,45}\/[0-9]{1,3}$/;
const KEY_B64 = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

function key32(name: string, value: UapiEntry[1]): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new WgExeError("rejected", `${name} must be 32 raw bytes`);
  return value;
}

function port(name: string, value: UapiEntry[1]): string {
  const text = String(value);
  if (!/^[0-9]{1,5}$/.test(text) || Number(text) > 65535) throw new WgExeError("rejected", `bad ${name}`);
  return text;
}

export async function wgSetArgs(
  tunnel: string,
  entries: readonly UapiEntry[],
  secretFile: (secret: Uint8Array) => Promise<string>,
): Promise<string[]> {
  if (!TUNNEL_NAME.test(tunnel)) throw new WgExeError("rejected", "invalid tunnel name");
  const args = ["set", tunnel];
  let inPeer = false;
  let allowed: string[] | null = null;
  const flushAllowed = () => {
    if (allowed !== null) args.push("allowed-ips", allowed.join(","));
    allowed = null;
  };
  for (const [name, value] of entries) {
    switch (name) {
      case "private_key":
      case "listen_port":
        if (inPeer) throw new WgExeError("rejected", `${name} after a peer`);
        if (name === "private_key") args.push("private-key", await secretFile(key32(name, value)));
        else args.push("listen-port", port(name, value));
        break;
      case "public_key":
        flushAllowed();
        inPeer = true;
        args.push("peer", Buffer.from(key32(name, value)).toString("base64"));
        break;
      case "remove":
        if (!inPeer || (value !== true && value !== "true")) throw new WgExeError("rejected", "bad remove");
        args.push("remove");
        break;
      case "preshared_key":
        if (!inPeer) throw new WgExeError("rejected", "preshared_key without peer");
        args.push("preshared-key", await secretFile(key32(name, value)));
        break;
      case "endpoint":
        if (!inPeer || typeof value !== "string" || !ENDPOINT.test(value)) throw new WgExeError("rejected", "bad endpoint");
        args.push("endpoint", value);
        break;
      case "persistent_keepalive_interval":
        if (!inPeer) throw new WgExeError("rejected", "keepalive without peer");
        args.push("persistent-keepalive", port(name, value));
        break;
      case "allowed_ip":
        if (!inPeer || typeof value !== "string" || !CIDR.test(value)) throw new WgExeError("rejected", "bad allowed_ip");
        (allowed ??= []).push(value);
        break;
      default:
        throw new WgExeError("rejected", `unsupported UAPI key ${name}`);
    }
  }
  flushAllowed();
  return args;
}

export function parseLatestHandshakes(stdout: string): UapiDevice {
  const peers: UapiPeer[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    if (line.trim().length === 0) continue;
    const [publicKey, seconds, ...rest] = line.trim().split("\t");
    if (rest.length > 0 || !publicKey || !KEY_B64.test(publicKey) || !seconds || !/^[0-9]{1,12}$/.test(seconds)) {
      throw new WgExeError("output", "unexpected latest-handshakes line");
    }
    const at = Number(seconds) * 1000;
    peers.push({
      publicKey,
      endpoint: null,
      allowedIps: [],
      lastHandshakeAt: at > 0 ? at : null,
      rxBytes: 0,
      txBytes: 0,
      persistentKeepalive: 0,
      hasPresharedKey: false,
    });
  }
  return { listenPort: null, peers };
}

export type WgExeControlOptions = {
  tunnel: string;
  runner: WgRunner;
  secrets: SecretFiles;
};

export class WgExeControl implements WireGuardControl {
  constructor(private readonly options: WgExeControlOptions) {
    if (!TUNNEL_NAME.test(options.tunnel)) throw new WgExeError("rejected", "invalid tunnel name");
  }

  async set(entries: readonly UapiEntry[]): Promise<void> {
    const files: string[] = [];
    try {
      const args = await wgSetArgs(this.options.tunnel, entries, async (secret) => {
        const file = await this.options.secrets.write(secret);
        files.push(file);
        return file;
      });
      const failure = classifyWgResult(await this.options.runner(args));
      if (failure) throw failure;
    } finally {
      await Promise.all(files.map((file) => this.options.secrets.remove(file)));
    }
  }

  async get(): Promise<UapiDevice> {
    const result = await this.options.runner(["show", this.options.tunnel, "latest-handshakes"]);
    const failure = classifyWgResult(result);
    if (failure) throw failure;
    return parseLatestHandshakes(result.stdout);
  }
}

export function wgFailureOf(error: unknown): WgExeError | null {
  let current: unknown = error;
  for (let depth = 0; current && depth < 6; depth++) {
    if (current instanceof WgExeError) return current;
    current = current instanceof Error ? current.cause : undefined;
  }
  return null;
}
