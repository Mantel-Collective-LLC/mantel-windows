import { readFileSync } from "node:fs";
import type { ExecResult } from "../src/main/system/exec";
import type { UapiDevice, UapiEntry, WireGuardControl } from "../src/main/pq/uapi";
import type { WgRunner } from "../src/main/pq/wgexe";

export type ParsedPeer = {
  publicKey: string;
  remove: boolean;
  presharedKey?: Buffer;
  endpoint?: string;
  keepalive?: number;
  allowedIps?: string[];
};

export type ParsedSet = { privateKey?: Buffer; listenPort?: number; peers: ParsedPeer[] };

const KEY_B64 = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

class WgUsage extends Error {}

function readKeyFile(file: string | undefined): Buffer {
  if (!file) throw new WgUsage("Key file missing");
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    throw new WgUsage(`Unable to open ${file}: No such file or directory`);
  }
  const trimmed = text.replace(/\r?\n$/, "");
  if (!KEY_B64.test(trimmed)) throw new WgUsage(`Key is not the correct length or format: \`${trimmed}'`);
  return Buffer.from(trimmed, "base64");
}

export function parseSetArgs(args: readonly string[]): ParsedSet {
  const result: ParsedSet = { peers: [] };
  let peer: ParsedPeer | null = null;
  for (let i = 0; i < args.length; ) {
    const word = args[i]!;
    const value = args[i + 1];
    if (!peer && word === "private-key") {
      result.privateKey = readKeyFile(value);
      i += 2;
    } else if (!peer && word === "listen-port") {
      result.listenPort = Number(value);
      i += 2;
    } else if (word === "peer") {
      if (!value || !KEY_B64.test(value)) throw new WgUsage("Invalid peer key");
      peer = { publicKey: value, remove: false };
      result.peers.push(peer);
      i += 2;
    } else if (peer && word === "remove") {
      peer.remove = true;
      i += 1;
    } else if (peer && word === "preshared-key") {
      peer.presharedKey = readKeyFile(value);
      i += 2;
    } else if (peer && word === "endpoint") {
      if (!value || !/:[0-9]+$/.test(value)) throw new WgUsage("Unable to parse endpoint");
      peer.endpoint = value;
      i += 2;
    } else if (peer && word === "persistent-keepalive") {
      peer.keepalive = value === "off" ? 0 : Number(value);
      i += 2;
    } else if (peer && word === "allowed-ips") {
      peer.allowedIps = (value ?? "").split(",").filter(Boolean);
      i += 2;
    } else {
      throw new WgUsage(`Invalid argument: ${word}`);
    }
  }
  return result;
}

export function toUapi(set: ParsedSet): UapiEntry[] {
  const entries: UapiEntry[] = [];
  if (set.privateKey) entries.push(["private_key", set.privateKey]);
  if (set.listenPort !== undefined) entries.push(["listen_port", set.listenPort]);
  for (const peer of set.peers) {
    entries.push(["public_key", Buffer.from(peer.publicKey, "base64")]);
    if (peer.remove) {
      entries.push(["remove", "true"]);
      continue;
    }
    if (peer.presharedKey) entries.push(["preshared_key", peer.presharedKey]);
    if (peer.endpoint) entries.push(["endpoint", peer.endpoint]);
    if (peer.keepalive !== undefined) entries.push(["persistent_keepalive_interval", peer.keepalive]);
    if (peer.allowedIps) {
      entries.push(["replace_allowed_ips", "true"]);
      for (const ip of peer.allowedIps) entries.push(["allowed_ip", ip]);
    }
  }
  return entries;
}

export type FakePeerState = {
  presharedKey: Buffer | null;
  endpoint: string | null;
  keepalive: number;
  allowedIps: string[];
  handshakeSec: number;
};

export type FakeWgOptions = {
  tunnel: string;
  backend?: WireGuardControl;
  handshakeAfterKeyChange?: () => number | null;
};

export class FakeWg {
  calls: string[][] = [];
  keyFiles: Buffer[][] = [];
  privateKey: Buffer | null = null;
  peers = new Map<string, FakePeerState>();
  failWith: ExecResult | null = null;
  failSetIndex: number | null = null;
  private sets = 0;

  constructor(private readonly options: FakeWgOptions) {}

  readonly run: WgRunner = async (args) => {
    this.calls.push([...args]);
    if (this.failWith) return this.failWith;
    const [command, iface, ...rest] = args;
    if (iface !== this.options.tunnel) return { code: 1, stdout: "", stderr: `Unable to access interface: No such file or directory\n` };
    try {
      if (command === "set") {
        if (this.failSetIndex === this.sets++) return { code: 1, stdout: "", stderr: "Unable to modify interface: Invalid argument\n" };
        const parsed = parseSetArgs(rest);
        this.keyFiles.push([parsed.privateKey, ...parsed.peers.map((peer) => peer.presharedKey)].filter((key): key is Buffer => !!key).map((key) => Buffer.from(key)));
        if (this.options.backend) await this.options.backend.set(toUapi(parsed));
        else this.apply(parsed);
        return { code: 0, stdout: "", stderr: "" };
      }
      if (command === "show" && rest.length === 1 && rest[0] === "latest-handshakes") {
        const device = this.options.backend ? await this.options.backend.get() : this.device();
        const lines = device.peers.map((peer) => `${peer.publicKey}\t${peer.lastHandshakeAt ? Math.floor(peer.lastHandshakeAt / 1000) : 0}\n`);
        return { code: 0, stdout: lines.join(""), stderr: "" };
      }
      return { code: 1, stdout: "", stderr: `Invalid subcommand: ${String(command)}\n` };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return { code: 1, stdout: "", stderr: error instanceof WgUsage ? `${message}\n` : `Unable to modify interface: ${message}\n` };
    }
  };

  private apply(set: ParsedSet): void {
    let keyChanged = false;
    if (set.privateKey) {
      keyChanged = !this.privateKey?.equals(set.privateKey);
      this.privateKey = set.privateKey;
    }
    for (const peer of set.peers) {
      if (peer.remove) {
        this.peers.delete(peer.publicKey);
        continue;
      }
      const state = this.peers.get(peer.publicKey) ?? { presharedKey: null, endpoint: null, keepalive: 0, allowedIps: [], handshakeSec: 0 };
      if (peer.presharedKey) state.presharedKey = peer.presharedKey;
      if (peer.endpoint) state.endpoint = peer.endpoint;
      if (peer.keepalive !== undefined) state.keepalive = peer.keepalive;
      if (peer.allowedIps) state.allowedIps = peer.allowedIps;
      this.peers.set(peer.publicKey, state);
    }
    if (keyChanged) {
      const at = this.options.handshakeAfterKeyChange?.() ?? null;
      for (const state of this.peers.values()) state.handshakeSec = at ?? 0;
    }
  }

  private device(): UapiDevice {
    return {
      listenPort: null,
      peers: [...this.peers.entries()].map(([publicKey, state]) => ({
        publicKey,
        endpoint: state.endpoint,
        allowedIps: state.allowedIps,
        lastHandshakeAt: state.handshakeSec > 0 ? state.handshakeSec * 1000 : null,
        rxBytes: 0,
        txBytes: 0,
        persistentKeepalive: state.keepalive,
        hasPresharedKey: state.presharedKey !== null,
      })),
    };
  }
}
