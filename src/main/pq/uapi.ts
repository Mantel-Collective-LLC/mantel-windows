import { connect, type NetConnectOpts } from "node:net";
import type { Duplex } from "node:stream";

export type UapiTransport = () => Promise<Duplex>;

export type UapiEntry = readonly [key: string, value: string | number | boolean | Uint8Array];

export type UapiPeer = {
  publicKey: string;
  endpoint: string | null;
  allowedIps: string[];
  lastHandshakeAt: number | null;
  rxBytes: number;
  txBytes: number;
  persistentKeepalive: number;
  hasPresharedKey: boolean;
};

export type UapiDevice = {
  listenPort: number | null;
  peers: UapiPeer[];
};

export type WireGuardControl = {
  set: (entries: readonly UapiEntry[]) => Promise<void>;
  get: () => Promise<UapiDevice>;
};

export class UapiError extends Error {}

export function namedPipePath(tunnelName: string): string {
  if (!/^[A-Za-z0-9_=+.-]{1,32}$/.test(tunnelName)) throw new UapiError("invalid tunnel name");
  return `\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WireGuard\\${tunnelName}`;
}

function connectWith(options: NetConnectOpts): Promise<Duplex> {
  return new Promise<Duplex>((resolve, reject) => {
    const socket = connect(options);
    socket.once("error", reject);
    socket.once("connect", () => {
      socket.off("error", reject);
      resolve(socket);
    });
  });
}

export function namedPipeTransport(tunnelName: string): UapiTransport {
  const pipe = namedPipePath(tunnelName);
  return () => connectWith({ path: pipe });
}

export function tcpTransport(host: string, port: number): UapiTransport {
  return () => connectWith({ host, port });
}

const KEY_PATTERN = /^[a-z_]{1,40}$/;
const HEX = "0123456789abcdef";

export function encodeSet(entries: readonly UapiEntry[]): Buffer {
  const parts: (string | Uint8Array)[] = ["set=1\n"];
  for (const [key, value] of entries) {
    if (!KEY_PATTERN.test(key)) throw new UapiError(`invalid key ${key}`);
    if (typeof value === "string" && /[\r\n\0]/.test(value)) throw new UapiError(`unsafe value for ${key}`);
    parts.push(`${key}=`);
    parts.push(value instanceof Uint8Array ? value : String(value));
    parts.push("\n");
  }
  parts.push("\n");
  const size = parts.reduce((sum, part) => sum + (typeof part === "string" ? Buffer.byteLength(part) : part.length * 2), 0);
  const out = Buffer.alloc(size);
  let offset = 0;
  for (const part of parts) {
    if (typeof part === "string") {
      offset += out.write(part, offset, "utf8");
      continue;
    }
    for (const byte of part) {
      out[offset++] = HEX.charCodeAt(byte >> 4);
      out[offset++] = HEX.charCodeAt(byte & 0x0f);
    }
  }
  return out;
}

const SECRET_LINES = [Buffer.from("private_key="), Buffer.from("preshared_key=")];

export function sanitizeResponse(raw: Buffer): string {
  const lines: string[] = [];
  let start = 0;
  while (start < raw.length) {
    let end = raw.indexOf(0x0a, start);
    if (end < 0) end = raw.length;
    const line = raw.subarray(start, end);
    const secret = SECRET_LINES.find((prefix) => line.subarray(0, prefix.length).equals(prefix));
    if (!secret) lines.push(line.toString("utf8"));
    else if (secret === SECRET_LINES[1]) lines.push(`preshared_key=${line.subarray(secret.length).every((byte) => byte === 0x30) ? 0 : 1}`);
    start = end + 1;
  }
  raw.fill(0);
  return lines.join("\n");
}

function readResponse(socket: Duplex, timeoutMs: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const finish = (error: Error | null) => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("end", onEnd);
      socket.off("error", onError);
      const raw = Buffer.concat(chunks);
      for (const chunk of chunks) chunk.fill(0);
      if (error) {
        raw.fill(0);
        reject(error);
      } else resolve(raw);
    };
    const onData = (chunk: Buffer | string) => {
      const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
      chunks.push(bytes);
      total += bytes.length;
      if (total > 1024 * 1024) return finish(new UapiError("response too large"));
      const last = chunks.length > 0 ? Buffer.concat(chunks.slice(-2)) : Buffer.alloc(0);
      if ((total === 1 && last[0] === 0x0a) || (last.length >= 2 && last[last.length - 1] === 0x0a && last[last.length - 2] === 0x0a)) {
        finish(null);
      }
    };
    const onEnd = () => finish(new UapiError("closed before end of response"));
    const onError = (error: Error) => finish(new UapiError(`transport: ${error.message}`));
    const timer = setTimeout(() => finish(new UapiError("timeout")), timeoutMs);
    socket.on("data", onData);
    socket.once("end", onEnd);
    socket.once("error", onError);
  });
}

export function checkErrno(response: string): string[] {
  const lines = response.split("\n").filter((line) => line.length > 0);
  const last = lines.pop();
  if (!last?.startsWith("errno=")) throw new UapiError("missing errno");
  if (last !== "errno=0") throw new UapiError(`UAPI ${last}`);
  return lines;
}

function hexToBase64(value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new UapiError("bad key in get");
  return Buffer.from(value, "hex").toString("base64");
}

export function parseGet(lines: readonly string[]): UapiDevice {
  const device: UapiDevice = { listenPort: null, peers: [] };
  let peer: UapiPeer | null = null;
  let seconds = 0;
  let nanoseconds = 0;
  const flush = () => {
    if (peer) {
      peer.lastHandshakeAt = seconds > 0 || nanoseconds > 0 ? seconds * 1000 + Math.floor(nanoseconds / 1e6) : null;
      device.peers.push(peer);
    }
    seconds = 0;
    nanoseconds = 0;
  };
  for (const line of lines) {
    const index = line.indexOf("=");
    if (index < 0) throw new UapiError("bad line in get");
    const key = line.slice(0, index);
    const value = line.slice(index + 1);
    if (key === "public_key") {
      flush();
      peer = {
        publicKey: hexToBase64(value),
        endpoint: null,
        allowedIps: [],
        lastHandshakeAt: null,
        rxBytes: 0,
        txBytes: 0,
        persistentKeepalive: 0,
        hasPresharedKey: false,
      };
      continue;
    }
    if (!peer) {
      if (key === "listen_port") device.listenPort = Number(value) || null;
      continue;
    }
    switch (key) {
      case "preshared_key":
        peer.hasPresharedKey = !/^0+$/.test(value);
        break;
      case "endpoint":
        peer.endpoint = value;
        break;
      case "allowed_ip":
        peer.allowedIps.push(value);
        break;
      case "last_handshake_time_sec":
        seconds = Number(value) || 0;
        break;
      case "last_handshake_time_nsec":
        nanoseconds = Number(value) || 0;
        break;
      case "rx_bytes":
        peer.rxBytes = Number(value) || 0;
        break;
      case "tx_bytes":
        peer.txBytes = Number(value) || 0;
        break;
      case "persistent_keepalive_interval":
        peer.persistentKeepalive = Number(value) || 0;
        break;
    }
  }
  flush();
  return device;
}

export class UapiClient implements WireGuardControl {
  constructor(
    private readonly transport: UapiTransport,
    private readonly timeoutMs = 5000,
  ) {}

  private async roundTrip(request: Buffer): Promise<string> {
    const socket = await this.transport();
    socket.on("error", () => undefined);
    try {
      const response = readResponse(socket, this.timeoutMs);
      await new Promise<void>((resolve, reject) => socket.write(request, (error) => (error ? reject(error) : resolve())));
      return sanitizeResponse(await response);
    } finally {
      request.fill(0);
      socket.destroy();
    }
  }

  async set(entries: readonly UapiEntry[]): Promise<void> {
    checkErrno(await this.roundTrip(encodeSet(entries)));
  }

  async get(): Promise<UapiDevice> {
    const lines = checkErrno(await this.roundTrip(Buffer.from("get=1\n\n")));
    return parseGet(lines);
  }
}
