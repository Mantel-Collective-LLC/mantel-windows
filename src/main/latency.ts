import { randomBytes } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";
import { isIP } from "node:net";
import {
  buildPingRequest,
  isPingReply,
  mapLimited,
  PING_CONCURRENCY,
  PING_TIMEOUT_MS,
  PINGS_PER_LOCATION,
  type LatencyMeasurement,
} from "../../shared/core/latency";

export type PingTarget = { id: string; host: string; port: number };

export type PingDependencies = {
  resolve: (host: string) => Promise<string[]>;
  createSocket: (type: "udp4" | "udp6") => Socket;
  randomNonce: () => Uint8Array;
  now: () => number;
  timeoutMs: number;
  pings: number;
  concurrency: number;
};

const DEFAULTS: PingDependencies = {
  resolve: async () => [],
  createSocket: (type) => createSocket({ type }),
  randomNonce: () => randomBytes(16),
  now: () => performance.now(),
  timeoutMs: PING_TIMEOUT_MS,
  pings: PINGS_PER_LOCATION,
  concurrency: PING_CONCURRENCY,
};

async function addressOf(host: string, resolve: PingDependencies["resolve"]): Promise<string | null> {
  if (isIP(host)) return host;
  const addresses = (await resolve(host).catch(() => [])).filter((address) => isIP(address) !== 0);
  return addresses.find((address) => isIP(address) === 4) ?? addresses[0] ?? null;
}

function pingOnce(socket: Socket, address: string, port: number, deps: PingDependencies): Promise<number | null> {
  return new Promise((resolve) => {
    const nonce = deps.randomNonce();
    let done = false;
    let started = 0;
    const finish = (value: number | null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.removeListener("message", onMessage);
      socket.removeListener("error", onError);
      resolve(value);
    };
    const onMessage = (message: Buffer) => {
      if (isPingReply(message, nonce)) finish(Math.max(0, deps.now() - started));
    };
    const onError = () => finish(null);
    const timer = setTimeout(() => finish(null), deps.timeoutMs);
    socket.on("message", onMessage);
    socket.on("error", onError);
    started = deps.now();
    try {
      socket.send(buildPingRequest(nonce), port, address, (error) => {
        if (error) finish(null);
      });
    } catch {
      finish(null);
    }
  });
}

export async function measureTarget(target: PingTarget, partial: Partial<PingDependencies> = {}): Promise<LatencyMeasurement> {
  const deps = { ...DEFAULTS, ...partial };
  const empty = { id: target.id, samples: new Array<number | null>(deps.pings).fill(null) };
  const address = await addressOf(target.host, deps.resolve);
  if (!address) return empty;
  let socket: Socket;
  try {
    socket = deps.createSocket(isIP(address) === 6 ? "udp6" : "udp4");
  } catch {
    return empty;
  }
  socket.on("error", () => undefined);
  const samples: (number | null)[] = [];
  try {
    for (let index = 0; index < deps.pings; index += 1) samples.push(await pingOnce(socket, address, target.port, deps));
  } finally {
    try {
      socket.close();
    } catch {
    }
  }
  return { id: target.id, samples };
}

export function measureTargets(targets: readonly PingTarget[], partial: Partial<PingDependencies> = {}): Promise<LatencyMeasurement[]> {
  const concurrency = partial.concurrency ?? DEFAULTS.concurrency;
  return mapLimited(targets, concurrency, (target) => measureTarget(target, partial));
}
