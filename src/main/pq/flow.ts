import { PQ_ADDRESS, type PqErrorCode, type QuantumState } from "../../../shared/core/contract";
import { PqAttemptError, PqError } from "./errors";
import { checkStatus, DEFAULT_EXCHANGE_TIMEOUTS, rawKey, runExchange, type Dial, type ExchangeResult, type ExchangeTimeouts, type Kem, type RawKeyPair } from "./exchange";
import type { UapiEntry, WireGuardControl } from "./uapi";

export type Clock = { now: () => number; sleep: (ms: number) => Promise<void> };

export const REAL_CLOCK: Clock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
};

export type RetryPolicy = {
  attempts: number;
  delaysMs: readonly number[];
  budgetMs: number;
};

export const DEFAULT_RETRY: RetryPolicy = { attempts: 3, delaysMs: [500, 1000], budgetMs: 20_000 };

export type FlowTimeouts = ExchangeTimeouts & {
  handshakeMs: number;
  statusMs: number;
  pollMs: number;
  statusConnectMs: number;
  statusDelayMs: number;
};

export const DEFAULT_FLOW_TIMEOUTS: FlowTimeouts = {
  ...DEFAULT_EXCHANGE_TIMEOUTS,
  handshakeMs: 8000,
  statusMs: 4000,
  pollMs: 250,
  statusConnectMs: 1500,
  statusDelayMs: 300,
};

export type PqUpgradeOptions = {
  wireguard: WireGuardControl;
  dial: Dial;
  nodeKey: string;
  clientKey: string;
  tunnelIpv4: string;
  endpoint: string;
  presharedKey?: string;
  clientPrivateKey?: string;
  allowedIps: readonly string[];
  onQuantum?: (state: QuantumState) => void;
  onAttempt?: (attempt: number) => void;
  clock?: Clock;
  retry?: Partial<RetryPolicy>;
  timeouts?: Partial<FlowTimeouts>;
  kem?: Kem;
  generateSessionKey?: () => RawKeyPair;
};

export type PqUpgradeResult = {
  sessionPublicKey: string;
};

const KEEPALIVE = 25;

export function phase1Entries(input: { clientPrivateKey?: Buffer; nodeKey: Buffer; presharedKey?: Buffer; endpoint: string }): UapiEntry[] {
  return [
    ...(input.clientPrivateKey ? ([["private_key", input.clientPrivateKey]] as UapiEntry[]) : []),
    ["public_key", input.nodeKey],
    ["remove", "true"],
    ["public_key", input.nodeKey],
    ...(input.presharedKey ? ([["preshared_key", input.presharedKey]] as UapiEntry[]) : []),
    ["endpoint", input.endpoint],
    ["persistent_keepalive_interval", KEEPALIVE],
    ["allowed_ip", `${PQ_ADDRESS}/32`],
  ];
}

export function phase2Entries(input: {
  sessionPrivateKey: Buffer;
  nodeKey: Buffer;
  psk: Buffer;
  endpoint: string;
  allowedIps: readonly string[];
}): UapiEntry[] {
  return [
    ["private_key", input.sessionPrivateKey],
    ["public_key", input.nodeKey],
    ["remove", "true"],
    ["public_key", input.nodeKey],
    ["preshared_key", input.psk],
    ["endpoint", input.endpoint],
    ["persistent_keepalive_interval", KEEPALIVE],
    ...input.allowedIps.map((ip): UapiEntry => ["allowed_ip", ip]),
  ];
}

export function inertEntries(nodeKey: Buffer): UapiEntry[] {
  return [
    ["public_key", nodeKey],
    ["remove", "true"],
  ];
}

export async function negotiate(
  options: Pick<PqUpgradeOptions, "dial" | "nodeKey" | "clientKey" | "tunnelIpv4" | "kem" | "generateSessionKey" | "onAttempt"> & {
    clock?: Clock;
    retry?: Partial<RetryPolicy>;
    timeouts?: ExchangeTimeouts;
  },
): Promise<ExchangeResult> {
  const clock = options.clock ?? REAL_CLOCK;
  const policy = { ...DEFAULT_RETRY, ...options.retry };
  const started = clock.now();
  let last: PqAttemptError | null = null;
  for (let attempt = 0; attempt < policy.attempts; attempt++) {
    if (attempt > 0 && last) {
      const base = policy.delaysMs[Math.min(attempt - 1, policy.delaysMs.length - 1)] ?? 0;
      const pause = Math.max(base, last.retryAfterS * 1000);
      if (clock.now() - started + pause >= policy.budgetMs) break;
      await clock.sleep(pause);
    }
    options.onAttempt?.(attempt + 1);
    try {
      return await runExchange({
        dial: options.dial,
        nodeKey: options.nodeKey,
        clientKey: options.clientKey,
        tunnelIpv4: options.tunnelIpv4,
        kem: options.kem,
        generateSessionKey: options.generateSessionKey,
        timeouts: options.timeouts,
      });
    } catch (error) {
      last = error instanceof PqAttemptError ? error : new PqAttemptError("retry", error instanceof Error ? error.message : String(error));
      if (last.failure === "unsupported") throw new PqError("pq_unsupported", { cause: last });
    }
    if (clock.now() - started >= policy.budgetMs) break;
  }
  throw new PqError(last?.failure === "mismatch" ? "pq_mismatch" : "pq_failed", { cause: last });
}

async function waitForHandshake(
  wireguard: WireGuardControl,
  nodeKey: string,
  sinceMs: number,
  clock: Clock,
  timeouts: FlowTimeouts,
): Promise<void> {
  const since = Math.floor(sinceMs / 1000) * 1000;
  const deadline = clock.now() + timeouts.handshakeMs;
  for (;;) {
    const device = await wireguard.get().catch(() => null);
    const peer = device?.peers.find((entry) => entry.publicKey === nodeKey);
    if (peer?.lastHandshakeAt != null && peer.lastHandshakeAt >= since) return;
    if (clock.now() >= deadline) throw new PqAttemptError("transport", "no handshake as session key");
    await clock.sleep(timeouts.pollMs);
  }
}

async function waitForActive(dial: Dial, sessionKey: Buffer, clock: Clock, timeouts: FlowTimeouts): Promise<void> {
  const deadline = clock.now() + timeouts.statusMs;
  await clock.sleep(timeouts.statusDelayMs);
  for (;;) {
    let lastFailure: string;
    try {
      const state = await checkStatus({
        dial,
        sessionKey,
        timeouts: { connectMs: timeouts.statusConnectMs, responseMs: timeouts.responseMs },
      });
      if (state === 2) return;
      if (state === 0) throw new PqAttemptError("protocol", "node has no session for this key");
      lastFailure = "pending";
    } catch (error) {
      if (error instanceof PqAttemptError && (error.failure === "protocol" || error.failure === "unsupported")) throw error;
      lastFailure = error instanceof Error ? error.message : String(error);
    }
    if (clock.now() >= deadline) throw new PqAttemptError("transport", lastFailure);
    await clock.sleep(timeouts.pollMs);
  }
}

async function makeInert(wireguard: WireGuardControl, nodeKey: Buffer): Promise<void> {
  await wireguard.set(inertEntries(nodeKey)).catch(() => undefined);
}

export async function runPqUpgrade(options: PqUpgradeOptions): Promise<PqUpgradeResult> {
  const clock = options.clock ?? REAL_CLOCK;
  const timeouts: FlowTimeouts = { ...DEFAULT_FLOW_TIMEOUTS, ...options.timeouts };
  const nodeKey = rawKey(options.nodeKey, "S");
  rawKey(options.clientKey, "K");
  const migrationPsk = options.presharedKey ? rawKey(options.presharedKey, "PSK") : undefined;
  const clientPrivateKey = options.clientPrivateKey ? rawKey(options.clientPrivateKey, "K private") : undefined;
  options.onQuantum?.("negotiating");

  const fail = async (code: PqErrorCode, cause: unknown): Promise<never> => {
    await makeInert(options.wireguard, nodeKey);
    options.onQuantum?.("off");
    if (cause instanceof PqError) throw cause;
    throw new PqError(code, { cause });
  };

  try {
    await options.wireguard.set(phase1Entries({ clientPrivateKey, nodeKey, presharedKey: migrationPsk, endpoint: options.endpoint }));
  } catch (error) {
    return fail("pq_failed", error);
  } finally {
    migrationPsk?.fill(0);
    clientPrivateKey?.fill(0);
  }

  let result: ExchangeResult;
  try {
    result = await negotiate({ ...options, clock, timeouts });
  } catch (error) {
    return fail("pq_failed", error);
  }

  const { session, psk } = result;
  const sessionPublicKey = session.publicKey.toString("base64");
  let phase2At: number;
  try {
    phase2At = clock.now();
    await options.wireguard.set(
      phase2Entries({ sessionPrivateKey: session.privateKey, nodeKey, psk, endpoint: options.endpoint, allowedIps: options.allowedIps }),
    );
  } catch (error) {
    return fail("pq_not_active", error);
  } finally {
    psk.fill(0);
    session.privateKey.fill(0);
  }

  try {
    await waitForHandshake(options.wireguard, options.nodeKey, phase2At, clock, timeouts);
    await waitForActive(options.dial, session.publicKey, clock, timeouts);
  } catch (error) {
    return fail("pq_not_active", error);
  }
  options.onQuantum?.("active");
  return { sessionPublicKey };
}

export async function sessionStillActive(dial: Dial, sessionPublicKey: string, timeouts?: Partial<FlowTimeouts>): Promise<boolean> {
  const merged = { ...DEFAULT_FLOW_TIMEOUTS, ...timeouts };
  try {
    return (await checkStatus({ dial, sessionKey: sessionPublicKey, timeouts: { connectMs: merged.connectMs, responseMs: merged.responseMs } })) === 2;
  } catch {
    return false;
  }
}
