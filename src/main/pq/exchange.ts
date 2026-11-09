import { connect } from "node:net";
import type { Duplex } from "node:stream";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { PQ_ADDRESS, PQ_PORT } from "../../../shared/core/contract";
import { generateRawKeyPair } from "../wireguard/keys";
import { PqAttemptError } from "./errors";
import { confirmMatches, derive, transcript } from "./kdf";
import {
  decodeServerFrame,
  encodeHello,
  encodeStatusRequest,
  HEADER_SIZE,
  KEM_ML_KEM_768,
  KEY_SIZE,
  MAX_FRAME_SIZE,
  parseHeader,
  PqProtocolError,
  PqWireError,
  type ServerFrame,
  type SessionState,
} from "./protocol";

export type Dial = () => Promise<Duplex>;

export type Kem = {
  keygen: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  decapsulate: (ciphertext: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};

export const ML_KEM_768: Kem = {
  keygen: () => ml_kem768.keygen(),
  decapsulate: (ciphertext, secretKey) => ml_kem768.decapsulate(ciphertext, secretKey),
};

export type RawKeyPair = { privateKey: Buffer; publicKey: Buffer };

export type ExchangeTimeouts = {
  connectMs: number;
  responseMs: number;
};

export const DEFAULT_EXCHANGE_TIMEOUTS: ExchangeTimeouts = { connectMs: 4000, responseMs: 6000 };

export type ExchangeResult = {
  session: RawKeyPair;
  psk: Buffer;
};

export function rawKey(key: string | Uint8Array, name: string): Buffer {
  const raw = typeof key === "string" ? Buffer.from(key, "base64") : Buffer.from(key);
  if (raw.length !== KEY_SIZE || (typeof key === "string" && raw.toString("base64") !== key)) {
    throw new Error(`invalid WireGuard key: ${name}`);
  }
  return raw;
}

function withTimeout<T>(promise: Promise<T>, ms: number, onLate: (value: T) => void, detail: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let done = false;
    const timer = setTimeout(() => {
      done = true;
      reject(new PqAttemptError("transport", detail));
    }, ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        if (done) onLate(value);
        else resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        if (!done) reject(error instanceof PqAttemptError ? error : new PqAttemptError("transport", describe(error)));
      },
    );
  });
}

function describe(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  if (typeof code === "string") return code;
  return error instanceof Error ? error.message : String(error);
}

function readFrame(socket: Duplex, timeoutMs: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let expected: number | null = null;
    const finish = (error: Error | null, frame?: Buffer) => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("end", onEnd);
      socket.off("close", onEnd);
      socket.off("error", onError);
      if (error) reject(error);
      else resolve(frame as Buffer);
    };
    const onData = (chunk: Buffer | string) => {
      const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
      chunks.push(bytes);
      total += bytes.length;
      if (total > MAX_FRAME_SIZE) return finish(new PqAttemptError("protocol", "frame too large"));
      const buffer = Buffer.concat(chunks);
      if (expected === null && total >= HEADER_SIZE) {
        try {
          expected = HEADER_SIZE + parseHeader(buffer.subarray(0, HEADER_SIZE)).length;
        } catch (error) {
          return finish(new PqAttemptError("protocol", describe(error)));
        }
      }
      if (expected !== null && total > expected) return finish(new PqAttemptError("protocol", "trailing data"));
      if (expected !== null && total === expected) finish(null, buffer);
    };
    const onEnd = () => finish(new PqAttemptError("transport", "closed without answer"));
    const onError = (error: Error) => finish(new PqAttemptError("transport", describe(error)));
    const timer = setTimeout(() => finish(new PqAttemptError("transport", "answer timeout")), timeoutMs);
    socket.on("data", onData);
    socket.once("end", onEnd);
    socket.once("close", onEnd);
    socket.once("error", onError);
  });
}

export async function requestFrame(dial: Dial, request: Buffer, timeouts: ExchangeTimeouts): Promise<ServerFrame> {
  const socket = await withTimeout(dial(), timeouts.connectMs, (late) => late.destroy(), "connect timeout");
  socket.on("error", () => undefined);
  try {
    const answer = readFrame(socket, timeouts.responseMs);
    socket.write(request);
    const frame = await answer;
    try {
      return decodeServerFrame(frame);
    } catch (error) {
      throw new PqAttemptError("protocol", error instanceof PqProtocolError ? error.reason : describe(error));
    }
  } finally {
    socket.destroy();
  }
}

export function errorFrameFailure(frame: Extract<ServerFrame, { type: "error" }>): PqAttemptError {
  switch (frame.code) {
    case PqWireError.unsupportedVersion:
    case PqWireError.unsupportedKem:
    case PqWireError.notAvailable:
      return new PqAttemptError("unsupported", `error ${frame.code}`);
    case PqWireError.rateLimited:
    case PqWireError.busy:
      return new PqAttemptError("rate_limited", `error ${frame.code}`, frame.retryAfterS);
    default:
      return new PqAttemptError("retry", `error ${frame.code}`);
  }
}

export type RunExchangeOptions = {
  dial: Dial;
  nodeKey: string | Uint8Array;
  clientKey: string | Uint8Array;
  tunnelIpv4: string;
  kem?: Kem;
  generateSessionKey?: () => RawKeyPair;
  timeouts?: ExchangeTimeouts;
};

export async function runExchange(options: RunExchangeOptions): Promise<ExchangeResult> {
  const nodeKey = rawKey(options.nodeKey, "S");
  const clientKey = rawKey(options.clientKey, "K");
  const kem = options.kem ?? ML_KEM_768;
  const session = (options.generateSessionKey ?? generateRawKeyPair)();
  const { publicKey: encapsulationKey, secretKey } = kem.keygen();
  let sharedSecret: Uint8Array | null = null;
  try {
    const frame = await requestFrame(options.dial, encodeHello(session.publicKey, encapsulationKey), options.timeouts ?? DEFAULT_EXCHANGE_TIMEOUTS);
    if (frame.type === "error") throw errorFrameFailure(frame);
    if (frame.type !== "response") throw new PqAttemptError("protocol", "expected RESPONSE");
    if (frame.kemId !== KEM_ML_KEM_768) throw new PqAttemptError("protocol", "unexpected kem_id");
    sharedSecret = kem.decapsulate(frame.ciphertext, secretKey);
    const th = transcript({
      nodeKey,
      clientKey,
      sessionKey: session.publicKey,
      tunnelIpv4: options.tunnelIpv4,
      encapsulationKey,
      ciphertext: frame.ciphertext,
    });
    const { psk, confirm } = derive(sharedSecret, th);
    if (!confirmMatches(confirm, frame.confirm)) {
      psk.fill(0);
      throw new PqAttemptError("mismatch", "key confirmation differs");
    }
    return { session, psk };
  } catch (error) {
    session.privateKey.fill(0);
    throw error;
  } finally {
    secretKey.fill(0);
    sharedSecret?.fill(0);
  }
}

export type CheckStatusOptions = {
  dial: Dial;
  sessionKey: string | Uint8Array;
  timeouts?: ExchangeTimeouts;
};

export async function checkStatus(options: CheckStatusOptions): Promise<SessionState> {
  const sessionKey = rawKey(options.sessionKey, "E");
  const frame = await requestFrame(options.dial, encodeStatusRequest(sessionKey), options.timeouts ?? DEFAULT_EXCHANGE_TIMEOUTS);
  if (frame.type === "error") throw errorFrameFailure(frame);
  if (frame.type !== "status") throw new PqAttemptError("protocol", "expected STATUS_RESPONSE");
  if (!frame.sessionKey.equals(sessionKey)) throw new PqAttemptError("protocol", "status for another key");
  return frame.state;
}

export function tunnelDial(tunnelIpv4: string): Dial {
  return () =>
    new Promise<Duplex>((resolve, reject) => {
      const socket = connect({ host: PQ_ADDRESS, port: PQ_PORT, localAddress: tunnelIpv4 });
      socket.setNoDelay(true);
      const onError = (error: Error) => {
        socket.destroy();
        reject(error);
      };
      socket.once("error", onError);
      socket.once("connect", () => {
        socket.off("error", onError);
        if (socket.localAddress !== tunnelIpv4) {
          socket.destroy();
          reject(new PqAttemptError("transport", "local address is not the tunnel address"));
          return;
        }
        resolve(socket);
      });
    });
}
