export const PQ_MAGIC = Buffer.from("MTPQ", "ascii");
export const PQ_VERSION = 1;
export const KEM_ML_KEM_768 = 0x0001;

export const HEADER_SIZE = 8;
export const KEY_SIZE = 32;
export const EK_SIZE = 1184;
export const CT_SIZE = 1088;
export const CONFIRM_SIZE = 32;
export const MAX_FRAME_SIZE = 1226;

export const FrameType = {
  hello: 0x01,
  response: 0x02,
  statusRequest: 0x03,
  statusResponse: 0x04,
  error: 0x7f,
} as const;

const PAYLOAD_SIZE: Record<number, number> = {
  [FrameType.hello]: 2 + KEY_SIZE + EK_SIZE,
  [FrameType.response]: 2 + CT_SIZE + CONFIRM_SIZE,
  [FrameType.statusRequest]: KEY_SIZE,
  [FrameType.statusResponse]: 1 + KEY_SIZE,
  [FrameType.error]: 4,
};

export const PqWireError = {
  unsupportedVersion: 1,
  unsupportedKem: 2,
  malformed: 3,
  unknownPeer: 4,
  rateLimited: 5,
  busy: 6,
  internal: 7,
  invalidSessionKey: 8,
  notAvailable: 9,
} as const;

export type SessionState = 0 | 1 | 2;

export type ServerFrame =
  | { type: "response"; kemId: number; ciphertext: Buffer; confirm: Buffer }
  | { type: "status"; state: SessionState; sessionKey: Buffer }
  | { type: "error"; code: number; retryAfterS: number };

export class PqProtocolError extends Error {
  constructor(readonly reason: string) {
    super(`PQ protocol: ${reason}`);
  }
}

function frame(type: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(HEADER_SIZE);
  PQ_MAGIC.copy(header, 0);
  header[4] = PQ_VERSION;
  header[5] = type;
  header.writeUInt16BE(payload.length, 6);
  return Buffer.concat([header, payload]);
}

function exact(value: Uint8Array, size: number, name: string): Buffer {
  if (value.length !== size) throw new PqProtocolError(`${name} must be ${size} bytes`);
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

export function encodeHello(sessionKey: Uint8Array, encapsulationKey: Uint8Array): Buffer {
  const kem = Buffer.alloc(2);
  kem.writeUInt16BE(KEM_ML_KEM_768, 0);
  return frame(FrameType.hello, Buffer.concat([kem, exact(sessionKey, KEY_SIZE, "session key"), exact(encapsulationKey, EK_SIZE, "ek")]));
}

export function encodeStatusRequest(sessionKey: Uint8Array): Buffer {
  return frame(FrameType.statusRequest, Buffer.from(exact(sessionKey, KEY_SIZE, "session key")));
}

export function parseHeader(header: Uint8Array): { type: number; length: number } {
  if (header.length < HEADER_SIZE) throw new PqProtocolError("short header");
  const buffer = Buffer.from(header.buffer, header.byteOffset, header.byteLength);
  if (!buffer.subarray(0, 4).equals(PQ_MAGIC)) throw new PqProtocolError("bad magic");
  if (buffer[4] !== PQ_VERSION) throw new PqProtocolError("unsupported version");
  const type = buffer[5] ?? 0;
  const length = buffer.readUInt16BE(6);
  const expected = PAYLOAD_SIZE[type];
  if (expected === undefined) throw new PqProtocolError("unknown type");
  if (length !== expected) throw new PqProtocolError("bad length");
  return { type, length };
}

export function decodeServerFrame(bytes: Uint8Array): ServerFrame {
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const { type, length } = parseHeader(buffer);
  if (buffer.length !== HEADER_SIZE + length) throw new PqProtocolError("bad frame size");
  const payload = buffer.subarray(HEADER_SIZE);
  switch (type) {
    case FrameType.response:
      return decodeResponsePayload(payload);
    case FrameType.statusResponse:
      return decodeStatusPayload(payload);
    case FrameType.error:
      return { type: "error", code: payload.readUInt16BE(0), retryAfterS: payload.readUInt16BE(2) };
    default:
      throw new PqProtocolError("unexpected type");
  }
}

function decodeResponsePayload(payload: Buffer): ServerFrame {
  return {
    type: "response",
    kemId: payload.readUInt16BE(0),
    ciphertext: Buffer.from(payload.subarray(2, 2 + CT_SIZE)),
    confirm: Buffer.from(payload.subarray(2 + CT_SIZE)),
  };
}

function decodeStatusPayload(payload: Buffer): ServerFrame {
  const state = payload[0];
  if (state !== 0 && state !== 1 && state !== 2) throw new PqProtocolError("bad state");
  return { type: "status", state, sessionKey: Buffer.from(payload.subarray(1)) };
}

export function decodeResponse(bytes: Uint8Array): Extract<ServerFrame, { type: "response" }> {
  const decoded = decodeServerFrame(bytes);
  if (decoded.type !== "response") throw new PqProtocolError("not a RESPONSE");
  return decoded;
}

export function decodeStatus(bytes: Uint8Array): Extract<ServerFrame, { type: "status" }> {
  const decoded = decodeServerFrame(bytes);
  if (decoded.type !== "status") throw new PqProtocolError("not a STATUS_RESPONSE");
  return decoded;
}

export function decodeError(bytes: Uint8Array): Extract<ServerFrame, { type: "error" }> {
  const decoded = decodeServerFrame(bytes);
  if (decoded.type !== "error") throw new PqProtocolError("not an ERROR");
  return decoded;
}
