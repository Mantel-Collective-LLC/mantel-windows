import { createHash, hkdfSync, timingSafeEqual } from "node:crypto";
import { isIPv4 } from "node:net";
import { CONFIRM_SIZE, CT_SIZE, EK_SIZE, KEM_ML_KEM_768, KEY_SIZE, PQ_VERSION } from "./protocol";

export const TRANSCRIPT_LABEL = "mantel-pq-v1/transcript";
export const INFO_PSK = "mantel-pq-v1/wireguard-psk";
export const INFO_CONFIRM = "mantel-pq-v1/confirm";
export const SHARED_SECRET_SIZE = 32;

export type TranscriptInput = {
  nodeKey: Uint8Array;
  clientKey: Uint8Array;
  sessionKey: Uint8Array;
  tunnelIpv4: string;
  encapsulationKey: Uint8Array;
  ciphertext: Uint8Array;
};

function sized(value: Uint8Array, size: number, name: string): Uint8Array {
  if (value.length !== size) throw new Error(`${name} must be ${size} bytes`);
  return value;
}

export function ipv4Bytes(address: string): Buffer {
  if (!isIPv4(address)) throw new Error("tunnel address must be IPv4");
  return Buffer.from(address.split(".").map(Number));
}

export function transcript(input: TranscriptInput): Buffer {
  const header = Buffer.alloc(4);
  header[0] = 0x00;
  header[1] = PQ_VERSION;
  header.writeUInt16BE(KEM_ML_KEM_768, 2);
  return createHash("sha256")
    .update(TRANSCRIPT_LABEL, "ascii")
    .update(header)
    .update(sized(input.nodeKey, KEY_SIZE, "S"))
    .update(sized(input.clientKey, KEY_SIZE, "K"))
    .update(sized(input.sessionKey, KEY_SIZE, "E"))
    .update(ipv4Bytes(input.tunnelIpv4))
    .update(sized(input.encapsulationKey, EK_SIZE, "ek"))
    .update(sized(input.ciphertext, CT_SIZE, "ct"))
    .digest();
}

export function derive(sharedSecret: Uint8Array, transcriptHash: Uint8Array): { psk: Buffer; confirm: Buffer } {
  sized(sharedSecret, SHARED_SECRET_SIZE, "ss");
  sized(transcriptHash, 32, "th");
  const psk = Buffer.from(hkdfSync("sha256", sharedSecret, transcriptHash, INFO_PSK, KEY_SIZE));
  const confirm = Buffer.from(hkdfSync("sha256", sharedSecret, transcriptHash, INFO_CONFIRM, CONFIRM_SIZE));
  return { psk, confirm };
}

export function confirmMatches(expected: Uint8Array, received: Uint8Array): boolean {
  return expected.length === CONFIRM_SIZE && received.length === CONFIRM_SIZE && timingSafeEqual(expected, received);
}
