import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { describe, expect, it } from "vitest";
import { confirmMatches, derive, INFO_CONFIRM, INFO_PSK, transcript, TRANSCRIPT_LABEL } from "../src/main/pq/kdf";
import {
  CT_SIZE,
  decodeError,
  decodeResponse,
  decodeStatus,
  EK_SIZE,
  encodeHello,
  encodeStatusRequest,
  KEM_ML_KEM_768,
  PQ_MAGIC,
  PQ_VERSION,
} from "../src/main/pq/protocol";
import { publicKeyFromPrivate } from "../src/main/wireguard/keys";

type Key = { privateKey: string; publicKey: string };
type Derived = { sharedSecret: string; transcriptHash: string; psk: string; confirm: string };
type Vector = {
  name: string;
  inputs: { mlkemSeed: string; encapsRandomness: string; nodeKey: Key; clientKey: Key; sessionKey: Key; tunnelIpv4: string };
  outputs: Derived & {
    encapsulationKey: string;
    encapsulationKeySha256: string;
    ciphertext: string;
    pskBase64: string;
    helloFrame: string;
    responseFrame: string;
    statusRequestFrame: string;
    statusResponseFrame: string;
    tamperedCiphertext: Derived & { ciphertext: string };
  };
};
type VectorFile = {
  constants: Record<string, string | number>;
  vectors: Vector[];
  errorFrames: { name: string; code: number; retryAfterS: number; errorFrame: string }[];
};

const file = JSON.parse(readFileSync(path.join(__dirname, "fixtures/pq-test-vectors.json"), "utf8")) as VectorFile;
const hex = (value: string) => Buffer.from(value, "hex");
const b64 = (value: string) => Buffer.from(value, "base64");
const toHex = (value: Uint8Array) => Buffer.from(value).toString("hex");

describe("PQ vector file", () => {
  it("matches the constants of the implementation", () => {
    const c = file.constants;
    expect(c.magic).toBe(PQ_MAGIC.toString("hex"));
    expect(c.protocolVersion).toBe(PQ_VERSION);
    expect(c.kemId).toBe(KEM_ML_KEM_768);
    expect(c.kemName).toBe("ML-KEM-768");
    expect(c.encapsulationKeySize).toBe(EK_SIZE);
    expect(c.ciphertextSize).toBe(CT_SIZE);
    expect(c.sharedSecretSize).toBe(32);
    expect(c.helloFrameSize).toBe(1226);
    expect(c.responseFrameSize).toBe(1130);
    expect(c.transcriptLabel).toBe(TRANSCRIPT_LABEL);
    expect(c.infoPsk).toBe(INFO_PSK);
    expect(c.infoConfirm).toBe(INFO_CONFIRM);
    expect(file.vectors.length).toBeGreaterThanOrEqual(3);
  });
});

describe.each(file.vectors.map((vector) => [vector.name, vector] as const))("vector %s", (_name, vector) => {
  const { inputs, outputs } = vector;
  const keys = ml_kem768.keygen(hex(inputs.mlkemSeed));
  const S = b64(inputs.nodeKey.publicKey);
  const K = b64(inputs.clientKey.publicKey);
  const E = b64(inputs.sessionKey.publicKey);

  it("has consistent WireGuard test keys", () => {
    for (const pair of [inputs.nodeKey, inputs.clientKey, inputs.sessionKey]) {
      expect(publicKeyFromPrivate(pair.privateKey)).toBe(pair.publicKey);
    }
  });

  it("derives ek from the seed (noble keygen)", () => {
    expect(toHex(keys.publicKey)).toBe(outputs.encapsulationKey);
    expect(createHash("sha256").update(keys.publicKey).digest("hex")).toBe(outputs.encapsulationKeySha256);
  });

  it("reproduces the deterministic ciphertext (noble encapsulate with the vector randomness)", () => {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(keys.publicKey, hex(inputs.encapsRandomness));
    expect(toHex(cipherText)).toBe(outputs.ciphertext);
    expect(toHex(sharedSecret)).toBe(outputs.sharedSecret);
  });

  it("decapsulates ss, builds th, psk and confirm", () => {
    const ss = ml_kem768.decapsulate(hex(outputs.ciphertext), keys.secretKey);
    expect(toHex(ss)).toBe(outputs.sharedSecret);
    const th = transcript({
      nodeKey: S,
      clientKey: K,
      sessionKey: E,
      tunnelIpv4: inputs.tunnelIpv4,
      encapsulationKey: keys.publicKey,
      ciphertext: hex(outputs.ciphertext),
    });
    expect(th.toString("hex")).toBe(outputs.transcriptHash);
    const { psk, confirm } = derive(ss, th);
    expect(psk.toString("hex")).toBe(outputs.psk);
    expect(psk.toString("base64")).toBe(outputs.pskBase64);
    expect(confirm.toString("hex")).toBe(outputs.confirm);
  });

  it("tampered ciphertext: implicit rejection gives other ss/psk and a confirm that does not match", () => {
    const tampered = outputs.tamperedCiphertext;
    const ct = hex(tampered.ciphertext);
    expect(ct[0]).toBe((hex(outputs.ciphertext)[0] ?? 0) ^ 1);
    const ss = ml_kem768.decapsulate(ct, ml_kem768.keygen(hex(inputs.mlkemSeed)).secretKey);
    expect(toHex(ss)).toBe(tampered.sharedSecret);
    const th = transcript({ nodeKey: S, clientKey: K, sessionKey: E, tunnelIpv4: inputs.tunnelIpv4, encapsulationKey: keys.publicKey, ciphertext: ct });
    expect(th.toString("hex")).toBe(tampered.transcriptHash);
    const { psk, confirm } = derive(ss, th);
    expect(psk.toString("hex")).toBe(tampered.psk);
    expect(confirm.toString("hex")).toBe(tampered.confirm);
    expect(confirmMatches(confirm, hex(outputs.confirm))).toBe(false);
    expect(confirmMatches(hex(outputs.confirm), hex(outputs.confirm))).toBe(true);
  });

  it("encodes HELLO and STATUS_REQUEST byte-exactly", () => {
    expect(encodeHello(E, keys.publicKey).toString("hex")).toBe(outputs.helloFrame);
    expect(encodeHello(E, keys.publicKey).length).toBe(1226);
    expect(encodeStatusRequest(E).toString("hex")).toBe(outputs.statusRequestFrame);
  });

  it("decodes RESPONSE and STATUS_RESPONSE", () => {
    const response = decodeResponse(hex(outputs.responseFrame));
    expect(hex(outputs.responseFrame).length).toBe(1130);
    expect(response.kemId).toBe(KEM_ML_KEM_768);
    expect(response.ciphertext.toString("hex")).toBe(outputs.ciphertext);
    expect(response.confirm.toString("hex")).toBe(outputs.confirm);
    const status = decodeStatus(hex(outputs.statusResponseFrame));
    expect(status.state).toBe(2);
    expect(status.sessionKey.equals(E)).toBe(true);
  });
});

describe("error frames", () => {
  it.each(file.errorFrames.map((entry) => [entry.name, entry] as const))("%s", (_name, entry) => {
    expect(decodeError(hex(entry.errorFrame))).toEqual({ type: "error", code: entry.code, retryAfterS: entry.retryAfterS });
  });
});
