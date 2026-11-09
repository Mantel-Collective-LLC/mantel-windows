import { LocalizedError } from "../../../shared/core/i18n";
import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";

export type KeyPair = { privateKey: string; publicKey: string };

function rawFromJwk(key: KeyObject, field: "d" | "x"): string {
  const jwk = key.export({ format: "jwk" });
  const value = jwk[field];
  if (typeof value !== "string") throw new LocalizedError("keyExportFailed");
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== 32) throw new LocalizedError("keyLength");
  return raw.toString("base64");
}

export function generateKeyPair(): KeyPair {
  const pair = generateKeyPairSync("x25519");
  return { privateKey: rawFromJwk(pair.privateKey, "d"), publicKey: rawFromJwk(pair.publicKey, "x") };
}

export function generateRawKeyPair(): { privateKey: Buffer; publicKey: Buffer } {
  const pair = generateKeyPairSync("x25519");
  return {
    privateKey: Buffer.from(rawFromJwk(pair.privateKey, "d"), "base64"),
    publicKey: Buffer.from(rawFromJwk(pair.publicKey, "x"), "base64"),
  };
}

export function publicKeyFromPrivate(privateKey: string): string {
  const raw = Buffer.from(privateKey, "base64");
  if (raw.length !== 32) throw new LocalizedError("keyLength");
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), raw]);
  const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return rawFromJwk(createPublicKey(key), "x");
}
