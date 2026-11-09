import { blake2b } from "@noble/hashes/blake2.js";
import { createPublicKey, randomBytes, verify } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { LocalizedError, type ErrorKey, type Params } from "../../../shared/core/i18n";
import { assertLocked, lockDirectory } from "../system/acl";
import { managedWireGuardDirectory, programDataDirectory } from "../system/environment";
import { POWERSHELL, run, system32 } from "../system/exec";

export const RELEASE_HOST = "https://download.wireguard.com";
export const RELEASE_LIST_URL = `${RELEASE_HOST}/windows-client/latest.sig`;
export const RELEASE_PUBLIC_KEY = "RWRNqGKtBXftKTKPpBPGDMe8jHLnFQ0EdRy8Wg0apV6vTDFLAODD83G4";
export const RELEASE_SIGNER = "CN=WireGuard LLC";

const MAX_LIST_BYTES = 64 * 1024;
const MAX_MSI_BYTES = 64 * 1024 * 1024;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const RELEASE_LINE = /^([a-f0-9]{64}) {2}(wireguard-(amd64|arm64|x86)-(\d+(?:\.\d+){1,3})\.msi)$/;

export type MsiArch = "amd64" | "arm64" | "x86";

export type Release = {
  file: string;
  arch: MsiArch;
  version: string;
  blake2b256: string;
};

export type BootstrapStep = "download" | "verify" | "extract" | "install";

export class BootstrapError extends LocalizedError {
  constructor(
    key: ErrorKey,
    readonly kind: "network" | "integrity" | "system",
    params?: Params,
  ) {
    super(key, params);
  }
}

function decodeSignifyBlob(base64: string, length: number, invalid: ErrorKey): Buffer {
  const blob = Buffer.from(base64.trim(), "base64");
  if (blob.length !== length || blob.subarray(0, 2).toString("latin1") !== "Ed") {
    throw new BootstrapError(invalid, "integrity");
  }
  return blob;
}

export function parseSignedReleaseList(text: string, publicKeyBase64: string = RELEASE_PUBLIC_KEY): Release[] {
  const first = text.indexOf("\n");
  const second = first === -1 ? -1 : text.indexOf("\n", first + 1);
  if (first === -1 || second === -1 || !text.startsWith("untrusted comment:")) {
    throw new BootstrapError("releaseListFormat", "integrity");
  }
  const signature = decodeSignifyBlob(text.slice(first + 1, second), 74, "releaseSignatureInvalid");
  const publicKey = decodeSignifyBlob(publicKeyBase64, 42, "releaseKeyInvalid");
  if (!signature.subarray(2, 10).equals(publicKey.subarray(2, 10))) {
    throw new BootstrapError("releaseForeignKey", "integrity");
  }
  const message = Buffer.from(text.slice(second + 1), "utf8");
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey.subarray(10)]),
    format: "der",
    type: "spki",
  });
  if (!verify(null, message, key, signature.subarray(10))) {
    throw new BootstrapError("releaseSignatureMismatch", "integrity");
  }
  const releases: Release[] = [];
  for (const line of message.toString("utf8").split("\n")) {
    const match = RELEASE_LINE.exec(line.trim());
    if (!match) continue;
    const [, hash, file, arch, version] = match;
    if (hash && file && arch && version) {
      releases.push({ file, arch: arch as MsiArch, version, blake2b256: hash });
    }
  }
  return releases;
}

function compareVersions(a: string, b: string): number {
  const left = a.split(".").map(Number);
  const right = b.split(".").map(Number);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const diff = (left[index] ?? 0) - (right[index] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

export function pickRelease(releases: readonly Release[], arch: MsiArch): Release {
  const candidates = releases.filter((release) => release.arch === arch);
  const best = candidates.sort((a, b) => compareVersions(b.version, a.version))[0];
  if (!best) throw new BootstrapError("releaseNoVersion", "integrity", { arch });
  return best;
}

export function msiArchFor(nodeArch: string = process.arch): MsiArch {
  if (nodeArch === "x64") return "amd64";
  if (nodeArch === "arm64") return "arm64";
  if (nodeArch === "ia32") return "x86";
  throw new BootstrapError("unsupportedArch", "system", { arch: nodeArch });
}

export function blake2b256Hex(data: Uint8Array): string {
  return Buffer.from(blake2b(data, { dkLen: 32 })).toString("hex");
}

async function download(url: string, maxBytes: number): Promise<Buffer> {
  let response: Response;
  try {
    response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(120_000) });
  } catch {
    throw new BootstrapError("downloadUnreachable", "network");
  }
  if (!response.ok || !response.body) {
    throw new BootstrapError("downloadFailed", "network", { status: response.status });
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new BootstrapError("downloadTooLarge", "integrity");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

const SIGNATURE_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "$sig = Get-AuthenticodeSignature -LiteralPath $env:MANTEL_SIGNED_FILE",
  "$subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }",
  "ConvertTo-Json -Compress -InputObject @{ status = [string]$sig.Status; subject = [string]$subject }",
].join("\n");

export function isTrustedSigner(status: string, subject: string): boolean {
  return status === "Valid" && (subject === RELEASE_SIGNER || subject.startsWith(`${RELEASE_SIGNER},`));
}

export async function assertSignedByWireGuard(file: string): Promise<void> {
  const result = await run(
    POWERSHELL(),
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SIGNATURE_SCRIPT],
    { timeoutMs: 60_000, env: { MANTEL_SIGNED_FILE: file } },
  );
  if (result.code !== 0) throw new BootstrapError("signatureUnreadable", "system", { file: path.win32.basename(file) });
  const parsed = JSON.parse(result.stdout.trim() || "{}") as { status?: unknown; subject?: unknown };
  if (!isTrustedSigner(String(parsed.status ?? ""), String(parsed.subject ?? ""))) {
    throw new BootstrapError("signatureUntrusted", "integrity", { file: path.win32.basename(file) });
  }
}

export async function installManagedWireGuard(onStep: (step: BootstrapStep) => void = () => undefined): Promise<string> {
  onStep("download");
  const list = await download(RELEASE_LIST_URL, MAX_LIST_BYTES);
  const release = pickRelease(parseSignedReleaseList(list.toString("utf8")), msiArchFor());
  const msi = await download(`${RELEASE_HOST}/windows-client/${release.file}`, MAX_MSI_BYTES);

  onStep("verify");
  if (blake2b256Hex(msi) !== release.blake2b256) {
    throw new BootstrapError("downloadMismatch", "integrity");
  }

  onStep("extract");
  const root = programDataDirectory();
  await lockDirectory(root, { setOwner: true });
  await assertLocked(root);
  const staging = path.win32.join(root, `.wireguard-${randomBytes(6).toString("hex")}`);
  try {
    await lockDirectory(staging, { setOwner: true });
    await assertLocked(staging);
    const msiPath = path.win32.join(staging, release.file);
    const extractDir = path.win32.join(staging, "extract");
    if (/[\s"]/.test(extractDir)) {
      throw new BootstrapError("pathHasSpaces", "system", { path: extractDir });
    }
    await writeFile(msiPath, msi, { flag: "wx" });
    await assertSignedByWireGuard(msiPath);
    const extracted = await run(system32("msiexec.exe"), ["/a", msiPath, "/qn", `TARGETDIR=${extractDir}`], {
      timeoutMs: 180_000,
    });
    if (extracted.code !== 0 && extracted.code !== 3010) {
      throw new BootstrapError("extractFailed", "system", { code: extracted.code });
    }
    const source = path.win32.join(extractDir, "WireGuard");
    for (const binary of ["wireguard.exe", "wg.exe"]) {
      const file = path.win32.join(source, binary);
      if (!existsSync(file)) throw new BootstrapError("binaryMissing", "integrity", { binary });
      await assertSignedByWireGuard(file);
    }

    onStep("install");
    const target = managedWireGuardDirectory();
    await rm(target, { recursive: true, force: true });
    await mkdir(path.win32.dirname(target), { recursive: true });
    await rename(source, target);
    await lockDirectory(target, { setOwner: true });
    await assertLocked(target);
    return release.version;
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
  }
}
