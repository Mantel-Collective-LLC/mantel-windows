import { generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { detectWireGuard, managedWireGuardDirectory } from "../src/main/system/environment";
import {
  blake2b256Hex,
  BootstrapError,
  isTrustedSigner,
  msiArchFor,
  parseSignedReleaseList,
  pickRelease,
} from "../src/main/wireguard/bootstrap";

const signed = readFileSync(path.join(__dirname, "fixtures", "wireguard-latest.sig"), "utf8");

function signWith(body: string): { text: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const keynum = Buffer.from("0102030405060708", "hex");
  const signature = sign(null, Buffer.from(body, "utf8"), privateKey);
  return {
    text: `untrusted comment: test\n${Buffer.concat([Buffer.from("Ed"), keynum, signature]).toString("base64")}\n${body}`,
    publicKey: Buffer.concat([Buffer.from("Ed"), keynum, raw]).toString("base64"),
  };
}

describe("signed WireGuard release list", () => {
  it("verifies the official list with the official key", () => {
    const releases = parseSignedReleaseList(signed);
    expect(releases.map((release) => release.arch).sort()).toEqual(["amd64", "arm64", "x86"]);
    const amd64 = pickRelease(releases, "amd64");
    expect(amd64.file).toMatch(/^wireguard-amd64-[\d.]+\.msi$/);
    expect(amd64.blake2b256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("rejects a tampered hash line", () => {
    const tampered = signed.replace(/^[a-f0-9]{64}( {2}wireguard-amd64)/m, `${"0".repeat(64)}$1`);
    expect(tampered).not.toBe(signed);
    expect(() => parseSignedReleaseList(tampered)).toThrow(BootstrapError);
  });

  it("rejects a list signed by a different key", () => {
    const forged = signWith(`${"a".repeat(64)}  wireguard-amd64-9.9.9.msi\n`);
    expect(() => parseSignedReleaseList(forged.text)).toThrow(/fremden Schlüssel|Signatur/);
    expect(parseSignedReleaseList(forged.text, forged.publicKey)).toHaveLength(1);
  });

  it("rejects garbage", () => {
    expect(() => parseSignedReleaseList("<html>not found</html>")).toThrow(BootstrapError);
  });

  it("ignores unknown lines and picks the highest version", () => {
    const list = signWith(
      [
        `${"a".repeat(64)}  wireguard-amd64-1.9.0.msi`,
        `${"b".repeat(64)}  wireguard-amd64-1.10.0.msi`,
        `${"c".repeat(64)}  wireguard-arm64-2.0.0.msi`,
        `${"d".repeat(64)}  ../evil.msi`,
        "",
      ].join("\n"),
    );
    const releases = parseSignedReleaseList(list.text, list.publicKey);
    expect(releases).toHaveLength(3);
    expect(pickRelease(releases, "amd64").version).toBe("1.10.0");
    expect(() => pickRelease(releases, "x86")).toThrow(BootstrapError);
  });
});

describe("bootstrap helpers", () => {
  it("computes BLAKE2b-256", () => {
    expect(blake2b256Hex(new Uint8Array())).toBe("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
  });

  it("maps Node architectures to MSI names", () => {
    expect(msiArchFor("x64")).toBe("amd64");
    expect(msiArchFor("arm64")).toBe("arm64");
    expect(() => msiArchFor("mips")).toThrow(BootstrapError);
  });

  it("only trusts valid WireGuard LLC signatures", () => {
    expect(isTrustedSigner("Valid", "CN=WireGuard LLC, O=WireGuard LLC, C=US")).toBe(true);
    expect(isTrustedSigner("NotSigned", "CN=WireGuard LLC, O=WireGuard LLC")).toBe(false);
    expect(isTrustedSigner("Valid", "CN=WireGuard LLC Fake, O=Evil")).toBe(false);
    expect(isTrustedSigner("Valid", "CN=Someone Else")).toBe(false);
  });

  it("prefers the Mantel copy over a system-wide WireGuard", () => {
    const managed = managedWireGuardDirectory();
    const found = detectWireGuard(() => true);
    expect(found).toMatchObject({ directory: managed, source: "managed" });
    const systemOnly = detectWireGuard((file) => !file.startsWith(managed));
    expect(systemOnly?.source).toBe("system");
  });
});
