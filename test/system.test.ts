import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { isLockedAcl, lockDirectory, lockFile, readAcl } from "../src/main/system/acl";
import { detectWireGuard } from "../src/main/system/environment";
import { generateKeyPair, publicKeyFromPrivate } from "../src/main/wireguard/keys";

const windows = process.platform === "win32";
const scratch = mkdtempSync(path.join(os.tmpdir(), "mantel-acl-"));
const user = `${process.env.USERDOMAIN ?? "."}\\${process.env.USERNAME ?? ""}`;

function restoreAccess(target: string) {
  execFileSync("icacls.exe", [target, "/grant", `${user}:(OI)(CI)F`, "/T", "/Q"], { stdio: "ignore" });
}

afterAll(() => {
  if (!existsSync(scratch)) return;
  if (windows) execFileSync("icacls.exe", [scratch, "/reset", "/T", "/C", "/Q"], { stdio: "ignore" });
  rmSync(scratch, { recursive: true, force: true });
});

describe("x25519 keys", () => {
  it("generates 32-byte base64 keys that wg.exe agrees with", () => {
    const keys = generateKeyPair();
    expect(Buffer.from(keys.privateKey, "base64")).toHaveLength(32);
    expect(publicKeyFromPrivate(keys.privateKey)).toBe(keys.publicKey);
    const wg = detectWireGuard();
    if (!wg) return;
    const derived = execFileSync(wg.wgExe, ["pubkey"], { input: `${keys.privateKey}\n`, encoding: "utf8" }).trim();
    expect(derived).toBe(keys.publicKey);
  });
});

describe.runIf(windows)("windows integration", () => {
  it("detects WireGuard in Program Files", () => {
    const fake = detectWireGuard(() => false);
    expect(fake).toBeNull();
    const real = detectWireGuard();
    expect(real === null || real.wireguardExe.endsWith("wireguard.exe")).toBe(true);
  });

  it("locks a directory and file to SYSTEM and Administrators", async () => {
    const directory = path.join(scratch, "Mantel");
    const file = path.join(directory, "mantel.conf");
    await lockDirectory(directory, { setOwner: false });
    const dirAcl = await readAcl(directory);
    expect(isLockedAcl(dirAcl)).toBe(true);
    expect(dirAcl.map((entry) => entry.sid).sort()).toEqual(["S-1-5-18", "S-1-5-32-544"]);

    restoreAccess(directory);
    writeFileSync(file, "");
    await lockFile(file);
    const fileAcl = await readAcl(file);
    expect(isLockedAcl(fileAcl)).toBe(true);

    const elevated = (() => {
      try {
        execFileSync("net.exe", ["session"], { stdio: "ignore" });
        return true;
      } catch {
        return false;
      }
    })();
    if (!elevated) {
      expect(() => readFileSync(file)).toThrow(/EPERM|EACCES/);
    }
  });

  it("rejects ACLs with inherited or foreign entries", () => {
    expect(isLockedAcl([{ sid: "S-1-5-18", rights: "FullControl", inherited: false, type: "Allow" }])).toBe(true);
    expect(isLockedAcl([{ sid: "S-1-5-32-545", rights: "ReadAndExecute", inherited: false, type: "Allow" }])).toBe(false);
    expect(isLockedAcl([{ sid: "S-1-5-18", rights: "FullControl", inherited: true, type: "Allow" }])).toBe(false);
    expect(isLockedAcl([])).toBe(false);
  });
});
