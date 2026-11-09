import { mkdtempSync, readdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PqError } from "../src/main/pq/errors";
import { inertEntries, phase1Entries, phase2Entries, runPqUpgrade } from "../src/main/pq/flow";
import {
  base64Line,
  classifyWgResult,
  lockedSecretFiles,
  parseLatestHandshakes,
  scrubWgOutput,
  sweepSecretFiles,
  WgExeControl,
  WgExeError,
  wgFailureOf,
  wgSetArgs,
  type SecretFiles,
} from "../src/main/pq/wgexe";
import { publicKeyFromPrivate } from "../src/main/wireguard/keys";
import { FakeWg, parseSetArgs } from "./fake-wg";
import { FakeNode, virtualClock } from "./pq-helpers";

const S = "h2lcXP+HuIipSc5D9u5MMVC139EotqrfTZ6u/c++XwA=";
const K_PRIVATE = "pSR7d2h8H6wS0RjX9z/ftpIAVDAsuu/flQQStRtweZ0=";
const K = "pLLGZN3M20E9HOfCw9BTwB1UWPNJLHZEkJS0Bi4uKxw=";
const X = "10.8.0.2";
const TUNNEL = "mantel-test";
const ENDPOINT = "198.51.100.7:51820";

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(path.join(tmpdir(), "mantel-wgexe-"));
});
afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
});

function tempSecrets(): SecretFiles & { readonly locks: number } {
  let locks = 0;
  const files = lockedSecretFiles(directory, {
    lock: async () => {
      locks++;
    },
  });
  return {
    ...files,
    get locks() {
      return locks;
    },
  };
}

describe("base64Line / scrub / classify", () => {
  it("encodes like Buffer.toString('base64') plus newline", () => {
    for (const length of [0, 1, 2, 3, 31, 32, 33]) {
      const bytes = randomBytes(length);
      expect(base64Line(bytes).toString("latin1")).toBe(`${bytes.toString("base64")}\n`);
    }
  });

  it("never keeps key-shaped text from wg.exe output", () => {
    const hex = "ab".repeat(32);
    const scrubbed = scrubWgOutput(`Key is not the correct length or format: \`${K_PRIVATE}'\n${hex}`);
    expect(scrubbed).not.toContain(K_PRIVATE);
    expect(scrubbed).not.toContain(hex);
    expect(scrubbed).toContain("<key>");
  });

  it("maps wg.exe failures", () => {
    expect(classifyWgResult({ code: 0, stdout: "", stderr: "" })).toBeNull();
    expect(classifyWgResult({ code: -1, stdout: "", stderr: "spawn C:\\WG\\wg.exe ENOENT" })?.failure).toBe("missing");
    expect(classifyWgResult({ code: 1, stdout: "", stderr: "Unable to access interface: Access is denied." })?.failure).toBe("access");
    expect(classifyWgResult({ code: 1, stdout: "", stderr: "Unable to access interface: No such file or directory" })?.failure).toBe("no_tunnel");
    expect(classifyWgResult({ code: 1, stdout: "", stderr: "Unable to modify interface: Invalid argument" })?.failure).toBe("rejected");
    const wrapped = new PqError("pq_failed", { cause: new Error("x", { cause: new WgExeError("access", "d") }) });
    expect(wgFailureOf(wrapped)?.failure).toBe("access");
  });
});

describe("wgSetArgs", () => {
  const files: Buffer[] = [];
  const secretFile = async (secret: Uint8Array) => {
    files.push(Buffer.from(secret));
    return `C:\\key${files.length}`;
  };
  beforeEach(() => {
    files.length = 0;
  });

  it("phase 1: K, peer S removed and re-created with migration PSK, only the PQ endpoint routed", async () => {
    const psk = randomBytes(32);
    const args = await wgSetArgs(
      TUNNEL,
      phase1Entries({ clientPrivateKey: Buffer.from(K_PRIVATE, "base64"), nodeKey: Buffer.from(S, "base64"), presharedKey: psk, endpoint: ENDPOINT }),
      secretFile,
    );
    expect(args).toEqual([
      "set", TUNNEL, "private-key", "C:\\key1",
      "peer", S, "remove",
      "peer", S, "preshared-key", "C:\\key2", "endpoint", ENDPOINT, "persistent-keepalive", "25", "allowed-ips", "10.8.255.1/32",
    ]);
    expect(files[0]!.toString("base64")).toBe(K_PRIVATE);
    expect(files[1]!.equals(psk)).toBe(true);
    expect(args.join(" ")).not.toContain(K_PRIVATE);
    expect(args.join(" ")).not.toContain(psk.toString("base64"));
  });

  it("phase 2: session key E and PQ PSK in one call, full AllowedIPs joined", async () => {
    const e = randomBytes(32);
    const psk = randomBytes(32);
    const args = await wgSetArgs(
      TUNNEL,
      phase2Entries({ sessionPrivateKey: e, nodeKey: Buffer.from(S, "base64"), psk, endpoint: "[2001:db8::1]:51820", allowedIps: ["0.0.0.0/0", "::/0"] }),
      secretFile,
    );
    expect(args).toEqual([
      "set", TUNNEL, "private-key", "C:\\key1",
      "peer", S, "remove",
      "peer", S, "preshared-key", "C:\\key2", "endpoint", "[2001:db8::1]:51820", "persistent-keepalive", "25", "allowed-ips", "0.0.0.0/0,::/0",
    ]);
    expect(files[0]!.equals(e) && files[1]!.equals(psk)).toBe(true);
  });

  it("inert: only removes the node peer", async () => {
    expect(await wgSetArgs(TUNNEL, inertEntries(Buffer.from(S, "base64")), secretFile)).toEqual(["set", TUNNEL, "peer", S, "remove"]);
    expect(files).toHaveLength(0);
  });

  it("rejects what wg.exe could misread: bad names, endpoints, keys, order, unknown keys", async () => {
    const key = Buffer.from(S, "base64");
    await expect(wgSetArgs("bad name", [], secretFile)).rejects.toThrow(WgExeError);
    await expect(wgSetArgs(TUNNEL, [["public_key", key], ["endpoint", "-x 1:2"]], secretFile)).rejects.toThrow(/endpoint/);
    await expect(wgSetArgs(TUNNEL, [["public_key", key], ["allowed_ip", "0.0.0.0/0,1.2.3.4/32"]], secretFile)).rejects.toThrow(/allowed_ip/);
    await expect(wgSetArgs(TUNNEL, [["public_key", key.subarray(0, 31)]], secretFile)).rejects.toThrow(/32 raw bytes/);
    await expect(wgSetArgs(TUNNEL, [["public_key", key], ["private_key", key]], secretFile)).rejects.toThrow(/after a peer/);
    await expect(wgSetArgs(TUNNEL, [["fwmark", 1]], secretFile)).rejects.toThrow(/unsupported/);
  });
});

describe("parseLatestHandshakes", () => {
  it("parses peers; 0 = never", () => {
    const device = parseLatestHandshakes(`${S}\t1761200000\r\n${K}\t0\n`);
    expect(device.peers).toMatchObject([
      { publicKey: S, lastHandshakeAt: 1761200000_000 },
      { publicKey: K, lastHandshakeAt: null },
    ]);
    expect(parseLatestHandshakes("").peers).toEqual([]);
  });

  it("refuses unexpected output (e.g. a dump with keys)", () => {
    expect(() => parseLatestHandshakes(`${K_PRIVATE}\t${S}\t51820\toff\n`)).toThrow(WgExeError);
  });
});

describe("lockedSecretFiles", () => {
  it("writes base64 + newline, locks once, wipes and deletes", async () => {
    const secrets = tempSecrets();
    const secret = randomBytes(32);
    const first = await secrets.write(secret);
    const second = await secrets.write(secret);
    expect(path.dirname(first)).toBe(directory);
    expect(first).not.toBe(second);
    expect(secrets.locks).toBe(1);
    expect(parseSetArgs(["private-key", first]).privateKey!.equals(secret)).toBe(true);
    await secrets.remove(first);
    await secrets.remove(second);
    await secrets.remove(second);
    expect(readdirSync(directory)).toEqual([]);
  });

  it("sweeps key files a crash left behind before the first write, keeps other files", async () => {
    writeFileSync(path.join(directory, "deadbeef.key"), `${K_PRIVATE}\n`);
    writeFileSync(path.join(directory, "other.txt"), "x");
    const secrets = tempSecrets();
    const file = await secrets.write(randomBytes(32));
    expect(readdirSync(directory).sort()).toEqual([path.basename(file), "other.txt"].sort());
    writeFileSync(path.join(directory, "again.key"), "x");
    expect(await sweepSecretFiles(directory)).toBe(2);
    expect(readdirSync(directory)).toEqual(["other.txt"]);
    expect(await sweepSecretFiles(path.join(directory, "missing"))).toBe(0);
  });

  it("a failing lock writes nothing and is retried next time", async () => {
    let fail = true;
    const secrets = lockedSecretFiles(directory, {
      lock: async () => {
        if (fail) throw new Error("icacls failed");
      },
    });
    await expect(secrets.write(randomBytes(32))).rejects.toThrow(/icacls/);
    expect(readdirSync(directory)).toEqual([]);
    fail = false;
    await secrets.remove(await secrets.write(randomBytes(32)));
  });
});

describe("WgExeControl", () => {
  it("one wg.exe call per transaction; key files exist only during the call", async () => {
    const wg = new FakeWg({ tunnel: TUNNEL });
    const seenDuring: boolean[] = [];
    const secrets = tempSecrets();
    const run = wg.run;
    const control = new WgExeControl({
      tunnel: TUNNEL,
      runner: async (args) => {
        seenDuring.push(...args.filter((arg) => arg.endsWith(".key")).map((file) => existsSync(file)));
        return run(args);
      },
      secrets,
    });
    const psk = randomBytes(32);
    await control.set(phase1Entries({ clientPrivateKey: Buffer.from(K_PRIVATE, "base64"), nodeKey: Buffer.from(S, "base64"), presharedKey: psk, endpoint: ENDPOINT }));
    expect(wg.calls).toHaveLength(1);
    expect(seenDuring).toEqual([true, true]);
    expect(readdirSync(directory)).toEqual([]);
    expect(wg.privateKey?.toString("base64")).toBe(K_PRIVATE);
    expect(wg.peers.get(S)).toMatchObject({ endpoint: ENDPOINT, keepalive: 25, allowedIps: ["10.8.255.1/32"] });
    expect(wg.peers.get(S)?.presharedKey?.equals(psk)).toBe(true);
  });

  it("failures: typed error, key files still deleted, nothing secret in the message", async () => {
    const wg = new FakeWg({ tunnel: TUNNEL });
    const control = new WgExeControl({ tunnel: TUNNEL, runner: wg.run, secrets: tempSecrets() });
    wg.failWith = { code: 1, stdout: "", stderr: `Key is not the correct length or format: \`${K_PRIVATE}'` };
    const error = await control.set([["private_key", Buffer.from(K_PRIVATE, "base64")]]).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(WgExeError);
    expect((error as Error).message).not.toContain(K_PRIVATE);
    expect(readdirSync(directory)).toEqual([]);

    wg.failWith = { code: 1, stdout: "", stderr: "Unable to access interface: Access is denied." };
    await expect(control.get()).rejects.toMatchObject({ failure: "access" });

    wg.failWith = null;
    const other = new WgExeControl({ tunnel: "other", runner: wg.run, secrets: tempSecrets() });
    await expect(other.get()).rejects.toMatchObject({ failure: "no_tunnel" });
  });
});

describe("runPqUpgrade over wg.exe", () => {
  let node: FakeNode;
  beforeEach(async () => {
    node = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X });
    await node.start();
  });
  afterEach(async () => {
    await node.stop();
  });

  const FAST = { connectMs: 1000, responseMs: 1000, handshakeMs: 2000, statusMs: 2000, pollMs: 250, statusConnectMs: 500 };

  function setup() {
    const clock = virtualClock();
    const wg = new FakeWg({ tunnel: TUNNEL, handshakeAfterKeyChange: () => Math.floor(clock.now() / 1000) });
    const control = new WgExeControl({ tunnel: TUNNEL, runner: wg.run, secrets: tempSecrets() });
    const states: string[] = [];
    const options = {
      wireguard: control,
      dial: node.dial,
      nodeKey: S,
      clientKey: K,
      tunnelIpv4: X,
      endpoint: ENDPOINT,
      clientPrivateKey: K_PRIVATE,
      allowedIps: ["0.0.0.0/0"],
      onQuantum: (state: string) => states.push(state),
      clock,
      timeouts: FAST,
    };
    return { wg, options, states };
  }

  it("active: device runs as E with the node's PSK and full AllowedIPs; no key file left", async () => {
    const { wg, options, states } = setup();
    const result = await runPqUpgrade(options);
    expect(states).toEqual(["negotiating", "active"]);
    expect(result.sessionPublicKey).toBe(node.hellos[0]!.sessionKey.toString("base64"));
    expect(publicKeyFromPrivate(wg.privateKey!.toString("base64"))).toBe(result.sessionPublicKey);
    const peer = wg.peers.get(S)!;
    expect(peer.presharedKey?.equals(node.psks[0]!)).toBe(true);
    expect(peer.allowedIps).toEqual(["0.0.0.0/0"]);
    expect(wg.calls.filter((call) => call[0] === "set")).toHaveLength(2);
    expect(wg.calls.some((call) => call.includes("dump"))).toBe(false);
    expect(readdirSync(directory)).toEqual([]);
  });

  it("phase 2 refused by wg.exe: pq_not_active, node peer removed (fail closed), no key file left", async () => {
    const { wg, options } = setup();
    wg.failSetIndex = 1;
    const error = await runPqUpgrade(options).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(PqError);
    expect((error as PqError).code).toBe("pq_not_active");
    expect(wgFailureOf(error)?.failure).toBe("rejected");
    expect(wg.peers.has(S)).toBe(false);
    expect(wg.calls.at(-1)).toEqual(["set", TUNNEL, "peer", S, "remove"]);
    expect(readdirSync(directory)).toEqual([]);
  });

  it("phase 1 refused (e.g. adapter gone): pq_failed before any exchange", async () => {
    const { wg, options } = setup();
    wg.failSetIndex = 0;
    const error = await runPqUpgrade(options).catch((caught: unknown) => caught);
    expect((error as PqError).code).toBe("pq_failed");
    expect(node.hellos).toHaveLength(0);
    expect(wg.peers.has(S)).toBe(false);
  });
});
