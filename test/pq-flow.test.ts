import { readFileSync } from "node:fs";
import { createServer, connect, type AddressInfo } from "node:net";
import path from "node:path";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { afterEach, describe, expect, it } from "vitest";
import { PqAttemptError, PqError } from "../src/main/pq/errors";
import { checkStatus, runExchange, type Kem } from "../src/main/pq/exchange";
import { negotiate, runPqUpgrade, sessionStillActive, type PqUpgradeOptions } from "../src/main/pq/flow";
import { FrameType } from "../src/main/pq/protocol";
import { errorFrame, FakeNode, FakeWireGuard, frame, statusFrame, tamperResponse, virtualClock, type FakeNodeOptions } from "./pq-helpers";

const vectors = JSON.parse(readFileSync(path.join(__dirname, "fixtures/pq-test-vectors.json"), "utf8")) as {
  vectors: {
    inputs: { mlkemSeed: string; nodeKey: { publicKey: string }; clientKey: { publicKey: string }; sessionKey: { privateKey: string; publicKey: string }; tunnelIpv4: string };
    outputs: { helloFrame: string; responseFrame: string; psk: string };
  }[];
};
const basic = vectors.vectors[0]!;
const S = basic.inputs.nodeKey.publicKey;
const K = basic.inputs.clientKey.publicKey;
const X = basic.inputs.tunnelIpv4;

let nodes: FakeNode[] = [];
afterEach(async () => {
  await Promise.all(nodes.map((node) => node.stop()));
  nodes = [];
});

async function fakeNode(options: Partial<FakeNodeOptions> = {}): Promise<FakeNode> {
  const node = new FakeNode({ nodeKey: S, clientKey: K, tunnelIpv4: X, ...options });
  await node.start();
  nodes.push(node);
  return node;
}

const FAST = { connectMs: 1000, responseMs: 1000, handshakeMs: 2000, statusMs: 2000, pollMs: 250, statusConnectMs: 500 };

function upgradeOptions(node: FakeNode, wireguard: FakeWireGuard, clock = virtualClock()): PqUpgradeOptions & { states: string[] } {
  const states: string[] = [];
  return {
    wireguard,
    dial: node.dial,
    nodeKey: S,
    clientKey: K,
    tunnelIpv4: X,
    endpoint: "198.51.100.7:51820",
    allowedIps: ["0.0.0.0/0", "::/0"],
    onQuantum: (state) => states.push(state),
    clock,
    timeouts: FAST,
    states,
  };
}

describe("runExchange", () => {
  it("reproduces the vector end to end (deterministic keys): HELLO bytes and PSK", async () => {
    const seededKem: Kem = { keygen: () => ml_kem768.keygen(Buffer.from(basic.inputs.mlkemSeed, "hex")), decapsulate: ml_kem768.decapsulate };
    let hello: Buffer | null = null;
    const node = await fakeNode({
      onHello: (received) => {
        hello = Buffer.concat([Buffer.from("4d545051010104c20001", "hex"), received.sessionKey, received.ek]);
        return Buffer.from(basic.outputs.responseFrame, "hex");
      },
    });
    const result = await runExchange({
      dial: node.dial,
      nodeKey: S,
      clientKey: K,
      tunnelIpv4: X,
      kem: seededKem,
      generateSessionKey: () => ({
        privateKey: Buffer.from(basic.inputs.sessionKey.privateKey, "base64"),
        publicKey: Buffer.from(basic.inputs.sessionKey.publicKey, "base64"),
      }),
    });
    expect(hello!.toString("hex")).toBe(basic.outputs.helloFrame);
    expect(result.psk.toString("hex")).toBe(basic.outputs.psk);
    expect(result.session.publicKey.toString("base64")).toBe(basic.inputs.sessionKey.publicKey);
  });

  it("agrees on the PSK with an honest node (random keys)", async () => {
    const node = await fakeNode();
    const result = await runExchange({ dial: node.dial, nodeKey: S, clientKey: K, tunnelIpv4: X });
    expect(result.psk.equals(node.psks[0]!)).toBe(true);
    expect(node.hellos[0]!.sessionKey.equals(result.session.publicKey)).toBe(true);
  });

  it("detects a tampered RESPONSE (confirm mismatch) and wipes the session key", async () => {
    let session: Buffer | null = null;
    const node = await fakeNode({ onHello: (_hello, _i, honest) => tamperResponse(honest().reply) });
    const error = await runExchange({
      dial: node.dial,
      nodeKey: S,
      clientKey: K,
      tunnelIpv4: X,
      generateSessionKey: () => {
        session = Buffer.alloc(32, 9);
        return { privateKey: session, publicKey: Buffer.alloc(32, 3) };
      },
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(PqAttemptError);
    expect((error as PqAttemptError).failure).toBe("mismatch");
    expect(session!.every((byte) => byte === 0)).toBe(true);
  });

  it("maps ERROR frames (3.6)", async () => {
    const cases: [number, string, number][] = [
      [1, "unsupported", 0],
      [2, "unsupported", 0],
      [9, "unsupported", 0],
      [5, "rate_limited", 30],
      [6, "rate_limited", 2],
      [3, "retry", 0],
      [4, "retry", 0],
      [7, "retry", 0],
      [8, "retry", 0],
      [99, "retry", 0],
    ];
    for (const [code, failure, retryAfterS] of cases) {
      const node = await fakeNode({ onHello: () => errorFrame(code, retryAfterS) });
      const error = (await runExchange({ dial: node.dial, nodeKey: S, clientKey: K, tunnelIpv4: X }).catch((caught: unknown) => caught)) as PqAttemptError;
      expect(error.failure, `code ${code}`).toBe(failure);
      expect(error.retryAfterS).toBe(retryAfterS);
    }
  });

  it("treats EOF, timeouts, trailing data and wrong frames as retryable attempt failures", async () => {
    const closing = await fakeNode({ onHello: () => "close" });
    await expect(runExchange({ dial: closing.dial, nodeKey: S, clientKey: K, tunnelIpv4: X })).rejects.toMatchObject({ failure: "transport" });
    const hanging = await fakeNode({ onHello: () => "hang" });
    await expect(
      runExchange({ dial: hanging.dial, nodeKey: S, clientKey: K, tunnelIpv4: X, timeouts: { connectMs: 500, responseMs: 200 } }),
    ).rejects.toMatchObject({ failure: "transport", detail: "answer timeout" });
    const trailing = await fakeNode({ onHello: (_h, _i, honest) => Buffer.concat([honest().reply, Buffer.from([0])]) });
    await expect(runExchange({ dial: trailing.dial, nodeKey: S, clientKey: K, tunnelIpv4: X })).rejects.toMatchObject({ failure: "protocol" });
    const status = await fakeNode({ onHello: (hello) => statusFrame(2, hello.sessionKey) });
    await expect(runExchange({ dial: status.dial, nodeKey: S, clientKey: K, tunnelIpv4: X })).rejects.toMatchObject({ failure: "protocol" });
    const refused = () =>
      new Promise<never>((_resolve, reject) => {
        const socket = connect({ host: "127.0.0.1", port: 1 });
        socket.once("error", reject);
      });
    await expect(runExchange({ dial: refused, nodeKey: S, clientKey: K, tunnelIpv4: X })).rejects.toMatchObject({ failure: "transport" });
  });

  it("refuses oversized answers without buffering them", async () => {
    const server = createServer((socket) => {
      socket.on("error", () => undefined);
      socket.resume();
      socket.end(Buffer.concat([frame(FrameType.response, Buffer.alloc(1122)), Buffer.alloc(4000)]));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const dial = () =>
      new Promise<ReturnType<typeof connect>>((resolve) => {
        const socket = connect({ host: "127.0.0.1", port });
        socket.once("connect", () => resolve(socket));
      });
    await expect(runExchange({ dial, nodeKey: S, clientKey: K, tunnelIpv4: X })).rejects.toMatchObject({ failure: "protocol" });
    server.close();
  });
});

describe("checkStatus", () => {
  it("returns the state and checks the echoed key", async () => {
    const E = Buffer.alloc(32, 5).toString("base64");
    const node = await fakeNode({ onStatus: (key, index) => statusFrame(index === 0 ? 1 : 2, key) });
    expect(await checkStatus({ dial: node.dial, sessionKey: E })).toBe(1);
    expect(await checkStatus({ dial: node.dial, sessionKey: E })).toBe(2);
    const liar = await fakeNode({ onStatus: () => statusFrame(2, Buffer.alloc(32, 6)) });
    await expect(checkStatus({ dial: liar.dial, sessionKey: E })).rejects.toMatchObject({ failure: "protocol" });
    expect(await sessionStillActive(node.dial, E)).toBe(true);
    expect(await sessionStillActive(liar.dial, E)).toBe(false);
  });
});

describe("negotiate (retries, 5.3)", () => {
  it("retries with new keys after a failed attempt (pause 0.5 s)", async () => {
    const node = await fakeNode({ onHello: (_h, index, honest) => (index === 0 ? errorFrame(7) : honest().reply) });
    const clock = virtualClock();
    const result = await negotiate({ dial: node.dial, nodeKey: S, clientKey: K, tunnelIpv4: X, clock });
    expect(node.hellos).toHaveLength(2);
    expect(node.hellos[0]!.sessionKey.equals(node.hellos[1]!.sessionKey)).toBe(false);
    expect(node.hellos[0]!.ek.equals(node.hellos[1]!.ek)).toBe(false);
    expect(clock.pauses).toEqual([500]);
    expect(result.psk.equals(node.psks[0]!)).toBe(true);
  });

  it("gives up after 3 attempts with pq_failed (pauses 0.5 s, 1 s)", async () => {
    const node = await fakeNode({ onHello: () => "close" });
    const clock = virtualClock();
    const error = await negotiate({ dial: node.dial, nodeKey: S, clientKey: K, tunnelIpv4: X, clock }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(PqError);
    expect((error as PqError).code).toBe("pq_failed");
    expect(node.hellos).toHaveLength(3);
    expect(clock.pauses).toEqual([500, 1000]);
  });

  it("reports pq_mismatch when the key confirmation never matches", async () => {
    const node = await fakeNode({ onHello: (_h, _i, honest) => tamperResponse(honest().reply) });
    await expect(negotiate({ dial: node.dial, nodeKey: S, clientKey: K, tunnelIpv4: X, clock: virtualClock() })).rejects.toMatchObject({
      code: "pq_mismatch",
    });
    expect(node.hellos).toHaveLength(3);
  });

  it("stops at once on unsupported_kem / not_available (pq_unsupported)", async () => {
    for (const code of [2, 9]) {
      const node = await fakeNode({ onHello: () => errorFrame(code) });
      await expect(negotiate({ dial: node.dial, nodeKey: S, clientKey: K, tunnelIpv4: X, clock: virtualClock() })).rejects.toMatchObject({
        code: "pq_unsupported",
      });
      expect(node.hellos).toHaveLength(1);
    }
  });

  it("waits retry_after_s of rate_limited/busy within the budget", async () => {
    const node = await fakeNode({ onHello: (_h, index, honest) => (index === 0 ? errorFrame(6, 2) : honest().reply) });
    const clock = virtualClock();
    await negotiate({ dial: node.dial, nodeKey: S, clientKey: K, tunnelIpv4: X, clock });
    expect(clock.pauses).toEqual([2000]);
  });

  it("does not wait beyond the 20 s budget (rate_limited 30 s → pq_failed after one attempt)", async () => {
    const node = await fakeNode({ onHello: () => errorFrame(5, 30) });
    const clock = virtualClock();
    await expect(negotiate({ dial: node.dial, nodeKey: S, clientKey: K, tunnelIpv4: X, clock })).rejects.toMatchObject({ code: "pq_failed" });
    expect(node.hellos).toHaveLength(1);
    expect(clock.pauses).toEqual([]);
  });
});

describe("runPqUpgrade (phases, fail closed)", () => {
  it("phase 1 → exchange → phase 2 with the node's PSK → handshake → STATUS 2 → active", async () => {
    const node = await fakeNode({ onStatus: (key, index) => statusFrame(index === 0 ? 1 : 2, key) });
    const clock = virtualClock();
    const wireguard = new FakeWireGuard(S, () => clock.now());
    const options = upgradeOptions(node, wireguard, clock);
    const result = await runPqUpgrade({ ...options, presharedKey: Buffer.alloc(32, 4).toString("base64") });

    expect(wireguard.transactions).toHaveLength(2);
    const [phase1, phase2] = wireguard.transactions;
    const hexS = Buffer.from(S, "base64").toString("hex");
    expect(phase1).toEqual([
      { key: "public_key", value: hexS },
      { key: "remove", value: "true" },
      { key: "public_key", value: hexS },
      { key: "preshared_key", value: "04".repeat(32) },
      { key: "endpoint", value: "198.51.100.7:51820" },
      { key: "persistent_keepalive_interval", value: "25" },
      { key: "allowed_ip", value: "10.8.255.1/32" },
    ]);
    expect(phase2?.map((entry) => entry.key)).toEqual([
      "private_key",
      "public_key",
      "remove",
      "public_key",
      "preshared_key",
      "endpoint",
      "persistent_keepalive_interval",
      "allowed_ip",
      "allowed_ip",
    ]);
    expect(phase2?.find((entry) => entry.key === "preshared_key")?.value).toBe(node.psks[0]!.toString("hex"));
    expect(phase2?.slice(-2).map((entry) => entry.value)).toEqual(["0.0.0.0/0", "::/0"]);
    expect(result.sessionPublicKey).toBe(node.hellos[0]!.sessionKey.toString("base64"));
    expect(options.states).toEqual(["negotiating", "active"]);
    expect(node.statusRequests).toBe(2);
  });

  it("makes the tunnel inert and reports pq_failed after 3 failed exchanges (no phase 2)", async () => {
    const node = await fakeNode({ onHello: () => errorFrame(7) });
    const wireguard = new FakeWireGuard(S);
    const options = upgradeOptions(node, wireguard);
    await expect(runPqUpgrade(options)).rejects.toMatchObject({ code: "pq_failed" });
    expect(node.hellos).toHaveLength(3);
    expect(wireguard.transactions).toHaveLength(2);
    expect(wireguard.transactions.some((tx) => tx.some((entry) => entry.key === "private_key"))).toBe(false);
    expect(wireguard.last().map((entry) => entry.key)).toEqual(["public_key", "remove"]);
    expect(options.states).toEqual(["negotiating", "off"]);
  });

  it("pq_mismatch for a manipulated RESPONSE, tunnel inert", async () => {
    const node = await fakeNode({ onHello: (_h, _i, honest) => tamperResponse(honest().reply) });
    const wireguard = new FakeWireGuard(S);
    await expect(runPqUpgrade(upgradeOptions(node, wireguard))).rejects.toMatchObject({ code: "pq_mismatch" });
    expect(wireguard.last().map((entry) => entry.key)).toEqual(["public_key", "remove"]);
  });

  it("pq_unsupported when the node answers not_available", async () => {
    const node = await fakeNode({ onHello: () => errorFrame(9) });
    await expect(runPqUpgrade(upgradeOptions(node, new FakeWireGuard(S)))).rejects.toMatchObject({ code: "pq_unsupported" });
  });

  it("pq_not_active without a handshake as E", async () => {
    const node = await fakeNode();
    const wireguard = new FakeWireGuard(S, () => null);
    await expect(runPqUpgrade(upgradeOptions(node, wireguard))).rejects.toMatchObject({ code: "pq_not_active" });
    expect(wireguard.last().map((entry) => entry.key)).toEqual(["public_key", "remove"]);
    expect(node.statusRequests).toBe(0);
  });

  it("pq_not_active when the node does not know the session (STATUS 0) or never activates it", async () => {
    for (const state of [0, 1]) {
      const node = await fakeNode({ onStatus: (key) => statusFrame(state, key) });
      const clock = virtualClock();
      const wireguard = new FakeWireGuard(S, () => clock.now());
      await expect(runPqUpgrade(upgradeOptions(node, wireguard, clock))).rejects.toMatchObject({ code: "pq_not_active" });
      expect(wireguard.last().map((entry) => entry.key)).toEqual(["public_key", "remove"]);
    }
  });

  it("pq_failed when WireGuard refuses phase 1", async () => {
    const node = await fakeNode();
    const wireguard = new FakeWireGuard(S);
    wireguard.failSetAt = 0;
    await expect(runPqUpgrade(upgradeOptions(node, wireguard))).rejects.toMatchObject({ code: "pq_failed" });
    expect(node.hellos).toHaveLength(0);
  });

  it("never sends user-traffic AllowedIPs before the PSK is set", async () => {
    const node = await fakeNode();
    const clock = virtualClock();
    const wireguard = new FakeWireGuard(S, () => clock.now());
    await runPqUpgrade(upgradeOptions(node, wireguard, clock));
    for (const tx of wireguard.transactions) {
      const routes = tx.filter((entry) => entry.key === "allowed_ip").map((entry) => entry.value);
      const hasPsk = tx.some((entry) => entry.key === "preshared_key");
      if (!hasPsk) expect(routes.every((route) => route === "10.8.255.1/32")).toBe(true);
    }
  });
});
