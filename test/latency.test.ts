import { EventEmitter } from "node:events";
import dgram, { type Socket } from "node:dgram";
import { describe, expect, it } from "vitest";
import {
  buildPingRequest,
  isPingReply,
  latencyBand,
  mapLimited,
  MEASURE_INTERVAL_MS,
  medianLatency,
  pingableNodes,
  shouldMeasure,
} from "../shared/core/latency";
import { measureTarget, measureTargets } from "../src/main/latency";
import { nodesSchema } from "../src/main/api/schemas";
import { latencyQuality } from "../shared/ui/src/lib/locations";

const MAGIC = Buffer.from("MNTP", "latin1");
const echo = {
  buildReply: (nonce: Buffer) => Buffer.concat([MAGIC, Buffer.from([1, 2, 0, 0]), nonce]),
  parseRequest: (message: Buffer) =>
    message.length === 32 && message.subarray(0, 4).equals(MAGIC) && message[4] === 1 && message[5] === 1 ? message.subarray(8, 24) : null,
  startPingServer: async ({ port, host }: { port: number; host: string }) => {
    const socket = dgram.createSocket("udp4");
    socket.on("message", (message, from) => {
      const nonce = echo.parseRequest(message);
      if (nonce) socket.send(echo.buildReply(nonce), from.port, from.address);
    });
    await new Promise<void>((resolve) => socket.bind(port, host, () => resolve()));
    return { port: socket.address().port, close: () => new Promise<void>((resolve) => socket.close(() => resolve())) };
  },
};

describe("latency rules (shared by Windows, macOS, Android)", () => {
  it("median of the answered pings, lost pings ignored, nothing answered = unknown", () => {
    expect(medianLatency([30, 12, 18])).toBe(18);
    expect(medianLatency([30, null, 12])).toBe(12);
    expect(medianLatency([null, 44.6, null])).toBe(45);
    expect(medianLatency([null, null, null])).toBeUndefined();
    expect(medianLatency([])).toBeUndefined();
    expect(medianLatency([Number.NaN, -1, Infinity])).toBeUndefined();
    expect(medianLatency([9, 11, 900])).toBe(11);
  });

  it("bands: <= 40 fast, <= 100 medium, else slow; unknown = no rating", () => {
    expect(latencyBand(0)).toBe("fast");
    expect(latencyBand(40)).toBe("fast");
    expect(latencyBand(41)).toBe("medium");
    expect(latencyBand(100)).toBe("medium");
    expect(latencyBand(101)).toBe("slow");
    expect(latencyBand(undefined)).toBeUndefined();
    expect(latencyBand(null)).toBeUndefined();
    expect(latencyBand(-3)).toBeUndefined();
    expect([latencyQuality(40), latencyQuality(41), latencyQuality(101), latencyQuality(undefined)]).toEqual(["fast", "medium", "slow", null]);
  });

  it("only reachable nodes with an echo port are measured", () => {
    const nodes = [
      { id: "a", online: true, pingPort: 51821 },
      { id: "b", online: false, pingPort: 51821 },
      { id: "c", online: true },
      { id: "d", online: true, pingPort: 0 },
      { id: "e", online: true, pingPort: 70_000 },
    ];
    expect(pingableNodes(nodes).map((node) => node.id)).toEqual(["a"]);
  });

  it("measures only without a tunnel, at start, when locations change, else every 5 minutes", () => {
    const base = { phase: "disconnected", running: false, lastAt: 1_000, now: 1_000 + MEASURE_INTERVAL_MS - 1, targetsChanged: false, hasTargets: true };
    expect(shouldMeasure({ ...base, lastAt: null })).toBe(true);
    expect(shouldMeasure(base)).toBe(false);
    expect(shouldMeasure({ ...base, now: 1_000 + MEASURE_INTERVAL_MS })).toBe(true);
    expect(shouldMeasure({ ...base, targetsChanged: true })).toBe(true);
    for (const phase of ["connecting", "connected", "stale", "disconnecting"]) {
      expect(shouldMeasure({ ...base, lastAt: null, phase })).toBe(false);
    }
    expect(shouldMeasure({ ...base, lastAt: null, running: true })).toBe(false);
    expect(shouldMeasure({ ...base, lastAt: null, hasTargets: false })).toBe(false);
  });

  it("packets match the node's echo format", () => {
    const nonce = new Uint8Array(16).map((_, index) => index + 1);
    const request = buildPingRequest(nonce);
    expect(request.length).toBe(32);
    const parsed = echo.parseRequest(Buffer.from(request));
    expect(parsed && [...parsed]).toEqual([...nonce]);
    const reply = echo.buildReply(Buffer.from(nonce));
    expect(isPingReply(reply, nonce)).toBe(true);
    expect(isPingReply(reply, new Uint8Array(16))).toBe(false);
    expect(isPingReply(reply.subarray(0, 23), nonce)).toBe(false);
    expect(isPingReply(request, nonce)).toBe(false);
    const wrongType = Buffer.from(reply);
    wrongType[5] = 1;
    expect(isPingReply(wrongType, nonce)).toBe(false);
    expect(() => buildPingRequest(new Uint8Array(15))).toThrow();
  });

  it("mapLimited keeps the order and the concurrency limit", async () => {
    let running = 0;
    let peak = 0;
    const result = await mapLimited([5, 1, 4, 2, 3, 0], 2, async (value) => {
      running += 1;
      peak = Math.max(peak, running);
      await new Promise((resolve) => setTimeout(resolve, value * 3));
      running -= 1;
      return value * 10;
    });
    expect(result).toEqual([50, 10, 40, 20, 30, 0]);
    expect(peak).toBe(2);
    expect(await mapLimited([], 4, async () => 1)).toEqual([]);
  });
});

describe("API: pingPort", () => {
  it("is optional; anything invalid counts as no echo, latencyMs null is fine", () => {
    const base = { id: "nl-ams", city: "Amsterdam", country: "NL", endpointHost: "198.51.100.4", endpointPort: 51820, online: true, latencyMs: null };
    const parsed = nodesSchema.parse([{ ...base, pingPort: 51821 }, base, { ...base, pingPort: "51821" }, { ...base, pingPort: 0 }]);
    expect(parsed.map((node) => node.pingPort)).toEqual([51821, undefined, undefined, undefined]);
    expect(parsed.every((node) => node.latencyMs === undefined)).toBe(true);
  });
});

describe("main: pings from this device", () => {
  it("measures the real echo three times over UDP", async () => {
    const server = await echo.startPingServer({ port: 0, host: "127.0.0.1" });
    try {
      const result = await measureTarget({ id: "local", host: "127.0.0.1", port: server.port });
      expect(result.id).toBe("local");
      expect(result.samples).toHaveLength(3);
      for (const sample of result.samples) {
        expect(typeof sample).toBe("number");
        expect(sample as number).toBeLessThan(1_500);
      }
      expect(medianLatency(result.samples)).toBeDefined();
    } finally {
      await server.close();
    }
  });

  it("no answer: null samples after the timeout; unresolvable host: no packet at all", async () => {
    const sent: unknown[] = [];
    const fake = () => {
      const socket = new EventEmitter() as unknown as Socket;
      Object.assign(socket, {
        send: (...args: unknown[]) => {
          sent.push(args[2]);
          (args.at(-1) as (error: Error | null) => void)(null);
        },
        close: () => undefined,
      });
      return socket;
    };
    const silent = await measureTarget({ id: "x", host: "192.0.2.1", port: 51821 }, { createSocket: fake, timeoutMs: 20 });
    expect(silent.samples).toEqual([null, null, null]);
    expect(sent).toEqual(["192.0.2.1", "192.0.2.1", "192.0.2.1"]);

    sent.length = 0;
    const unresolved = await measureTarget({ id: "y", host: "nodes.example", port: 51821 }, { createSocket: fake, resolve: async () => [], timeoutMs: 20 });
    expect(unresolved.samples).toEqual([null, null, null]);
    expect(sent).toEqual([]);

    const resolved = await measureTarget({ id: "z", host: "nodes.example", port: 51821 }, { createSocket: fake, resolve: async () => ["2001:db8::1", "198.51.100.9"], timeoutMs: 20 });
    expect(resolved.samples).toEqual([null, null, null]);
    expect(sent).toEqual(["198.51.100.9", "198.51.100.9", "198.51.100.9"]);
  });

  it("a reply with another nonce or from a stranger does not count", async () => {
    const fake = () => {
      const socket = new EventEmitter() as unknown as Socket;
      Object.assign(socket, {
        send: (_packet: Uint8Array, _port: number, _host: string, callback: (error: Error | null) => void) => {
          callback(null);
          socket.emit("message", echo.buildReply(Buffer.alloc(16, 9)));
        },
        close: () => undefined,
      });
      return socket;
    };
    const result = await measureTargets([{ id: "x", host: "192.0.2.1", port: 51821 }], { createSocket: fake, timeoutMs: 20 });
    expect(result).toEqual([{ id: "x", samples: [null, null, null] }]);
  });
});
