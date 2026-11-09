import { createServer, connect, type AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  decodeServerFrame,
  encodeHello,
  encodeStatusRequest,
  FrameType,
  parseHeader,
  PqProtocolError,
} from "../src/main/pq/protocol";
import { checkErrno, encodeSet, namedPipePath, parseGet, sanitizeResponse, tcpTransport, UapiClient } from "../src/main/pq/uapi";
import { phase1Entries, phase2Entries, inertEntries } from "../src/main/pq/flow";
import { errorFrame, frame, statusFrame } from "./pq-helpers";

const E = Buffer.alloc(32, 7);

describe("PQ frames (strict)", () => {
  it("encodes fixed sizes", () => {
    expect(encodeHello(E, Buffer.alloc(1184)).length).toBe(1226);
    expect(encodeStatusRequest(E).length).toBe(40);
    expect(() => encodeHello(Buffer.alloc(31), Buffer.alloc(1184))).toThrow(PqProtocolError);
    expect(() => encodeHello(E, Buffer.alloc(1183))).toThrow(PqProtocolError);
  });

  it("rejects wrong magic, version, type, length and trailing bytes", () => {
    const good = statusFrame(2, E);
    expect(decodeServerFrame(good)).toMatchObject({ type: "status", state: 2 });
    const badMagic = Buffer.from(good);
    badMagic[0] = 0x4e;
    expect(() => decodeServerFrame(badMagic)).toThrow(/magic/);
    const badVersion = Buffer.from(good);
    badVersion[4] = 2;
    expect(() => decodeServerFrame(badVersion)).toThrow(/version/);
    expect(() => decodeServerFrame(frame(0x05, Buffer.alloc(4)))).toThrow(/unknown type/);
    expect(() => decodeServerFrame(frame(FrameType.statusResponse, Buffer.alloc(32)))).toThrow(/length/);
    expect(() => decodeServerFrame(Buffer.concat([good, Buffer.from([0])]))).toThrow(/size/);
    expect(() => decodeServerFrame(good.subarray(0, 20))).toThrow(/size/);
    expect(() => decodeServerFrame(statusFrame(3, E))).toThrow(/state/);
    expect(() => decodeServerFrame(encodeStatusRequest(E))).toThrow(/unexpected/);
    expect(() => parseHeader(Buffer.alloc(4))).toThrow(/short/);
  });

  it("decodes ERROR frames", () => {
    expect(decodeServerFrame(errorFrame(6, 2))).toEqual({ type: "error", code: 6, retryAfterS: 2 });
  });
});

describe("UAPI", () => {
  const S = Buffer.alloc(32, 0xab);
  const psk = Buffer.alloc(32, 0x01);
  const sessionPrivate = Buffer.alloc(32, 0x02);

  it("builds phase 1: peer removed and re-added, only the PQ endpoint routed, keys hex", () => {
    const text = encodeSet(phase1Entries({ nodeKey: S, endpoint: "198.51.100.7:51820" })).toString();
    expect(text).toBe(
      [
        "set=1",
        `public_key=${"ab".repeat(32)}`,
        "remove=true",
        `public_key=${"ab".repeat(32)}`,
        "endpoint=198.51.100.7:51820",
        "persistent_keepalive_interval=25",
        "allowed_ip=10.8.255.1/32",
        "",
        "",
      ].join("\n"),
    );
    const withK = encodeSet(phase1Entries({ clientPrivateKey: Buffer.alloc(32, 0x0c), nodeKey: S, endpoint: "198.51.100.7:51820" })).toString();
    expect(withK.startsWith(`set=1\nprivate_key=${"0c".repeat(32)}\npublic_key=${"ab".repeat(32)}\nremove=true\n`)).toBe(true);
    const withMigration =encodeSet(phase1Entries({ nodeKey: S, presharedKey: psk, endpoint: "[2001:db8::1]:51820" })).toString();
    expect(withMigration).toContain(`public_key=${"ab".repeat(32)}\npreshared_key=${"01".repeat(32)}\nendpoint=[2001:db8::1]:51820\n`);
  });

  it("builds phase 2: private key E first, then the peer with PSK and the full AllowedIPs", () => {
    const lines = encodeSet(
      phase2Entries({ sessionPrivateKey: sessionPrivate, nodeKey: S, psk, endpoint: "198.51.100.7:51820", allowedIps: ["0.0.0.0/0", "::/0"] }),
    )
      .toString()
      .split("\n");
    expect(lines).toEqual([
      "set=1",
      `private_key=${"02".repeat(32)}`,
      `public_key=${"ab".repeat(32)}`,
      "remove=true",
      `public_key=${"ab".repeat(32)}`,
      `preshared_key=${"01".repeat(32)}`,
      "endpoint=198.51.100.7:51820",
      "persistent_keepalive_interval=25",
      "allowed_ip=0.0.0.0/0",
      "allowed_ip=::/0",
      "",
      "",
    ]);
    expect(encodeSet(inertEntries(S)).toString()).toBe(`set=1\npublic_key=${"ab".repeat(32)}\nremove=true\n\n`);
  });

  it("refuses line injection", () => {
    expect(() => encodeSet([["endpoint", "1.2.3.4:5\nallowed_ip=0.0.0.0/0"]])).toThrow();
    expect(() => encodeSet([["Endpoint", "x"]])).toThrow();
  });

  it("checks errno and parses get without keeping secrets", () => {
    expect(() => checkErrno("errno=1\n\n")).toThrow(/errno=1/);
    expect(() => checkErrno("\n")).toThrow(/missing/);
    const raw = Buffer.from(
      [
        `private_key=${"11".repeat(32)}`,
        "listen_port=51820",
        `public_key=${"ab".repeat(32)}`,
        `preshared_key=${"22".repeat(32)}`,
        "endpoint=198.51.100.7:51820",
        "last_handshake_time_sec=1700000000",
        "last_handshake_time_nsec=500000000",
        "rx_bytes=10",
        "tx_bytes=20",
        "persistent_keepalive_interval=25",
        "allowed_ip=0.0.0.0/0",
        `public_key=${"cd".repeat(32)}`,
        `preshared_key=${"00".repeat(32)}`,
        "errno=0",
        "",
        "",
      ].join("\n"),
    );
    const text = sanitizeResponse(raw);
    expect(raw.every((byte) => byte === 0)).toBe(true);
    expect(text).not.toContain("11".repeat(32));
    expect(text).not.toContain("22".repeat(32));
    const device = parseGet(checkErrno(text));
    expect(device.listenPort).toBe(51820);
    expect(device.peers).toHaveLength(2);
    expect(device.peers[0]).toMatchObject({
      publicKey: Buffer.alloc(32, 0xab).toString("base64"),
      endpoint: "198.51.100.7:51820",
      allowedIps: ["0.0.0.0/0"],
      lastHandshakeAt: 1_700_000_000_500,
      rxBytes: 10,
      txBytes: 20,
      persistentKeepalive: 25,
      hasPresharedKey: true,
    });
    expect(device.peers[1]).toMatchObject({ lastHandshakeAt: null, hasPresharedKey: false });
  });

  it("uses the protected named pipe of the tunnel service", () => {
    expect(namedPipePath("mantel")).toBe("\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WireGuard\\mantel");
    expect(() => namedPipePath("../x")).toThrow();
  });

  describe("client over a TCP transport (as in the E2E harness)", () => {
    let close: (() => Promise<void>) | null = null;
    afterEach(async () => {
      await close?.();
      close = null;
    });

    async function serve(answer: (request: string) => string): Promise<{ port: number; requests: string[] }> {
      const requests: string[] = [];
      const server = createServer((socket) => {
        let text = "";
        socket.on("data", (chunk) => {
          text += chunk.toString();
          if (text.endsWith("\n\n")) {
            requests.push(text);
            socket.end(answer(text));
          }
        });
      });
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      close = () => new Promise<void>((resolve) => server.close(() => resolve()));
      return { port: (server.address() as AddressInfo).port, requests };
    }

    it("sends one transaction per set and reports errno", async () => {
      const { port, requests } = await serve((request) => (request.includes("remove") ? "errno=0\n\n" : "errno=22\n\n"));
      const client = new UapiClient(tcpTransport("127.0.0.1", port));
      await client.set(inertEntries(Buffer.alloc(32, 1)));
      await expect(client.set([["listen_port", 1]])).rejects.toThrow(/errno=22/);
      expect(requests[0]).toBe(`set=1\npublic_key=${"01".repeat(32)}\nremove=true\n\n`);
    });

    it("reads get answers split over several chunks", async () => {
      const { port } = await serve(() => `public_key=${"ab".repeat(32)}\nlast_handshake_time_sec=5\nerrno=0\n\n`);
      const device = await new UapiClient(tcpTransport("127.0.0.1", port)).get();
      expect(device.peers[0]?.lastHandshakeAt).toBe(5000);
    });

    it("fails on a closed connection", async () => {
      const server = createServer((socket) => socket.resume().end());
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      close = () => new Promise<void>((resolve) => server.close(() => resolve()));
      const port = (server.address() as AddressInfo).port;
      await expect(new UapiClient(() => Promise.resolve(connect({ host: "127.0.0.1", port }))).get()).rejects.toThrow();
    });
  });
});
