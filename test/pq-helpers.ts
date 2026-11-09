import { createServer, connect, type AddressInfo, type Server, type Socket } from "node:net";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import type { Dial } from "../src/main/pq/exchange";
import type { Clock } from "../src/main/pq/flow";
import { derive, transcript } from "../src/main/pq/kdf";
import { CT_SIZE, EK_SIZE, FrameType, HEADER_SIZE, KEY_SIZE, PQ_MAGIC } from "../src/main/pq/protocol";
import type { UapiDevice, UapiEntry, WireGuardControl } from "../src/main/pq/uapi";

export function frame(type: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(HEADER_SIZE);
  PQ_MAGIC.copy(header);
  header[4] = 1;
  header[5] = type;
  header.writeUInt16BE(payload.length, 6);
  return Buffer.concat([header, payload]);
}

export function errorFrame(code: number, retryAfterS = 0): Buffer {
  const payload = Buffer.alloc(4);
  payload.writeUInt16BE(code, 0);
  payload.writeUInt16BE(retryAfterS, 2);
  return frame(FrameType.error, payload);
}

export function statusFrame(state: number, sessionKey: Buffer): Buffer {
  return frame(FrameType.statusResponse, Buffer.concat([Buffer.from([state]), sessionKey]));
}

export type Hello = { sessionKey: Buffer; ek: Buffer };

export type Reply = Buffer | "close" | "hang";

export type FakeNodeOptions = {
  nodeKey: string;
  clientKey: string;
  tunnelIpv4: string;
  onHello?: (hello: Hello, index: number, honest: () => { reply: Buffer; psk: Buffer }) => Reply;
  onStatus?: (sessionKey: Buffer, index: number) => Reply;
};

export class FakeNode {
  hellos: Hello[] = [];
  statusRequests = 0;
  psks: Buffer[] = [];
  private server: Server | null = null;
  private sockets = new Set<Socket>();
  port = 0;

  constructor(private readonly options: FakeNodeOptions) {}

  async start(): Promise<void> {
    this.server = createServer((socket) => this.handle(socket));
    await new Promise<void>((resolve) => this.server?.listen(0, "127.0.0.1", resolve));
    this.port = (this.server.address() as AddressInfo).port;
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }

  dial: Dial = () =>
    new Promise((resolve, reject) => {
      const socket = connect({ host: "127.0.0.1", port: this.port });
      socket.once("error", reject);
      socket.once("connect", () => resolve(socket));
    });

  honest(hello: Hello): { reply: Buffer; psk: Buffer } {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(hello.ek);
    const th = transcript({
      nodeKey: Buffer.from(this.options.nodeKey, "base64"),
      clientKey: Buffer.from(this.options.clientKey, "base64"),
      sessionKey: hello.sessionKey,
      tunnelIpv4: this.options.tunnelIpv4,
      encapsulationKey: hello.ek,
      ciphertext: cipherText,
    });
    const { psk, confirm } = derive(sharedSecret, th);
    const kem = Buffer.from([0, 1]);
    return { reply: frame(FrameType.response, Buffer.concat([kem, Buffer.from(cipherText), confirm])), psk };
  }

  private handle(socket: Socket): void {
    this.sockets.add(socket);
    socket.on("close", () => this.sockets.delete(socket));
    socket.on("error", () => undefined);
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < HEADER_SIZE) return;
      const type = buffer[5];
      const length = buffer.readUInt16BE(6);
      if (buffer.length < HEADER_SIZE + length) return;
      const payload = buffer.subarray(HEADER_SIZE, HEADER_SIZE + length);
      let reply: Reply = "close";
      if (type === FrameType.hello) {
        const hello = { sessionKey: Buffer.from(payload.subarray(2, 2 + KEY_SIZE)), ek: Buffer.from(payload.subarray(2 + KEY_SIZE, 2 + KEY_SIZE + EK_SIZE)) };
        this.hellos.push(hello);
        const index = this.hellos.length - 1;
        const honest = () => {
          const result = this.honest(hello);
          this.psks.push(result.psk);
          return result;
        };
        reply = this.options.onHello ? this.options.onHello(hello, index, honest) : honest().reply;
      } else if (type === FrameType.statusRequest) {
        const sessionKey = Buffer.from(payload);
        reply = this.options.onStatus ? this.options.onStatus(sessionKey, this.statusRequests) : statusFrame(2, sessionKey);
        this.statusRequests++;
      }
      if (reply === "hang") return;
      if (reply === "close") socket.end();
      else socket.end(reply);
    });
  }
}

export function tamperResponse(reply: Buffer): Buffer {
  const copy = Buffer.from(reply);
  copy[HEADER_SIZE + 2] = (copy[HEADER_SIZE + 2] ?? 0) ^ 1;
  return copy;
}

export const CT_OFFSET = HEADER_SIZE + 2;
export const CT_END = CT_OFFSET + CT_SIZE;

export class FakeWireGuard implements WireGuardControl {
  transactions: { key: string; value: string }[][] = [];
  handshakeAt: number | null = null;
  failSetAt: number | null = null;
  handshakeAfterPhase2: (() => number | null) | null;

  constructor(
    private readonly nodeKey: string,
    handshakeAfterPhase2: (() => number | null) | null = () => Date.now(),
  ) {
    this.handshakeAfterPhase2 = handshakeAfterPhase2;
  }

  async set(entries: readonly UapiEntry[]): Promise<void> {
    if (this.failSetAt === this.transactions.length) throw new Error("UAPI errno=1");
    this.transactions.push(
      entries.map(([key, value]) => ({ key, value: value instanceof Uint8Array ? Buffer.from(value).toString("hex") : String(value) })),
    );
    if (entries.some(([key]) => key === "private_key")) this.handshakeAt = this.handshakeAfterPhase2?.() ?? null;
  }

  async get(): Promise<UapiDevice> {
    return {
      listenPort: 51820,
      peers: [
        {
          publicKey: this.nodeKey,
          endpoint: null,
          allowedIps: [],
          lastHandshakeAt: this.handshakeAt,
          rxBytes: 0,
          txBytes: 0,
          persistentKeepalive: 25,
          hasPresharedKey: true,
        },
      ],
    };
  }

  last(): { key: string; value: string }[] {
    return this.transactions[this.transactions.length - 1] ?? [];
  }
}

export function virtualClock(start = Date.now()): Clock & { pauses: number[]; time: () => number } {
  let now = start;
  const pauses: number[] = [];
  return {
    now: () => now,
    sleep: async (ms) => {
      pauses.push(ms);
      now += ms;
    },
    pauses,
    time: () => now,
  };
}
