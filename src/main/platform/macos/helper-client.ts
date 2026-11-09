import { connect, type Socket } from "node:net";
import { z } from "zod";

export const HELPER_PROTOCOL = 1;

const MAX_RESPONSE = 256 * 1024;

const peerSchema = z.object({
  publicKey: z.string(),
  endpoint: z.string().optional(),
  lastHandshakeMs: z.number(),
  rxBytes: z.number(),
  txBytes: z.number(),
});

export const responseSchema = z.object({
  ok: z.boolean(),
  error: z.string().optional(),
  detail: z.string().optional(),
  version: z.string().optional(),
  protocol: z.number().optional(),
  flavor: z.string().optional(),
  interface: z.string().optional(),
  tunnel: z
    .object({
      running: z.boolean(),
      interface: z.string().optional(),
      publicKey: z.string().optional(),
      peers: z.array(peerSchema),
    })
    .optional(),
  killSwitch: z.boolean().optional(),
  killSwitchRules: z.number().optional(),
  service: z.object({ exists: z.boolean(), state: z.string().optional() }).optional(),
  wireguard: z.object({ directory: z.string(), source: z.string() }).optional(),
  wireguardVersion: z.string().optional(),
  relay: z
    .object({
      port: z.number().int().min(1).max(65535),
      state: z.enum(["connecting", "connected", "retrying"]),
      reason: z.enum(["rejected", "pin", "network"]).optional(),
    })
    .optional(),
});

export type HelperResponse = z.infer<typeof responseSchema>;

export type HelperRequest =
  | { op: "hello" | "down" | "status" | "killswitch-disable" | "killswitch-status" | "install-wireguard" }
  | { op: "relay-start" | "relay-stop" | "relay-status" }
  | { op: "up"; endpoint?: string }
  | { op: "wg-set" }
  | {
      op: "killswitch-enable";
      killSwitch: {
        hosts: { address: string; tcpPorts: number[]; udpPorts: number[] }[];
        allowLan: boolean;
        tunnelAddresses?: string[];
      };
    };

export class HelperUnavailableError extends Error {
  constructor(readonly reason: string) {
    super(`helper unavailable: ${reason}`);
  }
}

export class HelperCommandError extends Error {
  constructor(
    readonly code: string,
    readonly detail: string,
  ) {
    super(`helper ${code}: ${detail}`);
  }
}

export type HelperCall = (request: HelperRequest, payload?: Buffer) => Promise<HelperResponse>;

export function helperClient(socketPath: string, timeoutMs = 60_000, header: Record<string, unknown> = {}): HelperCall {
  return (request, payload) =>
    new Promise<HelperResponse>((resolve, reject) => {
      let socket: Socket;
      let settled = false;
      const chunks: Buffer[] = [];
      let total = 0;
      const finish = (error: Error | null, value?: HelperResponse) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        payload?.fill(0);
        socket.destroy();
        if (error) reject(error);
        else resolve(value as HelperResponse);
      };
      const timer = setTimeout(() => finish(new HelperUnavailableError("timeout")), timeoutMs);
      try {
        socket = connect({ path: socketPath });
      } catch (error) {
        clearTimeout(timer);
        payload?.fill(0);
        reject(new HelperUnavailableError(error instanceof Error ? error.message : String(error)));
        return;
      }
      socket.once("error", (error: NodeJS.ErrnoException) => finish(new HelperUnavailableError(error.code ?? error.message)));
      socket.once("connect", () => {
        const body = { ...header, ...request, ...(payload ? { payloadLength: payload.length } : {}) };
        const line = Buffer.from(`${JSON.stringify(body)}\n`, "utf8");
        socket.write(payload ? Buffer.concat([line, payload]) : line);
      });
      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        total += chunk.length;
        if (total > MAX_RESPONSE) return finish(new HelperUnavailableError("response too large"));
        const data = Buffer.concat(chunks);
        const end = data.indexOf(0x0a);
        if (end < 0) return;
        let parsed: HelperResponse;
        try {
          parsed = responseSchema.parse(JSON.parse(data.subarray(0, end).toString("utf8")));
        } catch {
          return finish(new HelperUnavailableError("unexpected answer"));
        }
        if (!parsed.ok) {
          if (parsed.error === "forbidden") return finish(new HelperUnavailableError("forbidden"));
          return finish(new HelperCommandError(parsed.error ?? "system", parsed.detail ?? ""));
        }
        finish(null, parsed);
      });
      socket.once("end", () => finish(new HelperUnavailableError("closed")));
    });
}
