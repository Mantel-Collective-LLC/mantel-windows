import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { HelperCommandError, type HelperCall, type HelperResponse } from "../platform/macos/helper-client";
import { VpnError } from "../vpn-error";

export type RelayConfig = {
  server: string;
  pin: string;
  token: string;
};

export type RelayState = "connecting" | "connected" | "retrying";
export type RelayFailure = "rejected" | "pin" | "network";

export type Relay = {
  readonly port: number;
  state: () => RelayState;
  failure: () => RelayFailure | null;
  onExit: (listener: () => void) => void;
  stop: () => void;
  readonly detached?: boolean;
  release?: () => void;
};

export type StartRelay = (config: RelayConfig) => Promise<Relay>;

const START_TIMEOUT_MS = 5000;
const KILL_AFTER_MS = 2000;

export function sidecarRelay(binary: string, args: readonly string[] = []): StartRelay {
  return (config) =>
    new Promise<Relay>((resolve, reject) => {
      let child: ChildProcessWithoutNullStreams;
      try {
        child = spawn(binary, [...args], { stdio: "pipe", windowsHide: true, shell: false, env: { PATH: process.env.PATH ?? "" } });
      } catch (error) {
        reject(missing(error));
        return;
      }
      let state: RelayState = "connecting";
      let failure: RelayFailure | null = null;
      let port = 0;
      let stopped = false;
      let exited = false;
      const exitListeners: Array<() => void> = [];
      const timer = setTimeout(() => {
        child.kill();
        reject(missing(new Error("no answer")));
      }, START_TIMEOUT_MS);

      const relay: Relay = {
        get port() {
          return port;
        },
        state: () => state,
        failure: () => failure,
        onExit: (listener) => {
          if (exited && !stopped) listener();
          else exitListeners.push(listener);
        },
        stop: () => {
          if (stopped || exited) return;
          stopped = true;
          child.stdin.end();
          setTimeout(() => {
            if (!exited) child.kill();
          }, KILL_AFTER_MS).unref();
        },
      };

      child.on("error", (error) => {
        clearTimeout(timer);
        reject(missing(error));
      });
      child.on("exit", () => {
        exited = true;
        clearTimeout(timer);
        if (port === 0) reject(missing(new Error("ended before listening")));
        if (!stopped) for (const listener of exitListeners.splice(0)) listener();
      });
      child.stdin.on("error", () => undefined);
      child.stderr.resume();
      createInterface({ input: child.stdout }).on("line", (line) => {
        const event = parseEvent(line);
        if (!event) return;
        if (event.event === "listening" && port === 0) {
          port = event.port;
          clearTimeout(timer);
          resolve(relay);
        } else if (event.event === "state") {
          state = event.state;
          failure = event.state === "retrying" ? (event.reason ?? "network") : event.state === "connected" ? null : failure;
        } else if (event.event === "error") {
          clearTimeout(timer);
          reject(missing(new Error(event.error)));
        }
      });
      child.stdin.write(`${JSON.stringify(config)}\n`);
    });
}

type SidecarEvent =
  | { event: "listening"; port: number }
  | { event: "state"; state: RelayState; reason?: RelayFailure }
  | { event: "error"; error: string };

const STATES = new Set<string>(["connecting", "connected", "retrying"]);
const FAILURES = new Set<string>(["rejected", "pin", "network"]);

export function parseEvent(line: string): SidecarEvent | null {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  const record = value as Record<string, unknown>;
  if (record.event === "listening" && Number.isInteger(record.port) && (record.port as number) > 0 && (record.port as number) < 65536) {
    return { event: "listening", port: record.port as number };
  }
  if (record.event === "state" && typeof record.state === "string" && STATES.has(record.state)) {
    const reason = typeof record.reason === "string" && FAILURES.has(record.reason) ? (record.reason as RelayFailure) : undefined;
    return { event: "state", state: record.state as RelayState, ...(reason ? { reason } : {}) };
  }
  if (record.event === "error" && typeof record.error === "string") return { event: "error", error: record.error.slice(0, 200) };
  return null;
}

function missing(error: unknown): VpnError {
  const details = error instanceof Error ? error.message : String(error);
  return new VpnError("obfsRelayFailed", "internal", { details: details.slice(0, 200) });
}

export const NO_RELAY: StartRelay = () => Promise.reject(missing(new Error("not available")));

export type ServiceRelay = { start: StartRelay; attach: () => Promise<Relay | null> };

const SERVICE_POLL_MS = 3000;

export function serviceRelay(call: HelperCall, fallback: StartRelay): ServiceRelay {
  let current: Relay | null = null;

  const handle = (port: number, initial: RelayState, reason: RelayFailure | null, claim: boolean): Relay => {
    let state = initial;
    let failure = reason;
    let ended = false;
    const exitListeners: Array<() => void> = [];
    const end = (notify: boolean) => {
      if (ended) return;
      ended = true;
      clearInterval(timer);
      if (current === relay) current = null;
      if (notify) for (const listener of exitListeners.splice(0)) listener();
    };
    const timer = setInterval(() => {
      call({ op: "relay-status" }).then(
        (response) => {
          const info = response.relay;
          if (!info || info.port !== port) return end(true);
          state = info.state;
          failure = info.state === "retrying" ? (info.reason ?? "network") : info.state === "connected" ? null : failure;
        },
        () => undefined,
      );
    }, SERVICE_POLL_MS);
    timer.unref?.();
    const relay: Relay = {
      detached: true,
      port,
      state: () => state,
      failure: () => failure,
      onExit: (listener) => exitListeners.push(listener),
      release: () => end(false),
      stop: () => {
        const owned = current === relay;
        end(false);
        if (owned) void call({ op: "relay-stop" }).catch(() => undefined);
      },
    };
    if (claim || current === null) current = relay;
    return relay;
  };

  const relayOf = (response: HelperResponse, claim: boolean): Relay | null => {
    const info = response.relay;
    return info ? handle(info.port, info.state, info.state === "retrying" ? (info.reason ?? "network") : null, claim) : null;
  };

  return {
    start: async (config) => {
      let response: HelperResponse;
      try {
        response = await call({ op: "relay-start" }, Buffer.from(JSON.stringify(config), "utf8"));
      } catch (error) {
        if (error instanceof HelperCommandError && error.code === "invalid" && /unknown op|payload not expected/.test(error.detail)) {
          return fallback(config);
        }
        throw missing(error);
      }
      const relay = relayOf(response, true);
      if (!relay) throw missing(new Error("service answered without a relay"));
      return relay;
    },
    attach: async () => relayOf(await call({ op: "relay-status" }), false),
  };
}
