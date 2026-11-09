import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { serviceRelay, type Relay, type StartRelay } from "../src/main/obfs/relay";
import { HelperCommandError, type HelperCall, type HelperRequest, type HelperResponse } from "../src/main/platform/macos/helper-client";

type Sent = { op: string; payload?: string };

function fakeService() {
  const sent: Sent[] = [];
  let relay: HelperResponse["relay"] = undefined;
  let port = 50000;
  let old = false;
  const call: HelperCall = async (request: HelperRequest, payload?: Buffer) => {
    sent.push({ op: request.op, payload: payload?.toString("utf8") });
    if (old && request.op.startsWith("relay-")) {
      throw new HelperCommandError("invalid", request.op === "relay-start" ? 'payload not expected/missing for "relay-start"' : "unknown op");
    }
    switch (request.op) {
      case "relay-start":
        relay = { port: ++port, state: "connecting" };
        return { ok: true, relay };
      case "relay-stop":
        relay = undefined;
        return { ok: true };
      case "relay-status":
        return { ok: true, ...(relay ? { relay } : {}) };
    }
    return { ok: true };
  };
  return {
    call,
    sent,
    set: (next: HelperResponse["relay"]) => {
      relay = next;
    },
    old: () => {
      old = true;
    },
  };
}

const config = { server: "198.51.100.7:443", pin: "q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJq80=", token: "obfs-token-1" };

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("serviceRelay", () => {
  it("starts in the service with the secrets only as payload and follows its state", async () => {
    const service = fakeService();
    const relay = await serviceRelay(service.call, vi.fn()).start(config);
    expect(relay).toMatchObject({ port: 50001, detached: true });
    expect(service.sent[0]).toEqual({ op: "relay-start", payload: JSON.stringify(config) });
    expect(relay.state()).toBe("connecting");
    service.set({ port: 50001, state: "retrying", reason: "pin" });
    await vi.advanceTimersByTimeAsync(3000);
    expect([relay.state(), relay.failure()]).toEqual(["retrying", "pin"]);
    service.set({ port: 50001, state: "connected" });
    await vi.advanceTimersByTimeAsync(3000);
    expect([relay.state(), relay.failure()]).toEqual(["connected", null]);
    relay.stop();
    expect(service.sent.at(-1)?.op).toBe("relay-stop");
  });

  it("a relay gone from the service (service restarted) ends the handle once", async () => {
    const service = fakeService();
    const relay = await serviceRelay(service.call, vi.fn()).start(config);
    const exited = vi.fn();
    relay.onExit(exited);
    service.set(undefined);
    await vi.advanceTimersByTimeAsync(6000);
    expect(exited).toHaveBeenCalledTimes(1);
  });

  it("a replaced relay's handle never stops the new one (location switch)", async () => {
    const service = fakeService();
    const relays = serviceRelay(service.call, vi.fn());
    const first = await relays.start(config);
    const second = await relays.start({ ...config, server: "198.51.100.8:443" });
    first.stop();
    expect(service.sent.filter((entry) => entry.op === "relay-stop")).toHaveLength(0);
    second.stop();
    expect(service.sent.filter((entry) => entry.op === "relay-stop")).toHaveLength(1);
  });

  it("attach takes over a running relay after an app restart, none when the service holds nothing", async () => {
    const service = fakeService();
    const relays = serviceRelay(service.call, vi.fn());
    expect(await relays.attach()).toBeNull();
    service.set({ port: 50007, state: "connected" });
    const attached = (await relays.attach()) as Relay;
    expect(attached).toMatchObject({ port: 50007, detached: true });
    attached.stop();
    expect(service.sent.at(-1)?.op).toBe("relay-stop");
    service.set({ port: 50008, state: "connected" });
    const raced = (await relays.attach()) as Relay;
    await relays.start(config);
    raced.release?.();
    raced.stop();
    expect(service.sent.filter((entry) => entry.op === "relay-stop")).toHaveLength(1);
  });

  it("an older service without relay ops: the mantel-obfs child process as before", async () => {
    const service = fakeService();
    service.old();
    const child = { port: 41000 } as Relay;
    const fallback: StartRelay = vi.fn(async () => child);
    const relays = serviceRelay(service.call, fallback);
    expect(await relays.start(config)).toBe(child);
    expect(fallback).toHaveBeenCalledWith(config);
    await expect(relays.attach()).rejects.toBeInstanceOf(HelperCommandError);
  });

  it("a real refusal (bad config) is an error, not a silent fallback", async () => {
    const fallback = vi.fn();
    const call: HelperCall = async () => {
      throw new HelperCommandError("invalid", "relay: invalid pin");
    };
    await expect(serviceRelay(call, fallback).start(config)).rejects.toMatchObject({ i18n: { key: "obfsRelayFailed" } });
    expect(fallback).not.toHaveBeenCalled();
  });
});
