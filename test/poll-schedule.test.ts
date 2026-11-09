import { describe, expect, it } from "vitest";
import { nextPollDelay, POLL_HIDDEN_MS, POLL_VISIBLE_MS, singleFlight, waitUntil } from "../src/main/poll-schedule";

describe("nextPollDelay", () => {
  it("window visible: every second, faster only right after a phase change", () => {
    expect([0, 1, 2, 3, 10].map((step) => nextPollDelay({ visible: true, step }))).toEqual([300, 600, 1000, 1000, 1000]);
    expect(nextPollDelay({ visible: true, step: 50 })).toBe(POLL_VISIBLE_MS);
  });

  it("tray/minimized: backs off from 300 ms to the slow pace, never faster than visible", () => {
    const delays = Array.from({ length: 8 }, (_, step) => nextPollDelay({ visible: false, step }));
    expect(delays).toEqual([300, 600, 1200, 2500, 5000, 10_000, POLL_HIDDEN_MS, POLL_HIDDEN_MS]);
    expect(POLL_HIDDEN_MS).toBeGreaterThanOrEqual(10_000);
    for (let step = 0; step < 10; step += 1) {
      expect(nextPollDelay({ visible: false, step })).toBeGreaterThanOrEqual(nextPollDelay({ visible: true, step }));
    }
  });
});

describe("waitUntil", () => {
  it("asks with growing pauses (150, 300, 600, then 1 s) instead of every 300 ms", async () => {
    let now = 0;
    const pauses: number[] = [];
    let asked = 0;
    const result = await waitUntil(
      async () => ++asked,
      (value) => value >= 6,
      20_000,
      async (ms) => {
        pauses.push(ms);
        now += ms;
      },
      () => now,
    );
    expect(result).toBe(6);
    expect(pauses).toEqual([150, 300, 600, 1000, 1000]);
  });

  it("gives up at the deadline with the last answer; a met predicate costs one request", async () => {
    let now = 0;
    let asked = 0;
    const query = async () => ++asked;
    const sleep = async (ms: number) => {
      now += ms;
    };
    expect(await waitUntil(query, () => false, 3000, sleep, () => now)).toBe(asked);
    expect(asked).toBe(6);
    asked = 0;
    expect(await waitUntil(query, () => true, 3000, sleep, () => now)).toBe(1);
  });
});

describe("singleFlight", () => {
  it("concurrent callers share one call; the next call after it settled runs again", async () => {
    let calls = 0;
    let release: () => void = () => undefined;
    const shared = singleFlight(() => {
      calls += 1;
      return new Promise<number>((resolve) => {
        release = () => resolve(calls);
      });
    });
    const both = Promise.all([shared(), shared(), shared()]);
    release();
    expect(await both).toEqual([1, 1, 1]);
    const next = shared();
    release();
    expect(await next).toBe(2);
  });

  it("a failed call is not cached", async () => {
    let calls = 0;
    const shared = singleFlight(async () => {
      calls += 1;
      if (calls === 1) throw new Error("down");
      return calls;
    });
    await expect(shared()).rejects.toThrow("down");
    expect(await shared()).toBe(2);
  });
});
