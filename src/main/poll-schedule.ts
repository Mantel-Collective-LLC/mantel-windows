export const POLL_VISIBLE_MS = 1000;
export const POLL_HIDDEN_MS = 15_000;
export const POLL_BURST_MS = [300, 600, 1200, 2500, 5000, 10_000] as const;

export function nextPollDelay(input: { visible: boolean; step: number }): number {
  const base = input.visible ? POLL_VISIBLE_MS : POLL_HIDDEN_MS;
  return Math.min(base, POLL_BURST_MS[input.step] ?? base);
}

const WAIT_DELAYS_MS = [150, 300, 600] as const;
const WAIT_MAX_MS = 1000;

export async function waitUntil<T>(
  query: () => Promise<T>,
  predicate: (value: T) => boolean,
  timeoutMs: number,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now: () => number = Date.now,
): Promise<T> {
  const deadline = now() + timeoutMs;
  let last = await query();
  for (let attempt = 0; !predicate(last) && now() < deadline; attempt += 1) {
    await sleep(WAIT_DELAYS_MS[attempt] ?? WAIT_MAX_MS);
    last = await query();
  }
  return last;
}

export function singleFlight<T>(task: () => Promise<T>): () => Promise<T> {
  let running: Promise<T> | null = null;
  return () => {
    running ??= task().finally(() => {
      running = null;
    });
    return running;
  };
}
