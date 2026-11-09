import { nativeImage, type NativeImage } from "electron";
import type { TunnelPhase } from "../../shared/core/contract";

type Rgb = readonly [number, number, number];

const INK: Rgb = [24, 24, 27];
const WHITE: Rgb = [255, 255, 255];
const DOT: Record<"off" | "busy" | "on" | "warn", Rgb> = {
  off: [161, 161, 170],
  busy: [245, 158, 11],
  on: [16, 185, 129],
  warn: [239, 68, 68],
};

const STROKE: ReadonlyArray<readonly [number, number]> = [
  [7, 16.5],
  [7, 8.2],
  [12, 11.6],
  [17, 8.2],
  [17, 16.5],
];

function insideRoundedRect(px: number, py: number, size: number, radius: number): boolean {
  const cx = Math.min(Math.max(px, radius), size - radius);
  const cy = Math.min(Math.max(py, radius), size - radius);
  return (px - cx) ** 2 + (py - cy) ** 2 <= radius ** 2;
}

function distanceToSegment(px: number, py: number, a: readonly [number, number], b: readonly [number, number]): number {
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  const t = Math.max(0, Math.min(1, ((px - a[0]) * dx + (py - a[1]) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (a[0] + t * dx), py - (a[1] + t * dy));
}

function sample(u: number, v: number, dot: Rgb): { color: Rgb; alpha: number } {
  if (!insideRoundedRect(u, v, 24, 7)) return { color: INK, alpha: 0 };
  if (Math.hypot(u - 12, v - 17) <= 2.2) return { color: dot, alpha: 1 };
  for (let index = 0; index < STROKE.length - 1; index += 1) {
    const from = STROKE[index];
    const to = STROKE[index + 1];
    if (from && to && distanceToSegment(u, v, from, to) <= 1.05) return { color: WHITE, alpha: 1 };
  }
  return { color: INK, alpha: 1 };
}

export function renderLogoBitmap(size: number, dot: Rgb): Buffer {
  const samples = 4;
  const buffer = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let red = 0;
      let green = 0;
      let blue = 0;
      let alpha = 0;
      for (let sy = 0; sy < samples; sy += 1) {
        for (let sx = 0; sx < samples; sx += 1) {
          const u = ((x + (sx + 0.5) / samples) / size) * 24;
          const v = ((y + (sy + 0.5) / samples) / size) * 24;
          const hit = sample(u, v, dot);
          red += hit.color[0] * hit.alpha;
          green += hit.color[1] * hit.alpha;
          blue += hit.color[2] * hit.alpha;
          alpha += hit.alpha;
        }
      }
      const offset = (y * size + x) * 4;
      const count = samples * samples;
      const coverage = alpha / count;
      const premultiplied = (channel: number) => Math.round(channel / count);
      buffer[offset] = premultiplied(blue);
      buffer[offset + 1] = premultiplied(green);
      buffer[offset + 2] = premultiplied(red);
      buffer[offset + 3] = Math.round(coverage * 255);
    }
  }
  return buffer;
}

function dotFor(phase: TunnelPhase): Rgb {
  if (phase === "connected") return DOT.on;
  if (phase === "stale") return DOT.warn;
  if (phase === "connecting" || phase === "disconnecting") return DOT.busy;
  return DOT.off;
}

const cache = new Map<string, NativeImage>();

export function trayImage(phase: TunnelPhase): NativeImage {
  const key = phase;
  const cached = cache.get(key);
  if (cached) return cached;
  const image = nativeImage.createEmpty();
  for (const scale of [1, 1.25, 1.5, 2]) {
    const size = Math.round(16 * scale);
    image.addRepresentation({ scaleFactor: scale, width: size, height: size, buffer: renderLogoBitmap(size, dotFor(phase)) });
  }
  cache.set(key, image);
  return image;
}
