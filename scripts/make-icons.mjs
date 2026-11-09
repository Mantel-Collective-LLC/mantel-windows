import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const INK = [24, 24, 27];
const WHITE = [255, 255, 255];
const ACCENT = [22, 158, 117];
const STROKE = [
  [7, 16.5],
  [7, 8.2],
  [12, 11.6],
  [17, 8.2],
  [17, 16.5],
];

function insideRoundedRect(px, py, size, radius) {
  const cx = Math.min(Math.max(px, radius), size - radius);
  const cy = Math.min(Math.max(py, radius), size - radius);
  return (px - cx) ** 2 + (py - cy) ** 2 <= radius ** 2;
}

function distanceToSegment(px, py, a, b) {
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  const t = Math.max(0, Math.min(1, ((px - a[0]) * dx + (py - a[1]) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - (a[0] + t * dx), py - (a[1] + t * dy));
}

function sample(u, v) {
  if (!insideRoundedRect(u, v, 24, 7)) return null;
  if (Math.hypot(u - 12, v - 16.6) <= 1.4) return ACCENT;
  for (let index = 0; index < STROKE.length - 1; index += 1) {
    if (distanceToSegment(u, v, STROKE[index], STROKE[index + 1]) <= 0.9) return WHITE;
  }
  return INK;
}

function rasterize(size, inset = 0) {
  const samples = 4;
  const rgba = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const sum = [0, 0, 0, 0];
      for (let sy = 0; sy < samples; sy += 1) {
        for (let sx = 0; sx < samples; sx += 1) {
          const scale = 1 - 2 * inset;
          const u = ((x + (sx + 0.5) / samples) / size - inset) / scale;
          const v = ((y + (sy + 0.5) / samples) / size - inset) / scale;
          const color = u < 0 || u > 1 || v < 0 || v > 1 ? null : sample(u * 24, v * 24);
          if (!color) continue;
          sum[0] += color[0];
          sum[1] += color[1];
          sum[2] += color[2];
          sum[3] += 1;
        }
      }
      const offset = (y * size + x) * 4;
      const hits = sum[3];
      rgba[offset] = hits ? Math.round(sum[0] / hits) : 0;
      rgba[offset + 1] = hits ? Math.round(sum[1] / hits) : 0;
      rgba[offset + 2] = hits ? Math.round(sum[2] / hits) : 0;
      rgba[offset + 3] = Math.round((hits / (samples * samples)) * 255);
    }
  }
  return rgba;
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, payload) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), payload]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

function png(size, inset = 0) {
  const rgba = rasterize(size, inset);
  const rows = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y += 1) {
    rows[y * (size * 4 + 1)] = 0;
    rgba.copy(rows, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(rows, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function ico(sizes) {
  const images = sizes.map((size) => ({ size, data: png(size) }));
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = 6 + images.length * 16;
  const entries = images.map(({ size, data }) => {
    const entry = Buffer.alloc(16);
    entry[0] = size >= 256 ? 0 : size;
    entry[1] = size >= 256 ? 0 : size;
    entry.writeUInt16LE(1, 4);
    entry.writeUInt16LE(32, 6);
    entry.writeUInt32LE(data.length, 8);
    entry.writeUInt32LE(offset, 12);
    offset += data.length;
    return entry;
  });
  return Buffer.concat([header, ...entries, ...images.map((image) => image.data)]);
}

const out = path.join(root, "build");
mkdirSync(out, { recursive: true });
writeFileSync(path.join(out, "icon.png"), png(512));
writeFileSync(path.join(out, "icon.ico"), ico([16, 24, 32, 48, 64, 128, 256]));

function icns() {
  const entries = [
    ["icp4", 16],
    ["icp5", 32],
    ["icp6", 64],
    ["ic07", 128],
    ["ic08", 256],
    ["ic09", 512],
    ["ic10", 1024],
    ["ic11", 32],
    ["ic12", 64],
    ["ic13", 256],
    ["ic14", 512],
  ].map(([type, size]) => {
    const data = png(size, 0.1);
    const header = Buffer.alloc(8);
    header.write(type, 0, "ascii");
    header.writeUInt32BE(data.length + 8, 4);
    return Buffer.concat([header, data]);
  });
  const header = Buffer.alloc(8);
  header.write("icns", 0, "ascii");
  header.writeUInt32BE(8 + entries.reduce((sum, entry) => sum + entry.length, 0), 4);
  return Buffer.concat([header, ...entries]);
}
writeFileSync(path.join(out, "icon.icns"), icns());
process.stdout.write("build/icon.png, build/icon.ico und build/icon.icns erzeugt\n");
