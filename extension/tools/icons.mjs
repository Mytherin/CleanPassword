// Draws the extension's icons (a white keyhole on a blue rounded square) as
// PNGs, so no image files need to be kept in the repository.
//
//   node tools/icons.mjs <out-dir>

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { deflateSync } from "node:zlib";

const out = process.argv[2];
mkdirSync(out, { recursive: true });

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, pixel) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixel(x, y);
      const o = y * (size * 4 + 1) + 1 + x * 4;
      raw[o] = r; raw[o + 1] = g; raw[o + 2] = b; raw[o + 3] = a;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

// Coverage of a shape at a pixel, by 4×4 supersampling.
function cover(inside, x, y, n = 4) {
  let c = 0;
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) if (inside(x + (i + 0.5) / n, y + (j + 0.5) / n)) c++;
  return c / (n * n);
}

// node tools/icons.mjs <out-dir> [sizes, e.g. 1024] [opaque]
// "opaque": a full square (iOS rounds app icons itself, and wants no alpha).
const sizes = process.argv[3] ? process.argv[3].split(",").map(Number) : [16, 32, 48, 128];
const opaque = process.argv[4] === "opaque";
for (const size of sizes) {
  const s = size;
  const r = s * 0.22;
  const square = (x, y) => {
    const cx = Math.min(Math.max(x, r), s - r);
    const cy = Math.min(Math.max(y, r), s - r);
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
  };
  const hole = (x, y) => {
    const cx = s / 2, cy = s * 0.42, rr = s * 0.15;
    const circle = (x - cx) ** 2 + (y - cy) ** 2 <= rr * rr;
    const t = (y - cy) / (s * 0.36);
    const stem = y >= cy && y <= s * 0.76 && Math.abs(x - cx) <= s * (0.06 + 0.05 * t);
    return circle || stem;
  };
  const buf = png(s, (x, y) => {
    const a = opaque ? 1 : cover(square, x, y);
    const k = cover(hole, x, y);
    const top = [10, 132, 255], bottom = [0, 96, 223];
    const g = y / s;
    const bg = top.map((c, i) => Math.round(c * (1 - g) + bottom[i] * g));
    const col = bg.map((c) => Math.round(c * (1 - k) + 255 * k));
    return [...col, Math.round(a * 255)];
  });
  writeFileSync(join(out, `${size}.png`), buf);
}
console.log(`Icons written to ${out}`);
