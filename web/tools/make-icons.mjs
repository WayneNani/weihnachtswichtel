// Generates the app icons (gift box) as SVG and PNG into public/ – Node standard library only.
//   node tools/make-icons.mjs
import { writeFileSync } from "node:fs";
import { deflateSync } from "node:zlib";

const RED = [14, 42, 32]; // evergreen background (also fills the bow loops)
const CREAM = [255, 247, 236];
const GOLD = [230, 184, 74];
const SHADE = [236, 222, 204];

// Shapes in a 512×512 coordinate system, painted in order.
const shapes = (maskable) => {
  const s = maskable ? 0.78 : 1; // keep content in the maskable safe zone
  const t = (v) => 256 + (v - 256) * s;
  const R = (x0, y0, x1, y1, color, r = 0) => ({ kind: "rect", x0: t(x0), y0: t(y0), x1: t(x1), y1: t(y1), r: r * s, color });
  const C = (cx, cy, rx, ry, color) => ({ kind: "ellipse", cx: t(cx), cy: t(cy), rx: rx * s, ry: ry * s, color });
  return [
    { kind: "rect", x0: 0, y0: 0, x1: 512, y1: 512, r: maskable ? 0 : 104, color: RED },
    C(206, 150, 54, 38, GOLD),
    C(306, 150, 54, 38, GOLD),
    C(212, 152, 26, 16, RED),
    C(300, 152, 26, 16, RED),
    R(144, 236, 368, 420, CREAM, 14),
    R(144, 236, 368, 262, SHADE),
    R(120, 176, 392, 246, CREAM, 14),
    R(234, 176, 278, 420, GOLD),
    C(256, 168, 26, 22, GOLD),
  ];
};

function inside(sh, x, y) {
  if (sh.kind === "ellipse") {
    const dx = (x - sh.cx) / sh.rx;
    const dy = (y - sh.cy) / sh.ry;
    return dx * dx + dy * dy <= 1;
  }
  if (x < sh.x0 || x > sh.x1 || y < sh.y0 || y > sh.y1) return false;
  const r = sh.r;
  if (!r) return true;
  const cx = x < sh.x0 + r ? sh.x0 + r : x > sh.x1 - r ? sh.x1 - r : x;
  const cy = y < sh.y0 + r ? sh.y0 + r : y > sh.y1 - r ? sh.y1 - r : y;
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}

function render(size, maskable) {
  const list = shapes(maskable);
  const ss = 4;
  const px = new Uint8Array(size * size * 4);
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < ss; sy++)
        for (let sx = 0; sx < ss; sx++) {
          const u = ((x + (sx + 0.5) / ss) * 512) / size;
          const v = ((y + (sy + 0.5) / ss) * 512) / size;
          let col = null;
          for (const sh of list) if (inside(sh, u, v)) col = sh.color;
          if (col) {
            r += col[0];
            g += col[1];
            b += col[2];
            a += 255;
          }
        }
      const n = ss * ss;
      const i = (y * size + x) * 4;
      const cov = a / n / 255;
      px[i] = cov ? Math.round(r / n / cov) : 0;
      px[i + 1] = cov ? Math.round(g / n / cov) : 0;
      px[i + 2] = cov ? Math.round(b / n / cov) : 0;
      px[i + 3] = Math.round(a / n);
    }
  return px;
}

const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(buf) {
  let c = -1;
  for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
function chunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, "ascii");
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}
function png(size, maskable) {
  const px = render(size, maskable);
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    Buffer.from(px.buffer, y * size * 4, size * 4).copy(raw, y * (size * 4 + 1) + 1);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function svg() {
  const hex = (c) => `#${c.map((v) => v.toString(16).padStart(2, "0")).join("")}`;
  const parts = shapes(false).map((sh) =>
    sh.kind === "ellipse"
      ? `<ellipse cx="${sh.cx}" cy="${sh.cy}" rx="${sh.rx}" ry="${sh.ry}" fill="${hex(sh.color)}"/>`
      : `<rect x="${sh.x0}" y="${sh.y0}" width="${sh.x1 - sh.x0}" height="${sh.y1 - sh.y0}"${sh.r ? ` rx="${sh.r}"` : ""} fill="${hex(sh.color)}"/>`,
  );
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">${parts.join("")}</svg>\n`;
}

const dir = new URL("../public/", import.meta.url);
writeFileSync(new URL("icon.svg", dir), svg());
writeFileSync(new URL("icon-192.png", dir), png(192, false));
writeFileSync(new URL("icon-512.png", dir), png(512, false));
writeFileSync(new URL("icon-maskable-512.png", dir), png(512, true));
writeFileSync(new URL("apple-touch-icon.png", dir), png(180, true));
console.log("Icons geschrieben: public/icon.svg, icon-192.png, icon-512.png, icon-maskable-512.png, apple-touch-icon.png");
