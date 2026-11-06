/**
 * Minimal QR code generator (ISO/IEC 18004, byte mode only, versions 1–40).
 * Self-contained, no network, no dependencies. Algorithm structure after Nayuki's public-domain
 * reference design (function patterns, Reed–Solomon over GF(256), mask penalty rules).
 */

export type Ecc = "L" | "M" | "Q" | "H";

const ECC_INDEX: Record<Ecc, number> = { L: 0, M: 1, Q: 2, H: 3 };
const ECC_FORMAT: Record<Ecc, number> = { L: 1, M: 0, Q: 3, H: 2 };

// prettier-ignore
const ECC_CODEWORDS_PER_BLOCK: number[][] = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
// prettier-ignore
const NUM_ERROR_CORRECTION_BLOCKS: number[][] = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

export interface QrCode {
  version: number;
  size: number;
  ecc: Ecc;
  mask: number;
  /** modules[y][x], true = dark. */
  modules: boolean[][];
}

function numRawDataModules(ver: number): number {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}

function numDataCodewords(ver: number, ecc: Ecc): number {
  const e = ECC_INDEX[ecc];
  return (
    Math.floor(numRawDataModules(ver) / 8) -
    ECC_CODEWORDS_PER_BLOCK[e]![ver]! * NUM_ERROR_CORRECTION_BLOCKS[e]![ver]!
  );
}

function alignmentPositions(ver: number, size: number): number[] {
  if (ver === 1) return [];
  const numAlign = Math.floor(ver / 7) + 2;
  const step = Math.floor((ver * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

function gfMul(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMul(result[j]!, root);
      if (j + 1 < result.length) result[j]! ^= result[j + 1]!;
    }
    root = gfMul(root, 0x02);
  }
  return result;
}

function rsRemainder(data: number[], divisor: number[]): number[] {
  const result = new Array<number>(divisor.length).fill(0);
  for (const b of data) {
    const factor = b ^ result.shift()!;
    result.push(0);
    divisor.forEach((coef, i) => {
      result[i]! ^= gfMul(coef, factor);
    });
  }
  return result;
}

function getBit(x: number, i: number): boolean {
  return ((x >>> i) & 1) !== 0;
}

/** Encodes `data` (bytes) with the smallest version that fits at the given error correction. */
export function encodeQr(data: Uint8Array, ecc: Ecc = "M", forceMask?: number): QrCode {
  let version = 0;
  for (let v = 1; v <= 40; v++) {
    const ccBits = v < 10 ? 8 : 16;
    if (data.length >= 1 << ccBits) continue;
    const needed = 4 + ccBits + data.length * 8;
    if (needed <= numDataCodewords(v, ecc) * 8) {
      version = v;
      break;
    }
  }
  if (version === 0) throw new Error("QR: Daten zu lang");

  // Bit stream: byte mode, char count, data, terminator, padding.
  const bits: number[] = [];
  const push = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  push(0b0100, 4);
  push(data.length, version < 10 ? 8 : 16);
  for (const b of data) push(b, 8);
  const capacity = numDataCodewords(version, ecc) * 8;
  push(0, Math.min(4, capacity - bits.length));
  push(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) push(pad, 8);
  const dataCodewords: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j]!;
    dataCodewords.push(b);
  }

  // Error correction and interleaving.
  const e = ECC_INDEX[ecc];
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[e]![version]!;
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[e]![version]!;
  const rawCodewords = Math.floor(numRawDataModules(version) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);
  const divisor = rsDivisor(blockEccLen);
  const blocks: number[][] = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = dataCodewords.slice(k, k + shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1));
    k += dat.length;
    const eccBytes = rsRemainder(dat, divisor);
    if (i < numShortBlocks) dat.push(0);
    blocks.push(dat.concat(eccBytes));
  }
  const allCodewords: number[] = [];
  for (let i = 0; i < blocks[0]!.length; i++) {
    blocks.forEach((block, j) => {
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) allCodewords.push(block[i]!);
    });
  }

  const size = version * 4 + 17;
  const modules: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const isFunction: boolean[][] = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const setF = (x: number, y: number, dark: boolean) => {
    modules[y]![x] = dark;
    isFunction[y]![x] = true;
  };

  // Function patterns.
  for (let i = 0; i < size; i++) {
    setF(6, i, i % 2 === 0);
    setF(i, 6, i % 2 === 0);
  }
  const finder = (x: number, y: number) => {
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const xx = x + dx;
        const yy = y + dy;
        if (xx >= 0 && xx < size && yy >= 0 && yy < size) setF(xx, yy, dist !== 2 && dist !== 4);
      }
  };
  finder(3, 3);
  finder(size - 4, 3);
  finder(3, size - 4);
  const align = alignmentPositions(version, size);
  const na = align.length;
  for (let i = 0; i < na; i++)
    for (let j = 0; j < na; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === na - 1) || (i === na - 1 && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++)
        for (let dx = -2; dx <= 2; dx++)
          setF(align[i]! + dx, align[j]! + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  const drawFormat = (mask: number) => {
    const d = (ECC_FORMAT[ecc] << 3) | mask;
    let rem = d;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const fbits = ((d << 10) | rem) ^ 0x5412;
    for (let i = 0; i <= 5; i++) setF(8, i, getBit(fbits, i));
    setF(8, 7, getBit(fbits, 6));
    setF(8, 8, getBit(fbits, 7));
    setF(7, 8, getBit(fbits, 8));
    for (let i = 9; i < 15; i++) setF(14 - i, 8, getBit(fbits, i));
    for (let i = 0; i < 8; i++) setF(size - 1 - i, 8, getBit(fbits, i));
    for (let i = 8; i < 15; i++) setF(8, size - 15 + i, getBit(fbits, i));
    setF(8, size - 8, true);
  };
  drawFormat(0);
  if (version >= 7) {
    let rem = version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const vbits = (version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = getBit(vbits, i);
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setF(a, b, bit);
      setF(b, a, bit);
    }
  }

  // Data modules in zigzag order.
  let bitIndex = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!isFunction[y]![x] && bitIndex < allCodewords.length * 8) {
          modules[y]![x] = getBit(allCodewords[bitIndex >>> 3]!, 7 - (bitIndex & 7));
          bitIndex++;
        }
      }
    }
  }

  const applyMask = (mask: number) => {
    for (let y = 0; y < size; y++)
      for (let x = 0; x < size; x++) {
        if (isFunction[y]![x]) continue;
        let invert: boolean;
        switch (mask) {
          case 0: invert = (x + y) % 2 === 0; break;
          case 1: invert = y % 2 === 0; break;
          case 2: invert = x % 3 === 0; break;
          case 3: invert = (x + y) % 3 === 0; break;
          case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
          case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          default: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
        }
        if (invert) modules[y]![x] = !modules[y]![x];
      }
  };

  let mask = forceMask ?? -1;
  if (mask < 0) {
    let best = Infinity;
    for (let m = 0; m < 8; m++) {
      applyMask(m);
      drawFormat(m);
      const p = penalty(modules, size);
      if (p < best) {
        best = p;
        mask = m;
      }
      applyMask(m); // undo (XOR)
    }
  }
  applyMask(mask);
  drawFormat(mask);
  return { version, size, ecc, mask, modules };
}

function penalty(modules: boolean[][], size: number): number {
  let result = 0;
  const N1 = 3, N2 = 3, N3 = 40, N4 = 10;
  const at = (x: number, y: number) => modules[y]![x]!;
  // Rule 1: runs of ≥ 5 same-coloured modules (rows and columns).
  for (let pass = 0; pass < 2; pass++) {
    for (let a = 0; a < size; a++) {
      let runColor = false;
      let run = 0;
      for (let b = 0; b < size; b++) {
        const c = pass === 0 ? at(b, a) : at(a, b);
        if (b === 0 || c !== runColor) {
          if (run >= 5) result += N1 + run - 5;
          runColor = c;
          run = 1;
        } else run++;
      }
      if (run >= 5) result += N1 + run - 5;
    }
  }
  // Rule 2: 2×2 blocks.
  for (let y = 0; y < size - 1; y++)
    for (let x = 0; x < size - 1; x++) {
      const c = at(x, y);
      if (c === at(x + 1, y) && c === at(x, y + 1) && c === at(x + 1, y + 1)) result += N2;
    }
  // Rule 3: finder-like patterns 1:1:3:1:1 with 4 light modules on one side.
  const pattern = [true, false, true, true, true, false, true];
  for (let pass = 0; pass < 2; pass++) {
    for (let a = 0; a < size; a++) {
      for (let b = 0; b + 7 <= size; b++) {
        let match = true;
        for (let k = 0; k < 7 && match; k++) {
          const c = pass === 0 ? at(b + k, a) : at(a, b + k);
          if (c !== pattern[k]) match = false;
        }
        if (!match) continue;
        const light = (from: number, to: number) => {
          for (let k = from; k < to; k++) {
            if (k < 0 || k >= size) continue; // outside counts as light
            if (pass === 0 ? at(k, a) : at(a, k)) return false;
          }
          return true;
        };
        if (light(b - 4, b) || light(b + 7, b + 11)) result += N3;
      }
    }
  }
  // Rule 4: dark/light balance.
  let dark = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (at(x, y)) dark++;
  const total = size * size;
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  result += Math.max(0, k) * N4;
  return result;
}

/** SVG path data (one `M x y h1 v1 h-1 z` per dark module, merged per row run). */
export function qrPath(qr: QrCode, border = 4): string {
  let d = "";
  for (let y = 0; y < qr.size; y++) {
    let x = 0;
    while (x < qr.size) {
      if (!qr.modules[y]![x]) {
        x++;
        continue;
      }
      let w = 1;
      while (x + w < qr.size && qr.modules[y]![x + w]) w++;
      d += `M${x + border} ${y + border}h${w}v1h${-w}z`;
      x += w;
    }
  }
  return d;
}
