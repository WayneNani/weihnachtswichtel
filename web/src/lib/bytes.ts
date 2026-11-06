/** Byte helpers: Base64url (RFC 4648 §5, no padding), UTF-8, concat, compare. */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

export function b64uEncode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

/** Strict decoder: rejects padding, foreign characters and non-canonical trailing bits. */
export function b64uDecode(text: string): Uint8Array {
  if (text.length % 4 === 1) throw new Error("base64url: ungültige Länge");
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    const v = c < 128 ? LOOKUP[c]! : -1;
    if (v < 0) throw new Error("base64url: ungültiges Zeichen");
    acc = ((acc << 6) | v) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Error("base64url: nicht kanonisch");
  return out.subarray(0, o);
}

/** Decodes and checks the exact length; returns null on any error. */
export function b64uDecodeLen(text: string | null | undefined, len: number): Uint8Array | null {
  if (typeof text !== "string") return null;
  try {
    const b = b64uDecode(text);
    return b.length === len ? b : null;
  } catch {
    return null;
  }
}

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });
export const utf8 = (s: string): Uint8Array => enc.encode(s);
export const fromUtf8 = (b: Uint8Array): string => dec.decode(b);
export const utf8Len = (s: string): number => enc.encode(s).length;

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}

export function u32be(x: number): Uint8Array {
  return new Uint8Array([(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255]);
}

/** Truncates a string so that its UTF-8 encoding is at most `max` bytes (no broken code points). */
export function truncateUtf8(s: string, max: number): string {
  if (utf8Len(s) <= max) return s;
  let out = "";
  let len = 0;
  for (const ch of s) {
    const l = utf8Len(ch);
    if (len + l > max) break;
    out += ch;
    len += l;
  }
  return out;
}
