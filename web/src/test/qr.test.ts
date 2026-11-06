import assert from "node:assert/strict";
import { test } from "node:test";
import { b64uEncode, utf8 } from "../lib/bytes";
import { encodeQr, qrPath } from "../lib/qr";
import { sha256 } from "../lib/sha256";

const PERSONAL =
  "https://wichteln.example/g/3q2-7wAAAAAAAAAAAAAAAA#k=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE&s=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

const matrixHash = (m: boolean[][]) => b64uEncode(sha256(new Uint8Array(m.flat().map((v) => (v ? 1 : 0)))));

// Reference hashes: matrices were cross-checked module by module against the Python library
// segno 1.6.6 (with minimal terminator padding) for versions 1–39 and all ECC levels.
test("QR matrices match the cross-checked reference", () => {
  assert.equal(matrixHash(encodeQr(utf8("HELLO"), "L", 0).modules), "WGtlTLpfoZbqvsC905ODpAnZCz2uESQt3hGZc41bcI0");
  const m = encodeQr(utf8(PERSONAL), "M", 3);
  assert.equal(m.version, 8);
  assert.equal(matrixHash(m.modules), "5aGTZIMci_t5yGfyRyHOTT8P0wBW4pQhXXhjizZ3mww");
  const h = encodeQr(utf8(PERSONAL), "H", 6);
  assert.equal(h.version, 12);
  assert.equal(matrixHash(h.modules), "PYBhbscMgr6N6qSGtX1mCoy17TOJeU0sK5iTLG22Y44");
});

test("QR: smallest version, finder patterns, size limits", () => {
  const q = encodeQr(utf8("x".repeat(14)), "M");
  assert.equal(q.version, 1); // v1-M holds 14 bytes
  assert.equal(encodeQr(utf8("x".repeat(15)), "M").version, 2);
  assert.equal(q.size, 21);
  // top-left finder: dark ring, light ring, dark 3×3 core
  assert.equal(q.modules[0]![0], true);
  assert.equal(q.modules[1]![1], false);
  assert.equal(q.modules[3]![3], true);
  assert.equal(q.modules[q.size - 8]![8], true); // dark module
  assert.ok(q.mask >= 0 && q.mask < 8);
  assert.throws(() => encodeQr(new Uint8Array(3000), "M"));
  assert.ok(qrPath(q).startsWith("M"));
});
