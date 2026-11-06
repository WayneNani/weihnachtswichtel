#!/usr/bin/env node
// Tests for the built wichtel-wasm module (Node 22, standard library only).
//
//   scripts/build-wasm.sh && node scripts/test-wasm.mjs
//
// Loads the wasm produced by scripts/build-wasm.sh (cargo output, re-bound with
// `wasm-bindgen --target nodejs` into a temp directory), then
//   1. checks the test vectors crates/wichtel-core/tests/vectors/v1.json,
//   2. checks error codes (thrown WichtelError with stable `code`),
//   3. runs a complete protocol with n = 4 against an in-memory mailbox (no server),
//   4. measures run times (roles vector n = 20/30, reveal upload / HPKE seal, open_result).
//
// Environment: WICHTEL_WASM = path to wichtel_wasm.wasm (default: cargo output under
// CARGO_TARGET_DIR or ./target), WASM_BINDGEN = wasm-bindgen binary, BENCH_RUNS (default 3).

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TARGET_DIR = process.env.CARGO_TARGET_DIR || path.join(ROOT, "target");
const WASM =
  process.env.WICHTEL_WASM ||
  path.join(TARGET_DIR, "wasm32-unknown-unknown", "wasm-release", "wichtel_wasm.wasm");
const BINDGEN =
  process.env.WASM_BINDGEN ||
  (() => {
    const home = path.join(os.homedir(), ".cargo", "bin", "wasm-bindgen");
    return fs.existsSync(home) ? home : "wasm-bindgen";
  })();
const BENCH_RUNS = Number(process.env.BENCH_RUNS || 3);

// Constants (Spec §2).
const T = 16;
const L_SD = 256;
const L_CT = 560;
const L_REVEAL = L_SD + T * L_CT;
const rolesLen = (n) => 2688 * n * n;

// ---------------------------------------------------------------------------------------------
// Load module
// ---------------------------------------------------------------------------------------------

if (!fs.existsSync(WASM)) {
  console.error(`wasm not found: ${WASM}\nrun scripts/build-wasm.sh first`);
  process.exit(1);
}
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wichtel-wasm-test-"));
let w;
try {
  execFileSync(BINDGEN, ["--target", "nodejs", "--out-dir", tmp, WASM], { stdio: "inherit" });
  w = createRequire(import.meta.url)(path.join(tmp, path.basename(WASM, ".wasm") + ".js"));
} finally {
  // The module is loaded synchronously; the files are no longer needed.
  fs.rmSync(tmp, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

const b64d = (s) => new Uint8Array(Buffer.from(s, "base64url"));
const b64e = (b) => Buffer.from(b).toString("base64url");
const hex = (b) => Buffer.from(b).toString("hex");
const enc = (s) => new TextEncoder().encode(s);
const sha256 = (...parts) => {
  const h = crypto.createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
const u32 = (x) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, x);
  return b;
};
const xorInto = (acc, src) => {
  assert.equal(acc.length, src.length);
  for (let i = 0; i < acc.length; i++) acc[i] ^= src[i];
};
const random = (n) => new Uint8Array(crypto.randomBytes(n));
const eq = (a, b) => assert.equal(hex(a), hex(b));

/** Ed25519 verification with node:crypto (independent of the WASM implementation). */
function ed25519Verify(ipk, msg, sig) {
  const key = crypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: b64e(ipk) },
    format: "jwk",
  });
  return crypto.verify(null, msg, key, sig);
}
const authHash = (tok) => sha256(enc("wichtel/v1/auth-hash"), tok);
const joinMsg = (gid, ipk, idh, ah, encName, encWish) =>
  sha256(
    enc("wichtel/v1/join"), gid, ipk, idh, ah,
    u32(encName.length), encName, u32(encWish.length), encWish,
  );
const uploadMsg = (kind, gid, round, pid, body) =>
  sha256(enc("wichtel/v1/upload"), Uint8Array.of(kind), gid, u32(round), pid, sha256(body));

/** Decode the evaluation state (format: crates/wichtel-wasm/src/state.rs). */
function decodeState(s) {
  assert.equal(s[0], 1, "state version");
  const n = s[1];
  let o = 2;
  const take = (len) => s.subarray(o, (o += len));
  const gR = take(32);
  const rho = take(32);
  const recipients = Array.from({ length: n }, () => take(32));
  const mask = (s[o] << 8) | s[o + 1];
  o += 2;
  const e = s[o++];
  const p = [];
  const givers = [];
  for (let t = 0; t < T; t++) {
    if (mask & (1 << t)) {
      p.push(s[o++]);
      givers.push(Array.from({ length: n }, () => take(32)));
    } else {
      p.push(null);
      givers.push(null);
    }
  }
  assert.equal(o, s.length, "state length");
  return { n, gR, rho, recipients, e, p, givers };
}

function expectCode(code, fn) {
  assert.throws(fn, (err) => {
    assert.equal(err.name, "WichtelError", `name for ${code}: ${err}`);
    assert.equal(err.code, code, `expected ${code}, got ${err.code} (${err.message})`);
    assert.ok(err.message.startsWith(code + ": "));
    return true;
  });
}

const timings = new Map(); // label → durations (ms)
function time(label, fn, runs = 1) {
  let result;
  const ms = timings.get(label) ?? [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    result = fn();
    ms.push(performance.now() - t0);
  }
  timings.set(label, ms);
  return result;
}

let passed = 0;
function test(name, fn) {
  fn();
  passed++;
  console.log(`ok - ${name}`);
}

// ---------------------------------------------------------------------------------------------
// 1. Test vectors
// ---------------------------------------------------------------------------------------------

const V = JSON.parse(
  fs.readFileSync(path.join(ROOT, "crates/wichtel-core/tests/vectors/v1.json"), "utf8"),
);
const gidV = b64d(V.gid);
const gkV = b64d(V.gk);
const roundV = V.round;
const keysV = V.participants.map((p) => w.deriveKeys(b64d(p.seed), gidV));
const rosterV = V.participants.map((p) => ({
  pid: b64d(p.pid),
  ipk: b64d(p.ipk),
  idh: b64d(p.idh),
  encName: b64d(p.enc_name),
}));
const nV = rosterV.length;

test("basics", () => {
  assert.equal(w.protocolVersion(), V.version);
  assert.deepEqual(w.participantLimits(), [4, 30]);
  const a = w.generateSecret();
  const b = w.generateSecret();
  assert.ok(a instanceof Uint8Array && a.length === 32);
  assert.notEqual(hex(a), hex(b));
  const as = random(32);
  eq(w.adminHash(as), sha256(enc("wichtel/v1/admin-hash"), as));
});

test("vectors: key derivation", () => {
  V.participants.forEach((p, i) => {
    const k = keysV[i];
    assert.equal(b64e(k.pid), p.pid);
    assert.equal(b64e(k.ipk), p.ipk);
    assert.equal(b64e(k.idh), p.idh);
    assert.equal(b64e(authHash(k.authToken)), p.auth_hash);
  });
});

test("vectors: enc_name opens to name", () => {
  V.participants.forEach((p, i) => {
    const k = keysV[i];
    const name = w.gkOpen(gkV, "name", gidV, b64d(p.enc_name), k.pid, k.ipk, k.idh);
    assert.equal(new TextDecoder().decode(name), p.name);
    assert.equal(hex(b64d(p.enc_name).subarray(0, 12)), hex(b64d(p.enc_name_nonce)));
  });
});

test("vectors: fingerprint (roster order independent)", () => {
  assert.deepEqual(w.fingerprint(gidV, rosterV), V.fingerprint);
  assert.deepEqual(w.fingerprint(gidV, [...rosterV].reverse()), V.fingerprint);
});

const rolesV = keysV.map((k) => w.buildRolesVector(k, gidV, roundV, rosterV));
const rV = new Uint8Array(rolesLen(nV));
rolesV.forEach((v) => xorInto(rV, v));
const evalV = keysV.map((k) => w.evaluateRoles(k, gidV, roundV, rosterV, rV));

test("vectors: roles vectors, R", () => {
  V.participants.forEach((p, i) => {
    assert.equal(rolesV[i].length, rolesLen(nV));
    assert.equal(b64e(sha256(rolesV[i])), p.roles_vector_sha256);
  });
  assert.equal(b64e(sha256(rV)), V.r_sha256);
});

test("vectors: evaluation, positions, rho, G_r", () => {
  V.participants.forEach((p, i) => {
    const ev = evalV[i];
    assert.equal(ev.valid, true);
    assert.equal(ev.ownRoleMissing, false);
    assert.deepEqual(ev.attemptValid, V.attempt_valid);
    const s = decodeState(ev.state);
    assert.equal(b64e(s.gR), V.g_r);
    assert.equal(b64e(s.rho), V.rho);
    assert.equal(s.e, p.e);
    assert.deepEqual(s.p, p.p);
  });
});

const uploadsV = keysV.map((k, i) =>
  w.buildRevealUpload(k, gidV, roundV, rosterV, evalV[i].state, V.participants[i].note),
);
const sdV = new Uint8Array(L_SD);
uploadsV.forEach((u) => xorInto(sdV, u.subarray(0, L_SD)));

test("vectors: reveal uploads, SD, t*", () => {
  V.participants.forEach((p, i) => {
    assert.equal(uploadsV[i].length, L_REVEAL);
    assert.equal(b64e(sha256(uploadsV[i])), p.reveal_upload_sha256);
  });
  assert.equal(b64e(sdV), V.selfdraw_aggregate);
  evalV.forEach((ev) => assert.equal(w.selectAttempt(ev.state, sdV), V.t_star));
});

const releasedV = rosterV.map((e, i) => ({
  pid: e.pid,
  ciphertext: uploadsV[i].slice(L_SD + (V.t_star - 1) * L_CT, L_SD + V.t_star * L_CT),
}));

test("vectors: open_result", () => {
  const noteOf = new Map(V.participants.map((p) => [p.pid, p.note]));
  V.participants.forEach((p, i) => {
    const res = w.openResult(keysV[i], gidV, roundV, rosterV, evalV[i].state, V.t_star, releasedV);
    assert.equal(b64e(res.recipientPid), p.recipient_pid);
    assert.equal(res.note, noteOf.get(p.recipient_pid));
  });
});

// ---------------------------------------------------------------------------------------------
// 2. Signatures, GK, errors
// ---------------------------------------------------------------------------------------------

test("signatures verify with node:crypto", () => {
  const k = keysV[0];
  const encName = random(60);
  const encWish = random(124);
  const sig = k.signJoin(encName, encWish);
  assert.equal(sig.length, 64);
  const msg = joinMsg(gidV, k.ipk, k.idh, authHash(k.authToken), encName, encWish);
  assert.ok(ed25519Verify(k.ipk, msg, sig));
  assert.ok(!ed25519Verify(k.ipk, joinMsg(gidV, k.ipk, k.idh, authHash(k.authToken), encWish, encName), sig));
  for (const kind of [1, 2]) {
    const body = random(100);
    const s = k.signUpload(kind, 7, body);
    assert.ok(ed25519Verify(k.ipk, uploadMsg(kind, gidV, 7, k.pid, body), s));
    assert.ok(!ed25519Verify(k.ipk, uploadMsg(3 - kind, gidV, 7, k.pid, body), s));
  }
});

test("gk seal/open for all contexts", () => {
  const k = keysV[1];
  const gk = w.generateSecret();
  const meta = enc(JSON.stringify({ title: "Büro-Wichteln 🎄", budget: 20 }));
  const sm = w.gkSeal(gk, "meta", gidV, meta);
  eq(w.gkOpen(gk, "meta", gidV, sm), meta);
  assert.equal((sm.length - 28) % 32, 0);
  for (const ctx of ["name", "wish"]) {
    const data = enc(ctx === "name" ? "Zoë" : "x".repeat(1000));
    const s = w.gkSeal(gk, ctx, gidV, data, k.pid, k.ipk, k.idh);
    eq(w.gkOpen(gk, ctx, gidV, s, k.pid, k.ipk, k.idh), data);
    expectCode("DECRYPTION_FAILED", () =>
      w.gkOpen(gk, ctx, gidV, s, keysV[2].pid, k.ipk, k.idh),
    );
  }
  const tampered = sm.slice();
  tampered[20] ^= 1;
  expectCode("DECRYPTION_FAILED", () => w.gkOpen(gk, "meta", gidV, tampered));
  expectCode("DECRYPTION_FAILED", () => w.gkOpen(w.generateSecret(), "meta", gidV, sm));
  expectCode("INVALID_LENGTH", () => w.gkOpen(gk, "meta", gidV, sm.subarray(0, 20)));
  expectCode("INVALID_LENGTH", () => w.gkSeal(gk, "name", gidV, new Uint8Array(65), k.pid, k.ipk, k.idh));
  expectCode("INVALID_ARGUMENT", () => w.gkSeal(gk, "name", gidV, enc("a")));
  expectCode("INVALID_ARGUMENT", () => w.gkSeal(gk, "group", gidV, enc("a")));
  expectCode("INVALID_LENGTH", () => w.gkSeal(gk.subarray(1), "meta", gidV, enc("a")));
  expectCode("INVALID_LENGTH", () => w.gkSeal(gk, "name", gidV, enc("a"), k.pid.subarray(1), k.ipk, k.idh));
});

test("error codes", () => {
  const k = keysV[0];
  expectCode("INVALID_LENGTH", () => w.deriveKeys(random(31), gidV));
  expectCode("INVALID_LENGTH", () => w.deriveKeys(random(32), random(15)));
  expectCode("INVALID_LENGTH", () => w.adminHash(random(33)));
  expectCode("INVALID_ARGUMENT", () => k.signUpload(3, 1, random(4)));
  expectCode("INVALID_ARGUMENT", () => k.signUpload(1, -1, random(4)));
  expectCode("INVALID_ARGUMENT", () => k.signUpload(1, 1.5, random(4)));
  // Roster shape.
  expectCode("INVALID_ARGUMENT", () => w.fingerprint(gidV, "nope"));
  expectCode("INVALID_ARGUMENT", () => w.fingerprint(gidV, [null]));
  expectCode("INVALID_ARGUMENT", () => w.fingerprint(gidV, [{ ...rosterV[0], encName: "x" }]));
  expectCode("INVALID_ARGUMENT", () => w.fingerprint(gidV, [{ ...rosterV[0], ipk: [1, 2] }]));
  expectCode("INVALID_LENGTH", () => w.fingerprint(gidV, [{ ...rosterV[0], idh: random(31) }]));
  expectCode("INVALID_ENCODING", () => w.fingerprint(gidV, [rosterV[0], rosterV[0]]));
  expectCode("INVALID_PARTICIPANT_COUNT", () =>
    w.fingerprint(gidV, Array.from({ length: 31 }, () => rosterV[0])),
  );
  // Round functions.
  expectCode("INVALID_PARTICIPANT_COUNT", () => w.buildRolesVector(k, gidV, 1, rosterV.slice(0, 3)));
  const otherKeys = w.deriveKeys(random(32), gidV);
  const withOther = [otherKeys, ...keysV.slice(1)].map((kk, i) =>
    i === 0 ? { pid: kk.pid, ipk: kk.ipk, idh: kk.idh, encName: random(60) } : rosterV[i],
  );
  expectCode("NOT_IN_ROSTER", () => w.buildRolesVector(k, gidV, 1, withOther));
  expectCode("NOT_IN_ROSTER", () => w.evaluateRoles(k, gidV, roundV, withOther, rV));
  expectCode("NOT_IN_ROSTER", () => w.buildRolesVector(w.deriveKeys(b64d(V.participants[0].seed), random(16)), gidV, 1, rosterV));
  const forgedPid = rosterV.map((e, i) => (i === 1 ? { ...e, pid: random(16) } : e));
  expectCode("INVALID_KEY", () => w.buildRolesVector(k, gidV, 1, forgedPid));
  expectCode("INVALID_LENGTH", () => w.evaluateRoles(k, gidV, roundV, rosterV, rV.subarray(1)));
  // Evaluation state.
  const st = evalV[0].state;
  expectCode("INVALID_STATE", () => w.selectAttempt(st.subarray(0, st.length - 1), sdV));
  expectCode("INVALID_STATE", () => w.selectAttempt(new Uint8Array(0), sdV));
  expectCode("INVALID_STATE", () => w.selectAttempt(Uint8Array.of(9, ...st.subarray(1)), sdV));
  expectCode("INVALID_LENGTH", () => w.selectAttempt(st, sdV.subarray(1)));
  expectCode("STATE_MISMATCH", () => w.buildRevealUpload(k, gidV, roundV + 1, rosterV, st, ""));
  expectCode("STATE_MISMATCH", () =>
    w.openResult(k, gidV, roundV, rosterV.map((e, i) => (i === 3 ? { ...e, encName: random(60) } : e)), st, V.t_star, releasedV),
  );
  expectCode("INVALID_LENGTH", () => w.buildRevealUpload(k, gidV, roundV, rosterV, st, "x".repeat(462)));
  w.buildRevealUpload(k, gidV, roundV, rosterV, st, "ü".repeat(230)); // 460 B: ok
  // Result.
  const invalidT = V.attempt_valid.indexOf(false) + 1;
  expectCode("ATTEMPT_MISMATCH", () => w.openResult(k, gidV, roundV, rosterV, st, invalidT, releasedV));
  expectCode("ATTEMPT_MISMATCH", () => w.openResult(k, gidV, roundV, rosterV, st, 0, releasedV));
  expectCode("ATTEMPT_MISMATCH", () => w.openResult(k, gidV, roundV, rosterV, st, 300, releasedV));
  expectCode("INVALID_ARGUMENT", () => w.openResult(k, gidV, roundV, rosterV, st, 1.5, releasedV));
  const ownIdx = 0;
  const myGiverIdx = rosterV.findIndex((e) => b64e(e.pid) === V.participants[ownIdx].recipient_pid);
  expectCode("REVEAL_COUNT", () =>
    w.openResult(k, gidV, roundV, rosterV, st, V.t_star, releasedV.filter((_, i) => i !== myGiverIdx)),
  );
  expectCode("REVEAL_COUNT", () =>
    w.openResult(k, gidV, roundV, rosterV, st, V.t_star, [...releasedV, releasedV[myGiverIdx]]),
  );
  expectCode("REVEAL_COUNT", () => w.openResult(k, gidV, roundV, rosterV, st, V.t_star, Array(31).fill(releasedV[0])));
  expectCode("INVALID_ARGUMENT", () => w.openResult(k, gidV, roundV, rosterV, st, V.t_star, [{ pid: rosterV[0].pid }]));
  // Swapped ciphertext: the reveal of t* from another uploader is not valid for that pid.
  const swapped = releasedV.map((r, i) => (i === myGiverIdx ? { ...r, pid: releasedV[(i + 1) % nV].pid } : r));
  expectCode("REVEAL_COUNT", () => w.openResult(k, gidV, roundV, rosterV, st, V.t_star, swapped));
});

test("evaluation: collision and own role missing", () => {
  // Random R ⇒ E invalid.
  const garbage = random(rolesLen(nV));
  const ev = w.evaluateRoles(keysV[0], gidV, roundV, rosterV, garbage);
  assert.equal(ev.valid, false);
  assert.equal(ev.ownRoleMissing, false);
  assert.deepEqual(ev.attemptValid, Array(T).fill(false));
  assert.equal(ev.state.length, 0);
  // Missing contribution ⇒ masks do not cancel ⇒ collision.
  const partial = new Uint8Array(rolesLen(nV));
  rolesV.slice(1).forEach((v) => xorInto(partial, v));
  assert.equal(w.evaluateRoles(keysV[0], gidV, roundV, rosterV, partial).valid, false);
  // Move participant 0's E-slot to a free slot: E stays valid, but its RP is not at its slot.
  const s0 = decodeState(evalV[0].state);
  const moved = rV.slice();
  const slotOf = (rp) => {
    for (let i = 0; i < 16 * nV * nV; i++) {
      if (hex(moved.subarray(40 * i, 40 * i + 32)) === hex(rp)) return i;
    }
    return -1;
  };
  const own = slotOf(s0.recipients[s0.e]);
  assert.ok(own >= 0);
  let free = 0;
  while (free === own || moved.subarray(40 * free, 40 * free + 40).some((b) => b !== 0)) free++;
  moved.copyWithin(40 * free, 40 * own, 40 * own + 40);
  moved.fill(0, 40 * own, 40 * own + 40);
  const ev0 = w.evaluateRoles(keysV[0], gidV, roundV, rosterV, moved);
  assert.equal(ev0.valid, true);
  assert.equal(ev0.ownRoleMissing, true);
  assert.equal(ev0.state.length, 0);
  // Others are not affected in their own checks.
  assert.equal(w.evaluateRoles(keysV[1], gidV, roundV, rosterV, moved).ownRoleMissing, false);
});

test("handle lifecycle", () => {
  const k = w.deriveKeys(random(32), gidV);
  const pid = k.pid;
  assert.equal(pid.length, 16);
  k.free();
  assert.throws(() => k.pid);
  // Module still usable after all the error paths above (no trap/poisoned instance).
  assert.equal(b64e(keysV[0].pid), V.participants[0].pid);
});

// ---------------------------------------------------------------------------------------------
// 3. Complete protocol, n = 4, in-memory mailbox
// ---------------------------------------------------------------------------------------------

/** The "server": stores joins and uploads, aggregates, releases. No secrets. */
class Mailbox {
  constructor(gid) {
    this.gid = gid;
    this.members = new Map(); // b64(pid) → join record
    this.round = 1;
    this.uploads = new Map(); // `${round}/${kind}/${pid}` → body
  }
  join(rec) {
    const ah = sha256(enc("wichtel/v1/auth-hash"), rec.authToken);
    assert.ok(
      ed25519Verify(rec.ipk, joinMsg(this.gid, rec.ipk, rec.idh, ah, rec.encName, rec.encWish), rec.sig),
      "join signature",
    );
    eq(rec.pid, sha256(enc("wichtel/v1/pid"), this.gid, rec.ipk).subarray(0, 16));
    this.members.set(b64e(rec.pid), rec);
  }
  roster() {
    return [...this.members.values()].map(({ pid, ipk, idh, encName }) => ({ pid, ipk, idh, encName }));
  }
  upload(kind, round, pid, body, sig) {
    assert.equal(round, this.round, "upload for current round");
    const m = this.members.get(b64e(pid));
    assert.ok(ed25519Verify(m.ipk, uploadMsg(kind, this.gid, round, pid, body), sig), "upload sig");
    const key = `${round}/${kind}/${b64e(pid)}`;
    assert.ok(!this.uploads.has(key), "second upload");
    this.uploads.set(key, body);
  }
  aggregate(kind, len) {
    const acc = new Uint8Array(len);
    let count = 0;
    for (const [key, body] of this.uploads) {
      if (key.startsWith(`${this.round}/${kind}/`)) {
        xorInto(acc, body.subarray(0, len));
        count++;
      }
    }
    assert.equal(count, this.members.size);
    return acc;
  }
  revealsFor(tStar) {
    return [...this.members.values()].map(({ pid }) => ({
      pid,
      ciphertext: this.uploads
        .get(`${this.round}/2/${b64e(pid)}`)
        .slice(L_SD + (tStar - 1) * L_CT, L_SD + tStar * L_CT),
    }));
  }
}

/** Server-side t* (Spec §9.1), computed from the public evaluation (independent of WASM). */
function serverTStar(attemptValid, sd) {
  for (let t = 1; t <= T; t++) {
    if (attemptValid[t - 1] && sd.subarray(16 * (t - 1), 16 * t).every((b) => b === 0)) return t;
  }
  return null;
}

function runProtocol(n, { measure = false } = {}) {
  const gid = random(16);
  const gk = w.generateSecret();
  const box = new Mailbox(gid);
  const names = ["Anna", "Ben", "Clara", "David", "Emil", "Frieda"].slice(0, n);
  const people = names.map((name) => {
    const seed = w.generateSecret();
    const keys = w.deriveKeys(seed, gid);
    const encName = w.gkSeal(gk, "name", gid, enc(name), keys.pid, keys.ipk, keys.idh);
    const encWish = w.gkSeal(gk, "wish", gid, enc(`Wunsch von ${name}`), keys.pid, keys.ipk, keys.idh);
    box.join({
      pid: keys.pid, ipk: keys.ipk, idh: keys.idh, authToken: keys.authToken,
      encName, encWish, sig: keys.signJoin(encName, encWish),
    });
    return { name, keys, note: `Grüße von ${name}` };
  });
  const roster = box.roster();
  // Everybody sees the same fingerprint, and names decrypt.
  const fps = people.map(() => w.fingerprint(gid, roster).join(" "));
  assert.equal(new Set(fps).size, 1);
  for (const e of roster) {
    const name = new TextDecoder().decode(w.gkOpen(gk, "name", gid, e.encName, e.pid, e.ipk, e.idh));
    assert.ok(names.includes(name));
  }

  for (let attempt = 0; attempt < 10; attempt++) {
    const round = box.round;
    // Step 1.
    for (const p of people) {
      const v = w.buildRolesVector(p.keys, gid, round, roster);
      box.upload(1, round, p.keys.pid, v, p.keys.signUpload(1, round, v));
    }
    const r = box.aggregate(1, rolesLen(n));
    const evals = people.map((p) => w.evaluateRoles(p.keys, gid, round, roster, r));
    assert.ok(evals.every((e) => !e.ownRoleMissing));
    if (!evals[0].valid) {
      assert.ok(evals.every((e) => !e.valid));
      console.log(`  round ${round}: collision`);
      box.round++;
      continue;
    }
    // Step 2.
    people.forEach((p, i) => {
      const body = w.buildRevealUpload(p.keys, gid, round, roster, evals[i].state, p.note);
      box.upload(2, round, p.keys.pid, body, p.keys.signUpload(2, round, body));
    });
    const sd = box.aggregate(2, L_SD);
    const tStar = serverTStar(evals[0].attemptValid, sd);
    evals.forEach((e) => assert.equal(w.selectAttempt(e.state, sd), tStar));
    if (tStar === null) {
      console.log(`  round ${round}: no valid attempt`);
      box.round++;
      continue;
    }
    const reveals = box.revealsFor(tStar);
    const results = people.map((p, i) =>
      measure
        ? time(`openResult n=${n}`, () => w.openResult(p.keys, gid, round, roster, evals[i].state, tStar, reveals))
        : w.openResult(p.keys, gid, round, roster, evals[i].state, tStar, reveals),
    );
    // Derangement: every giver one distinct recipient, nobody draws themselves; notes arrive.
    const byPid = new Map(people.map((p) => [b64e(p.keys.pid), p]));
    const recipients = new Set();
    results.forEach((res, i) => {
      const me = b64e(people[i].keys.pid);
      const them = b64e(res.recipientPid);
      assert.notEqual(them, me, "self-draw");
      assert.ok(byPid.has(them));
      assert.equal(res.note, byPid.get(them).note);
      recipients.add(them);
    });
    assert.equal(recipients.size, n);
    console.log(`  round ${round}: t* = ${tStar}, ${people.map((p, i) => `${p.name}→${byPid.get(b64e(results[i].recipientPid)).name}`).join(", ")}`);
    people.forEach((p) => p.keys.free());
    return { round, tStar };
  }
  throw new Error("no result after 10 rounds");
}

test("complete protocol n=4 (in-memory mailbox)", () => {
  for (let i = 0; i < 3; i++) runProtocol(4, { measure: i === 0 });
});

// ---------------------------------------------------------------------------------------------
// 4. Timings
// ---------------------------------------------------------------------------------------------

function bigRoster(n) {
  const gid = random(16);
  const keys = Array.from({ length: n }, () => w.deriveKeys(w.generateSecret(), gid));
  const roster = keys.map((k) => ({ pid: k.pid, ipk: k.ipk, idh: k.idh, encName: random(60) }));
  return { gid, keys, roster };
}

test("timings", () => {
  for (const n of [20, 30]) {
    const { gid, keys, roster } = bigRoster(n);
    const v = time(`buildRolesVector n=${n}`, () => w.buildRolesVector(keys[0], gid, 1, roster), BENCH_RUNS);
    assert.equal(v.length, rolesLen(n));
    if (n === 30) {
      // Full step 1 for n = 30 (all participants), then evaluation / step 2 / result.
      const r = v.slice();
      for (const k of keys.slice(1)) xorInto(r, w.buildRolesVector(k, gid, 1, roster));
      const ev = time(`evaluateRoles n=${n}`, () => w.evaluateRoles(keys[0], gid, 1, roster, r), BENCH_RUNS);
      if (!ev.valid) {
        console.log("  (n=30: collision round – step 2 timings skipped)");
        return;
      }
      const evals = keys.map((k, i) => (i === 0 ? ev : w.evaluateRoles(k, gid, 1, roster, r)));
      const valid = ev.attemptValid.filter(Boolean).length;
      const uploads = keys.map((k, i) =>
        i === 0
          ? time(`buildRevealUpload n=${n} (${valid} HPKE seals)`, () => w.buildRevealUpload(k, gid, 1, roster, evals[i].state, "Hallo"), BENCH_RUNS)
          : w.buildRevealUpload(k, gid, 1, roster, evals[i].state, "Hallo"),
      );
      const sd = new Uint8Array(L_SD);
      uploads.forEach((u) => xorInto(sd, u.subarray(0, L_SD)));
      const tStar = w.selectAttempt(ev.state, sd);
      if (tStar === null) {
        console.log("  (n=30: no valid attempt – openResult timing skipped)");
        return;
      }
      const reveals = keys.map((k, i) => ({
        pid: k.pid,
        ciphertext: uploads[i].slice(L_SD + (tStar - 1) * L_CT, L_SD + tStar * L_CT),
      }));
      time(`openResult n=${n}`, () => w.openResult(keys[0], gid, 1, roster, ev.state, tStar, reveals), BENCH_RUNS);
    }
  }
  // One HPKE seal ≈ (reveal upload with 16 valid attempts − with 0 valid attempts) / 16 is not
  // observable through the API; approximate from n = 4: reveal upload / valid attempts.
  const { gid, keys, roster } = bigRoster(4);
  const r = new Uint8Array(rolesLen(4));
  keys.forEach((k) => xorInto(r, w.buildRolesVector(k, gid, 1, roster)));
  const ev = w.evaluateRoles(keys[0], gid, 1, roster, r);
  if (ev.valid) {
    const valid = ev.attemptValid.filter(Boolean).length;
    time(`buildRevealUpload n=4 (${valid} HPKE seals)`, () => w.buildRevealUpload(keys[0], gid, 1, roster, ev.state, "Hallo"), BENCH_RUNS * 3);
  }
});

console.log(`\n${passed} tests passed\n\nTimings (median, ms):`);
for (const [label, ms] of timings) {
  const sorted = [...ms].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  console.log(`  ${label.padEnd(44)} ${median.toFixed(1).padStart(9)}  (${ms.length} run${ms.length > 1 ? "s" : ""})`);
}
