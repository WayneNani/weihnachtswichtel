/**
 * Mock implementation of `WichtelWasm` (../wasm-api.ts) for UI development without the Rust
 * core. Produces plausible data with the right sizes; consistent with ./server.ts via ./shared.ts.
 * NOT secure – never ship this (the real build excludes it via the `__MOCK__` define).
 */
import { b64uDecode, b64uEncode, bytesEqual, concat, fromUtf8, u32be, utf8 } from "../lib/bytes";
import { pidFromIpk } from "../lib/hashes";
import { sha256 } from "../lib/sha256";
import type {
  DrawResultJs,
  ParticipantKeysHandle,
  RolesEvaluation,
  RosterEntryInput,
  WichtelWasm,
} from "../wasm-api";
import { adminHash, joinMessage, mockAttemptValid, mockSign, mockSigma, T, uploadMessage, WORDS } from "./shared";

export interface MockOptions {
  /** Busy-wait in `buildRolesVector` to simulate the real cost (runs in the worker). */
  rolesDelayMs?: number;
  /** Returns true if a disturbance should be simulated in `openResult`. */
  disturb?: () => boolean;
}

const l = (s: string) => utf8(s);

function busyWait(ms: number): void {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    /* simulate CPU work */
  }
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function stream(key: Uint8Array, nonce: Uint8Array, len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let i = 0, ctr = 0; i < len; i += 32, ctr++) {
    out.set(sha256(key, nonce, u32be(ctr)).subarray(0, Math.min(32, len - i)), i);
  }
  return out;
}

function pad(data: Uint8Array): Uint8Array {
  const len = 2 + data.length;
  const total = Math.ceil(len / 32) * 32;
  const out = new Uint8Array(total);
  out[0] = data.length >> 8;
  out[1] = data.length & 255;
  out.set(data, 2);
  return out;
}

function unpad(p: Uint8Array): Uint8Array {
  const len = (p[0]! << 8) | p[1]!;
  if (len > p.length - 2) throw new Error("bad padding");
  for (let i = 2 + len; i < p.length; i++) if (p[i] !== 0) throw new Error("bad padding");
  return p.slice(2, 2 + len);
}

function aad(context: "meta" | "name" | "wish", gid: Uint8Array, pid?: Uint8Array, ipk?: Uint8Array, idh?: Uint8Array): Uint8Array {
  if (context === "meta") return concat(l("wichtel/v1/meta"), gid);
  if (!pid || !ipk || !idh) throw new Error("pid/ipk/idh required");
  return concat(l(`wichtel/v1/${context}`), gid, pid, ipk, idh);
}

interface EvalState {
  gid: string;
  round: number;
  pid: string;
  index: number;
  n: number;
  attemptValid: boolean[];
  pids: string[];
}

function encodeState(s: EvalState): Uint8Array {
  return utf8(JSON.stringify(s));
}
function decodeState(b: Uint8Array): EvalState {
  return JSON.parse(fromUtf8(b)) as EvalState;
}

/** Spec §16.2 sizes: plaintext L_KP, contact L_K = 32 (enc) + 768 + 16 (tag). */
const L_KP = 768;
const L_K = 816;
const ENDPOINT_MAX = 700;

/**
 * Mock contact key: bound to the recipient's IDH and the chosen attempt (stands in for HPKE to
 * IDH_j). The tag binds the sender pid (stands in for Mode Auth with GP of the Schenker role).
 */
function contactKey(idh: Uint8Array, gid: Uint8Array, round: number, tStar: number): Uint8Array {
  return sha256(l("mock/contact"), idh, gid, u32be(round), new Uint8Array([tStar]));
}

function contactTag(key: Uint8Array, enc: Uint8Array, senderPid: Uint8Array, ct: Uint8Array): Uint8Array {
  return sha256(l("mock/contact-tag"), key, enc, senderPid, ct).slice(0, 16);
}

function selfDraws(st: EvalState, gid: Uint8Array, t: number): boolean {
  return mockSigma(gid, st.round, t, st.n)[st.index] === st.index;
}

export function createMockWasm(opts: MockOptions = {}): WichtelWasm {
  const disturb = opts.disturb ?? (() => false);
  return {
    protocolVersion: () => "wichtel/v1 (mock)",
    participantLimits: () => [4, 30],
    generateSecret: () => randomBytes(32),
    adminHash: (as) => adminHash(as),

    deriveKeys(seed, gid): ParticipantKeysHandle {
      const ipk = sha256(l("mock/ipk"), seed, gid);
      const idh = sha256(l("mock/idh"), seed, gid);
      const authToken = sha256(l("mock/tok"), seed, gid);
      const pid = pidFromIpk(gid, ipk);
      const ah = sha256(l("wichtel/v1/auth-hash"), authToken);
      let freed = false;
      return {
        pid,
        ipk,
        idh,
        authToken,
        signJoin(encName, encWish) {
          if (freed) throw new Error("handle freed");
          return mockSign(ipk, joinMessage(gid, ipk, idh, ah, encName, encWish));
        },
        signUpload(kind, round, body) {
          if (freed) throw new Error("handle freed");
          return mockSign(ipk, uploadMessage(kind, gid, round, pid, body));
        },
        free() {
          freed = true;
        },
      };
    },

    gkSeal(gk, context, gid, data, pid, ipk, idh) {
      const key = sha256(l("mock/gk"), gk);
      const nonce = randomBytes(12);
      const pt = pad(data);
      const ks = stream(key, nonce, pt.length);
      const ct = pt.map((b, i) => b ^ ks[i]!);
      const tag = sha256(key, nonce, aad(context, gid, pid, ipk, idh), ct).slice(0, 16);
      return concat(nonce, ct, tag);
    },

    gkOpen(gk, context, gid, sealed, pid, ipk, idh) {
      if (sealed.length < 12 + 32 + 16) throw new Error("too short");
      const key = sha256(l("mock/gk"), gk);
      const nonce = sealed.subarray(0, 12);
      const ct = sealed.subarray(12, sealed.length - 16);
      const tag = sealed.subarray(sealed.length - 16);
      const expect = sha256(key, nonce, aad(context, gid, pid, ipk, idh), ct).slice(0, 16);
      if (!bytesEqual(tag, expect)) throw new Error("authentication failed");
      const ks = stream(key, nonce, ct.length);
      return unpad(ct.map((b, i) => b ^ ks[i]!));
    },

    fingerprint(gid, roster) {
      const parts: Uint8Array[] = [l("wichtel/v1/fp"), gid, u32be(roster.length)];
      for (const e of roster) parts.push(e.pid, e.ipk, e.idh, sha256(e.encName));
      const fp = sha256(...parts);
      return Array.from(fp.subarray(0, 8), (b) => WORDS[b]!);
    },

    buildRolesVector(keys, gid, round, roster) {
      const n = roster.length;
      const out = new Uint8Array(2688 * n * n);
      // Some deterministic, non-zero content.
      out.set(sha256(l("mock/roles"), keys.pid, gid, u32be(round)), 0);
      if (opts.rolesDelayMs) busyWait(opts.rolesDelayMs);
      return out;
    },

    evaluateRoles(keys, gid, round, roster, r): RolesEvaluation {
      const n = roster.length;
      if (r.length !== 2688 * n * n) throw new Error("R has wrong length");
      const index = roster.findIndex((e) => bytesEqual(e.pid, keys.pid));
      if (index < 0) throw new Error("not in roster");
      const attemptValid = Array.from({ length: T }, (_, i) => mockAttemptValid(gid, round, i + 1));
      const state: EvalState = {
        gid: b64uEncode(gid),
        round,
        pid: b64uEncode(keys.pid),
        index,
        n,
        attemptValid,
        pids: roster.map((e) => b64uEncode(e.pid)),
      };
      return { valid: true, attemptValid, ownRoleMissing: false, state: encodeState(state) };
    },

    buildRevealUpload(keys, gid, round, roster, evaluationState, note) {
      const st = decodeState(evaluationState);
      if (st.round !== round || st.n !== roster.length) throw new Error("state mismatch");
      const noteBytes = utf8(note);
      if (noteBytes.length > 461) throw new Error("note too long");
      const sd = new Uint8Array(256);
      const cts: Uint8Array[] = [];
      for (let t = 1; t <= T; t++) {
        const valid = st.attemptValid[t - 1]!;
        if (valid && selfDraws(st, gid, t)) {
          sd.set(sha256(l("mock/sd"), keys.authToken, u32be(round), new Uint8Array([t])).subarray(0, 16), (t - 1) * 16);
        }
        const ct = new Uint8Array(560);
        if (!valid) {
          ct.set(stream(sha256(l("mock/rnd"), keys.authToken), u32be(round * 100 + t), 560));
        } else {
          // The giver of me is σ_t⁻¹(index); mark the reveal for them.
          const sigma = mockSigma(gid, round, t, st.n);
          const giverIndex = sigma.indexOf(st.index);
          const giverPid = b64uDecode(st.pids[giverIndex]!);
          const pt = new Uint8Array(512);
          pt[0] = 1;
          pt.set(keys.pid, 1);
          pt.set(sha256(l("mock/mac"), giverPid, gid, u32be(round), new Uint8Array([t])), 17);
          pt[49] = noteBytes.length >> 8;
          pt[50] = noteBytes.length & 255;
          pt.set(noteBytes, 51);
          ct.set(pt, 32);
        }
        cts.push(ct);
      }
      return concat(sd, ...cts);
    },

    selectAttempt(evaluationState, selfdrawAggregate) {
      const st = decodeState(evaluationState);
      for (let t = 1; t <= T; t++) {
        if (!st.attemptValid[t - 1]) continue;
        const slot = selfdrawAggregate.subarray((t - 1) * 16, t * 16);
        if (slot.every((b) => b === 0)) return t;
      }
      return null;
    },

    openResult(keys, gid, round, roster, evaluationState, tStar, reveals): DrawResultJs {
      const st = decodeState(evaluationState);
      if (disturb()) throw new Error("Störung (simuliert)");
      const myMac = sha256(l("mock/mac"), keys.pid, gid, u32be(round), new Uint8Array([tStar]));
      const found: DrawResultJs[] = [];
      for (const r of reveals) {
        if (r.ciphertext.length !== 560) continue;
        const pt = r.ciphertext.subarray(32, 544);
        if (pt[0] !== 1) continue;
        if (!bytesEqual(pt.subarray(1, 17), r.pid)) continue;
        if (!bytesEqual(pt.subarray(17, 49), myMac)) continue;
        const len = (pt[49]! << 8) | pt[50]!;
        if (len > 461) continue;
        found.push({ recipientPid: r.pid.slice(), note: fromUtf8(pt.subarray(51, 51 + len)) });
      }
      if (found.length !== 1) throw new Error(`expected exactly one reveal, got ${found.length}`);
      // Sanity: matches the mock permutation.
      const expected = st.pids[mockSigma(gid, round, tStar, st.n)[st.index]!];
      if (expected !== b64uEncode(found[0]!.recipientPid)) throw new Error("mock permutation mismatch");
      void roster;
      return found[0]!;
    },

    buildContact(keys, gid, round, roster, evaluationState, tStar, recipientIdh, endpoint) {
      const st = decodeState(evaluationState);
      if (st.round !== round || st.n !== roster.length) throw new Error("state mismatch");
      if (!roster.some((e) => bytesEqual(e.idh, recipientIdh))) throw new Error("recipient not in roster");
      const ep = utf8(endpoint);
      if (ep.length > ENDPOINT_MAX) throw new Error("endpoint too long");
      if (endpoint && !endpoint.startsWith("https://")) throw new Error("endpoint must be https");
      const pt = new Uint8Array(L_KP);
      pt[0] = 1;
      pt[1] = ep.length >> 8;
      pt[2] = ep.length & 255;
      pt.set(ep, 3);
      const enc = randomBytes(32); // fresh on every call, like the HPKE ephemeral
      const key = contactKey(recipientIdh, gid, round, tStar);
      const ks = stream(key, enc, L_KP);
      const ct = pt.map((b, i) => b ^ ks[i]!);
      return concat(enc, ct, contactTag(key, enc, keys.pid, ct));
    },

    openContacts(keys, gid, round, roster, evaluationState, tStar, contacts) {
      const st = decodeState(evaluationState);
      if (st.round !== round || st.n !== roster.length) throw new Error("state mismatch");
      if (contacts.length % L_K !== 0) throw new Error("contacts have wrong length");
      // Only the own Schenker (giver of me in attempt t*) can have produced a valid tag.
      const sigma = mockSigma(gid, round, tStar, st.n);
      const giverPid = b64uDecode(st.pids[sigma.indexOf(st.index)]!);
      const key = contactKey(keys.idh, gid, round, tStar);
      for (let off = 0; off < contacts.length; off += L_K) {
        const enc = contacts.subarray(off, off + 32);
        const ct = contacts.subarray(off + 32, off + 32 + L_KP);
        const tag = contacts.subarray(off + 32 + L_KP, off + L_K);
        if (!bytesEqual(tag, contactTag(key, enc, giverPid, ct))) continue;
        const ks = stream(key, enc, L_KP);
        const pt = ct.map((b, i) => b ^ ks[i]!);
        const len = (pt[1]! << 8) | pt[2]!;
        if (pt[0] !== 1 || len > ENDPOINT_MAX || pt.subarray(3 + len).some((b) => b !== 0)) continue;
        return len === 0 ? null : fromUtf8(pt.subarray(3, 3 + len));
      }
      return null;
    },
  };
}

/** Simple ready-made instance for places that just need *a* mock. */
export const mockWasm: WichtelWasm = createMockWasm();

export type { RosterEntryInput };
