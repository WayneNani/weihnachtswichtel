/**
 * In-memory mock of the HTTP API in docs/api.md, including the group state machine
 * (Spec §10): open → drawing{roles} → drawing{reveal} → done, collision rounds, failed-attempt
 * rounds, restarts, leaving after start and the draw schedule.
 *
 * Transport-agnostic: `handle()` takes a plain request object. ./node-server.ts wraps it in
 * node:http (dev:mock), tests call it through `mockFetch()`.
 */
import type {
  GroupView,
  ParticipantView,
  Phase,
  PushSubscriptionRequest,
  RevealRelease,
  UpdateEvent,
} from "../api/types";
import { b64uDecode, b64uDecodeLen, b64uEncode, bytesEqual, compareBytes, fromUtf8, utf8 } from "../lib/bytes";
import {
  adminHash as computeAdminHash,
  authHash,
  joinMessage,
  mockAttemptValid,
  mockSign,
  pidFromIpk,
  T,
  uploadMessage,
} from "./shared";

export interface MockRequest {
  method: string;
  /** Path incl. optional query, e.g. `/api/groups/abc`. */
  path: string;
  /** Lower-case header names. */
  headers: Record<string, string | undefined>;
  body: Uint8Array;
}

export interface MockResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

interface Participant {
  pid: Uint8Array;
  ipk: Uint8Array;
  idh: Uint8Array;
  authHash: Uint8Array;
  encName: string;
  encWish: string;
  joinedAt: number;
}

interface Group {
  gid: Uint8Array;
  gidB64: string;
  adminHash: Uint8Array;
  encMeta: string;
  deleteAfter: number;
  drawAt: number | null;
  scheduleMissed: boolean;
  createdAt: number;
  state: "open" | "drawing" | "done";
  round: number;
  phase: Phase;
  tStar: number;
  drawNo: number;
  participants: Map<string, Participant>;
  submitted: Set<string>;
  rolesAgg: Uint8Array | null;
  rolesR: Map<number, Uint8Array>;
  sdAgg: Uint8Array | null;
  revealUploads: Map<string, Uint8Array>;
  releases: Map<number, RevealRelease>;
  push: Map<string, PushSubscriptionRequest>;
}

export interface MockServerOptions {
  /** Unix seconds. */
  now?: () => number;
  /** Probability that a completed roles phase is treated as a collision (round r+1). */
  collisionRate?: number;
  random?: () => number;
  /** Called for every push subscription on a state change (payload-less push). */
  onPush?: (sub: PushSubscriptionRequest) => void;
  /** Uncompressed P-256 public key for `GET /api/push/vapid-key`. */
  vapidPublicKey?: Uint8Array;
  /** Log function for state changes (no secrets are ever logged; there are none server-side). */
  log?: (msg: string) => void;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const N_MIN = 4;
const N_MAX = 30;

function jsonResponse(status: number, body: unknown): MockResponse {
  return {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: utf8(JSON.stringify(body)),
  };
}

function empty(status = 204): MockResponse {
  return { status, headers: { "cache-control": "no-store" }, body: new Uint8Array(0) };
}

function xorInto(acc: Uint8Array, v: Uint8Array): void {
  for (let i = 0; i < acc.length; i++) acc[i]! ^= v[i]!;
}

export class MockServer {
  private groups = new Map<string, Group>();
  private listeners = new Map<string, Set<(ev: UpdateEvent) => void>>();
  private now: () => number;
  private collisionRate: number;
  private random: () => number;
  private onPush: (sub: PushSubscriptionRequest) => void;
  private log: (msg: string) => void;
  vapidPublicKey: Uint8Array;

  constructor(opts: MockServerOptions = {}) {
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.collisionRate = opts.collisionRate ?? 0;
    this.random = opts.random ?? Math.random;
    this.onPush = opts.onPush ?? (() => {});
    this.log = opts.log ?? (() => {});
    this.vapidPublicKey = opts.vapidPublicKey ?? new Uint8Array([4, ...new Uint8Array(64).fill(7)]);
  }

  // ------------------------------------------------------------ events

  subscribe(gidB64: string, cb: (ev: UpdateEvent) => void): () => void {
    let set = this.listeners.get(gidB64);
    if (!set) {
      set = new Set();
      this.listeners.set(gidB64, set);
    }
    set.add(cb);
    return () => set.delete(cb);
  }

  hasGroup(gidB64: string): boolean {
    return this.groups.has(gidB64);
  }

  private changed(g: Group): void {
    const ev = this.updateEvent(g);
    this.log(`[${g.gidB64.slice(0, 6)}] ${ev.state}${"round" in ev ? ` r=${ev.round}` : ""}${"phase" in ev ? ` ${ev.phase}` : ""} draw_no=${g.drawNo} ${ev.submitted_count}/${ev.participant_count}`);
    for (const cb of this.listeners.get(g.gidB64) ?? []) cb(ev);
    for (const sub of g.push.values()) {
      try {
        this.onPush(sub);
      } catch {
        /* ignore */
      }
    }
  }

  private updateEvent(g: Group): UpdateEvent {
    const base = { draw_no: g.drawNo, submitted_count: g.submitted.size, participant_count: g.participants.size };
    if (g.state === "open") return { state: "open", ...base };
    if (g.state === "drawing") return { state: "drawing", round: g.round, phase: g.phase, ...base };
    return { state: "done", round: g.round, t_star: g.tStar, ...base };
  }

  /** Background job (Spec §10): start or mark missed when `draw_at` is reached. */
  tick(): void {
    const now = this.now();
    for (const g of this.groups.values()) {
      if (g.state === "open" && g.drawAt !== null && g.drawAt <= now) {
        g.drawAt = null;
        if (g.participants.size >= N_MIN && g.participants.size <= N_MAX) {
          this.newRound(g, true);
        } else {
          g.scheduleMissed = true;
        }
        this.changed(g);
      }
      if (now > g.deleteAfter) {
        this.groups.delete(g.gidB64);
      }
    }
  }

  // ------------------------------------------------------------ http

  handle(req: MockRequest): MockResponse {
    try {
      return this.route(req);
    } catch (e) {
      if (e instanceof HttpError) return jsonResponse(e.status, { error: e.code, message: e.message });
      return jsonResponse(500, { error: "internal", message: String(e) });
    }
  }

  private route(req: MockRequest): MockResponse {
    const path = req.path.split("?")[0]!;
    const m = req.method.toUpperCase();
    let r: RegExpExecArray | null;

    if (path === "/api/health" && m === "GET") return { status: 200, headers: {}, body: utf8("ok") };
    if (path === "/api/push/vapid-key" && m === "GET") return jsonResponse(200, { public_key: b64uEncode(this.vapidPublicKey) });
    if (path === "/api/groups" && m === "POST") return this.createGroup(req);

    if ((r = /^\/api\/groups\/([^/]+)$/.exec(path))) {
      const g = this.group(r[1]!);
      if (m === "GET") return jsonResponse(200, this.view(g));
      if (m === "DELETE") {
        this.requireAdmin(g, req);
        this.groups.delete(g.gidB64);
        for (const cb of this.listeners.get(g.gidB64) ?? []) cb({ state: "open", draw_no: -1, submitted_count: 0, participant_count: 0 });
        return empty();
      }
    }
    if ((r = /^\/api\/groups\/([^/]+)\/schedule$/.exec(path)) && m === "PUT") {
      const g = this.group(r[1]!);
      this.requireAdmin(g, req);
      if (g.state !== "open") throw new HttpError(409, "conflict", "not open");
      const body = this.json<{ draw_at: number | null }>(req);
      if (body.draw_at !== null && (typeof body.draw_at !== "number" || body.draw_at <= this.now()))
        throw new HttpError(400, "bad_request", "draw_at must be in the future");
      g.drawAt = body.draw_at;
      if (body.draw_at !== null) g.scheduleMissed = false;
      this.changed(g);
      return empty();
    }
    if ((r = /^\/api\/groups\/([^/]+)\/start$/.exec(path)) && m === "POST") {
      const g = this.group(r[1]!);
      this.requireAdmin(g, req);
      if (g.state !== "open") throw new HttpError(409, "conflict", "not open");
      if (g.participants.size < N_MIN) throw new HttpError(409, "too_few_participants", "need at least 4");
      if (g.participants.size > N_MAX) throw new HttpError(409, "group_full", "too many");
      g.drawAt = null;
      g.scheduleMissed = false;
      this.newRound(g, true);
      this.changed(g);
      return empty();
    }
    if ((r = /^\/api\/groups\/([^/]+)\/restart$/.exec(path)) && m === "POST") {
      const g = this.group(r[1]!);
      this.requireAdmin(g, req);
      if (g.state === "open") throw new HttpError(409, "conflict", "not started");
      this.newRound(g, true);
      this.changed(g);
      return empty();
    }
    if ((r = /^\/api\/groups\/([^/]+)\/participants$/.exec(path)) && m === "POST") {
      return this.join(this.group(r[1]!), req);
    }
    if ((r = /^\/api\/groups\/([^/]+)\/participants\/([^/]+)$/.exec(path))) {
      const g = this.group(r[1]!);
      const p = g.participants.get(r[2]!);
      if (!p) throw new HttpError(404, "not_found", "no such participant");
      if (m === "PUT") return this.updateParticipant(g, p, req);
      if (m === "DELETE") return this.removeParticipant(g, p, req);
    }
    if ((r = /^\/api\/groups\/([^/]+)\/participants\/([^/]+)\/push$/.exec(path))) {
      const g = this.group(r[1]!);
      const p = g.participants.get(r[2]!);
      if (!p) throw new HttpError(404, "not_found", "no such participant");
      this.requireParticipant(p, req);
      if (m === "PUT") {
        const body = this.json<PushSubscriptionRequest>(req);
        if (typeof body.endpoint !== "string" || !/^https:\/\//.test(body.endpoint) || body.endpoint.length > 1024)
          throw new HttpError(400, "bad_request", "endpoint must be https");
        if (!b64uDecodeLen(body.p256dh, 65) || !b64uDecodeLen(body.auth, 16)) throw new HttpError(400, "bad_request", "bad keys");
        g.push.set(b64uEncode(p.pid), body);
        return empty();
      }
      if (m === "DELETE") {
        g.push.delete(b64uEncode(p.pid));
        return empty();
      }
    }
    if ((r = /^\/api\/groups\/([^/]+)\/rounds\/(\d+)\/(roles|reveal)$/.exec(path))) {
      const g = this.group(r[1]!);
      const round = Number(r[2]);
      const kind = r[3] as "roles" | "reveal";
      if (m === "PUT") return kind === "roles" ? this.uploadRoles(g, round, req) : this.uploadReveal(g, round, req);
      if (m === "GET") {
        if (kind === "roles") {
          const R = g.rolesR.get(round);
          if (!R) throw new HttpError(409, "conflict", "incomplete");
          return { status: 200, headers: { "content-type": "application/octet-stream", "cache-control": "no-store" }, body: R };
        }
        const rel = g.releases.get(round);
        if (!rel) throw new HttpError(409, "conflict", "incomplete");
        return jsonResponse(200, rel);
      }
    }
    throw new HttpError(404, "not_found", "no route");
  }

  // ------------------------------------------------------------ helpers

  private json<T>(req: MockRequest): T {
    if (req.body.length > 16 * 1024) throw new HttpError(413, "payload_too_large", "json too large");
    try {
      return JSON.parse(fromUtf8(req.body)) as T;
    } catch {
      throw new HttpError(400, "bad_request", "invalid json");
    }
  }

  private group(gidB64: string): Group {
    const g = this.groups.get(gidB64);
    if (!g) throw new HttpError(404, "not_found", "no such group");
    return g;
  }

  private bearer(req: MockRequest): Uint8Array {
    const h = req.headers["authorization"] ?? "";
    const m = /^Bearer ([A-Za-z0-9_-]+)$/.exec(h);
    const b = m ? b64uDecodeLen(m[1], 32) : null;
    if (!b) throw new HttpError(401, "unauthorized", "missing bearer");
    return b;
  }

  private isAdmin(g: Group, req: MockRequest): boolean {
    try {
      return bytesEqual(computeAdminHash(this.bearer(req)), g.adminHash);
    } catch {
      return false;
    }
  }

  private requireAdmin(g: Group, req: MockRequest): void {
    if (!this.isAdmin(g, req)) throw new HttpError(401, "unauthorized", "admin only");
  }

  private requireParticipant(p: Participant, req: MockRequest): void {
    if (!bytesEqual(authHash(this.bearer(req)), p.authHash)) throw new HttpError(401, "unauthorized", "wrong token");
  }

  private participantByToken(g: Group, req: MockRequest): Participant {
    const h = authHash(this.bearer(req));
    for (const p of g.participants.values()) if (bytesEqual(p.authHash, h)) return p;
    throw new HttpError(401, "unauthorized", "unknown token");
  }

  private sortedParticipants(g: Group): Participant[] {
    return [...g.participants.values()].sort((a, b) => compareBytes(a.pid, b.pid));
  }

  private view(g: Group): GroupView {
    const participants: ParticipantView[] = this.sortedParticipants(g).map((p) => ({
      pid: b64uEncode(p.pid),
      ipk: b64uEncode(p.ipk),
      idh: b64uEncode(p.idh),
      enc_name: p.encName,
      enc_wish: p.encWish,
      joined_at: p.joinedAt,
    }));
    const common = {
      gid: g.gidB64,
      draw_no: g.drawNo,
      enc_meta: g.encMeta,
      draw_at: g.drawAt,
      schedule_missed: g.scheduleMissed,
      delete_after: g.deleteAfter,
      created_at: g.createdAt,
      participants,
    };
    if (g.state === "open") return { state: "open", ...common, progress: null };
    if (g.state === "drawing")
      return {
        state: "drawing",
        round: g.round,
        phase: g.phase,
        ...common,
        progress: { round: g.round, phase: g.phase, submitted: [...g.submitted].sort() },
      };
    return { state: "done", round: g.round, t_star: g.tStar, ...common, progress: null };
  }

  private newRound(g: Group, newDraw: boolean): void {
    g.state = "drawing";
    g.round += 1;
    g.phase = "roles";
    if (newDraw) g.drawNo += 1;
    g.submitted = new Set();
    g.rolesAgg = null;
    g.sdAgg = null;
    g.revealUploads = new Map();
  }

  // ------------------------------------------------------------ endpoints

  private createGroup(req: MockRequest): MockResponse {
    const body = this.json<{ admin_hash: string; enc_meta: string; delete_after: number; draw_at: number | null }>(req);
    const adminHash = b64uDecodeLen(body.admin_hash, 32);
    if (!adminHash) throw new HttpError(400, "bad_request", "admin_hash");
    let meta: Uint8Array;
    try {
      meta = b64uDecode(body.enc_meta);
    } catch {
      throw new HttpError(400, "bad_request", "enc_meta");
    }
    if (meta.length > 2048) throw new HttpError(413, "payload_too_large", "enc_meta too large");
    const now = this.now();
    if (typeof body.delete_after !== "number" || body.delete_after <= now) throw new HttpError(400, "bad_request", "delete_after");
    if (body.draw_at !== null && body.draw_at !== undefined && (typeof body.draw_at !== "number" || body.draw_at <= now))
      throw new HttpError(400, "bad_request", "draw_at");
    const gid = new Uint8Array(16);
    crypto.getRandomValues(gid);
    const gidB64 = b64uEncode(gid);
    this.groups.set(gidB64, {
      gid,
      gidB64,
      adminHash,
      encMeta: body.enc_meta,
      deleteAfter: Math.min(body.delete_after, now + 60 * 86400),
      drawAt: body.draw_at ?? null,
      scheduleMissed: false,
      createdAt: now,
      state: "open",
      round: 0,
      phase: "roles",
      tStar: 0,
      drawNo: 0,
      participants: new Map(),
      submitted: new Set(),
      rolesAgg: null,
      rolesR: new Map(),
      sdAgg: null,
      revealUploads: new Map(),
      releases: new Map(),
      push: new Map(),
    });
    this.log(`[${gidB64.slice(0, 6)}] created`);
    return jsonResponse(201, { gid: gidB64 });
  }

  private parseJoin(g: Group, req: MockRequest) {
    const body = this.json<{ ipk: string; idh: string; auth_hash: string; enc_name: string; enc_wish: string; join_sig: string }>(req);
    const ipk = b64uDecodeLen(body.ipk, 32);
    const idh = b64uDecodeLen(body.idh, 32);
    const ah = b64uDecodeLen(body.auth_hash, 32);
    const sig = b64uDecodeLen(body.join_sig, 64);
    if (!ipk || !idh || !ah || !sig) throw new HttpError(400, "bad_request", "bad keys");
    let encName: Uint8Array, encWish: Uint8Array;
    try {
      encName = b64uDecode(body.enc_name);
      encWish = b64uDecode(body.enc_wish);
    } catch {
      throw new HttpError(400, "bad_request", "bad ciphertext");
    }
    if (encName.length > 128 || encWish.length > 1100) throw new HttpError(413, "payload_too_large", "too large");
    if (!bytesEqual(sig, mockSign(ipk, joinMessage(g.gid, ipk, idh, ah, encName, encWish))))
      throw new HttpError(400, "bad_request", "bad join_sig");
    return { ipk, idh, ah, encName: body.enc_name, encWish: body.enc_wish };
  }

  private join(g: Group, req: MockRequest): MockResponse {
    const j = this.parseJoin(g, req);
    if (g.state !== "open") throw new HttpError(409, "conflict", "not open");
    if (g.participants.size >= N_MAX) throw new HttpError(409, "group_full", "group full");
    const pid = pidFromIpk(g.gid, j.ipk);
    const pidB64 = b64uEncode(pid);
    if (g.participants.has(pidB64)) throw new HttpError(409, "conflict", "already joined");
    g.participants.set(pidB64, {
      pid,
      ipk: j.ipk,
      idh: j.idh,
      authHash: j.ah,
      encName: j.encName,
      encWish: j.encWish,
      joinedAt: this.now(),
    });
    this.changed(g);
    return jsonResponse(201, { pid: pidB64 });
  }

  private updateParticipant(g: Group, p: Participant, req: MockRequest): MockResponse {
    this.requireParticipant(p, req);
    const j = this.parseJoin(g, req);
    if (g.state !== "open") throw new HttpError(409, "conflict", "not open");
    if (!bytesEqual(j.ipk, p.ipk) || !bytesEqual(j.idh, p.idh) || !bytesEqual(j.ah, p.authHash))
      throw new HttpError(400, "bad_request", "keys differ");
    p.encName = j.encName;
    p.encWish = j.encWish;
    this.changed(g);
    return empty();
  }

  private removeParticipant(g: Group, p: Participant, req: MockRequest): MockResponse {
    if (!this.isAdmin(g, req)) this.requireParticipant(p, req);
    const pidB64 = b64uEncode(p.pid);
    g.participants.delete(pidB64);
    g.push.delete(pidB64);
    if (g.state !== "open") {
      if (g.participants.size < N_MIN) {
        g.state = "open";
        g.submitted = new Set();
      } else {
        this.newRound(g, true);
      }
    }
    this.changed(g);
    return empty();
  }

  private uploadRoles(g: Group, round: number, req: MockRequest): MockResponse {
    const p = this.participantByToken(g, req);
    if (g.state !== "drawing" || g.phase !== "roles" || g.round !== round) throw new HttpError(409, "conflict", "wrong round/phase");
    const pidB64 = b64uEncode(p.pid);
    if (g.submitted.has(pidB64)) throw new HttpError(409, "conflict", "duplicate upload");
    const n = g.participants.size;
    if (req.body.length !== 2688 * n * n) throw new HttpError(400, "bad_request", "wrong length");
    this.checkSig(g, p, 1, round, req);
    if (!g.rolesAgg) g.rolesAgg = new Uint8Array(req.body.length);
    xorInto(g.rolesAgg, req.body);
    g.submitted.add(pidB64);
    if (g.submitted.size === n) {
      const R = g.rolesAgg;
      g.rolesR.set(round, R);
      g.rolesAgg = null;
      if (this.random() < this.collisionRate) {
        this.log(`[${g.gidB64.slice(0, 6)}] simulated collision in E`);
        this.newRound(g, false);
      } else {
        g.phase = "reveal";
        g.submitted = new Set();
      }
    }
    this.changed(g);
    return empty();
  }

  private uploadReveal(g: Group, round: number, req: MockRequest): MockResponse {
    const p = this.participantByToken(g, req);
    if (g.state !== "drawing" || g.phase !== "reveal" || g.round !== round) throw new HttpError(409, "conflict", "wrong round/phase");
    const pidB64 = b64uEncode(p.pid);
    if (g.submitted.has(pidB64)) throw new HttpError(409, "conflict", "duplicate upload");
    if (req.body.length !== 9216) throw new HttpError(400, "bad_request", "wrong length");
    this.checkSig(g, p, 2, round, req);
    if (!g.sdAgg) g.sdAgg = new Uint8Array(256);
    xorInto(g.sdAgg, req.body.subarray(0, 256));
    g.revealUploads.set(pidB64, req.body.slice(256));
    g.submitted.add(pidB64);
    if (g.submitted.size === g.participants.size) {
      const sd = g.sdAgg;
      let tStar = 0;
      for (let t = 1; t <= T; t++) {
        if (!mockAttemptValid(g.gid, round, t)) continue;
        if (sd.subarray((t - 1) * 16, t * 16).every((b) => b === 0)) {
          tStar = t;
          break;
        }
      }
      if (tStar === 0) {
        this.log(`[${g.gidB64.slice(0, 6)}] no valid attempt`);
        this.newRound(g, false);
      } else {
        const reveals = this.sortedParticipants(g).map((pp) => {
          const pb = b64uEncode(pp.pid);
          const all = g.revealUploads.get(pb)!;
          return { pid: pb, ciphertext: b64uEncode(all.subarray((tStar - 1) * 560, tStar * 560)) };
        });
        g.releases.set(round, { round, selfdraw_aggregate: b64uEncode(sd), t_star: tStar, reveals });
        g.revealUploads = new Map(); // drop all other attempts
        g.state = "done";
        g.tStar = tStar;
        g.submitted = new Set();
      }
    }
    this.changed(g);
    return empty();
  }

  private checkSig(g: Group, p: Participant, kind: 1 | 2, round: number, req: MockRequest): void {
    const sig = b64uDecodeLen(req.headers["x-wichtel-signature"], 64);
    if (!sig) throw new HttpError(400, "bad_request", "missing signature");
    if (!bytesEqual(sig, mockSign(p.ipk, uploadMessage(kind, g.gid, round, p.pid, req.body))))
      throw new HttpError(400, "bad_request", "bad signature");
  }
}

/** `fetch`-compatible adapter for tests (and for an optional in-page mock). */
export function mockFetch(server: MockServer): (input: string, init?: RequestInit) => Promise<Response> {
  return async (input, init = {}) => {
    const url = new URL(input, "http://mock.invalid");
    const headers: Record<string, string> = {};
    new Headers(init.headers).forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    let body: Uint8Array = new Uint8Array(0);
    if (typeof init.body === "string") body = utf8(init.body);
    else if (init.body instanceof Uint8Array) body = init.body;
    else if (init.body instanceof ArrayBuffer) body = new Uint8Array(init.body);
    const res = server.handle({ method: init.method ?? "GET", path: url.pathname + url.search, headers, body });
    return new Response(res.status === 204 ? null : (res.body as unknown as BodyInit), { status: res.status, headers: res.headers });
  };
}
