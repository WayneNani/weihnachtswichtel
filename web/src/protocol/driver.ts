/**
 * Client-side protocol driver (Spec §7–§11).
 *
 * On every visit (and on every live update) the UI hands the current `GroupView` to
 * `ProtocolDriver.step()`. The driver decides – purely from public state plus what this device
 * remembers – which step is due and executes at most one upload per call:
 *
 *   open                       → nothing to do
 *   drawing{r, roles}          → build role vector V_i (Web Worker) and upload       (Schritt 1)
 *   drawing{r, reveal}         → fetch R, evaluate, build SD_i ‖ C_i and upload      (Schritt 2)
 *   done{r, t*}                → fetch reveals, verify t*, open own result           (Ergebnis)
 *
 * Errors never cause a message to the server that would reveal own positions (Spec §11).
 */
import { ApiError, type Api } from "../api/client";
import { N_MAX, NOTE_MAX, type GroupView } from "../api/types";
import { b64uDecode, b64uDecodeLen, b64uEncode, utf8Len } from "../lib/bytes";
import type { KvStore } from "../lib/idb";
import type { ParticipantKeysHandle, RosterEntryInput, WichtelWasm } from "../wasm-api";

export interface RolesJob {
  seed: Uint8Array;
  gid: Uint8Array;
  round: number;
  roster: RosterEntryInput[];
}

export interface RolesJobResult {
  body: Uint8Array;
  sig: Uint8Array;
}

export type DisturbanceReason =
  | "own_role_missing" // §7.4
  | "evaluation_mismatch" // server proceeded although R is invalid for us
  | "t_star_mismatch" // §9.1
  | "open_failed"; // §9.3 (≠ 1 valid reveal)

export type DriverStatus =
  | { kind: "inactive"; reason: "open" | "not_member" | "invalid_roster" | "too_many" }
  | { kind: "uploaded"; step: 1 | 2; round: number }
  | { kind: "waiting"; step: 1 | 2 | 3; round: number }
  | { kind: "result"; round: number; recipientPid: string; note: string }
  | { kind: "disturbance"; round: number; reason: DisturbanceReason }
  | { kind: "retry"; message: string };

export interface LocalFacts {
  /** Round for which a result is cached. */
  resultRound?: number;
  /** Round in which this client detected a disturbance. */
  disturbedRound?: number;
  rosterValid: boolean;
}

export type Plan =
  | { kind: "nothing"; status: DriverStatus }
  | { kind: "roles"; round: number }
  | { kind: "reveal"; round: number }
  | { kind: "result"; round: number; tStar: number };

/** Pure decision: which step is due for participant `pidB64`? */
export function decide(view: GroupView, pidB64: string, local: LocalFacts): Plan {
  if (!view.participants.some((p) => p.pid === pidB64)) return { kind: "nothing", status: { kind: "inactive", reason: "not_member" } };
  if (view.state === "open") return { kind: "nothing", status: { kind: "inactive", reason: "open" } };
  if (view.participants.length > N_MAX) return { kind: "nothing", status: { kind: "inactive", reason: "too_many" } };
  if (!local.rosterValid) return { kind: "nothing", status: { kind: "inactive", reason: "invalid_roster" } };
  const round = view.round;
  if (local.disturbedRound === round) return { kind: "nothing", status: { kind: "disturbance", round, reason: "open_failed" } };
  if (view.state === "drawing") {
    const submitted = view.progress?.round === round && view.progress.phase === view.phase ? view.progress.submitted : [];
    const step = view.phase === "roles" ? 1 : 2;
    if (submitted.includes(pidB64)) return { kind: "nothing", status: { kind: "waiting", step, round } };
    return { kind: view.phase === "roles" ? "roles" : "reveal", round };
  }
  if (local.resultRound === round) return { kind: "nothing", status: { kind: "waiting", step: 3, round } };
  return { kind: "result", round, tStar: view.t_star };
}

export interface DriverDeps {
  wasm: WichtelWasm;
  api: Api;
  kv: KvStore;
  computeRoles(job: RolesJob): Promise<RolesJobResult>;
}

export interface Participation {
  gidB64: string;
  gid: Uint8Array;
  seed: Uint8Array;
  keys: ParticipantKeysHandle;
  /** Private note for the Schenker (read at the moment of the step-2 upload). */
  note(): string;
}

interface CachedResult {
  round: number;
  recipientPid: string;
  note: string;
}

interface CachedDisturbance {
  round: number;
  reason: DisturbanceReason;
}

export class ProtocolDriver {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly deps: DriverDeps,
    private readonly me: Participation,
  ) {}

  get pidB64(): string {
    return b64uEncode(this.me.keys.pid);
  }

  private key(kind: string, round: number): string {
    return `${kind}:${this.me.gidB64}:${this.pidB64}:${round}`;
  }

  async cachedResult(round: number): Promise<CachedResult | undefined> {
    return this.deps.kv.get<CachedResult>(this.key("result", round));
  }

  /**
   * Runs the due step for `view` (at most one upload). Calls are serialised; callers should
   * coalesce views themselves (see ui/controller.ts) and refetch after `uploaded`/`retry`.
   */
  step(view: GroupView, roster: RosterEntryInput[], rosterValid: boolean): Promise<DriverStatus> {
    const p = this.queue.then(() => this.run(view, roster, rosterValid));
    this.queue = p.catch(() => undefined);
    return p;
  }

  private async run(view: GroupView, roster: RosterEntryInput[], rosterValid: boolean): Promise<DriverStatus> {
    const round = "round" in view ? view.round : 0;
    const cached = round ? await this.deps.kv.get<CachedResult>(this.key("result", round)) : undefined;
    const disturbed = round ? await this.deps.kv.get<CachedDisturbance>(this.key("disturb", round)) : undefined;
    const plan = decide(view, this.pidB64, {
      rosterValid,
      resultRound: cached?.round,
      disturbedRound: disturbed?.round,
    });
    if (plan.kind === "nothing") {
      if (plan.status.kind === "waiting" && plan.status.step === 3 && cached)
        return { kind: "result", round: cached.round, recipientPid: cached.recipientPid, note: cached.note };
      if (plan.status.kind === "disturbance" && disturbed) return { kind: "disturbance", round, reason: disturbed.reason };
      return plan.status;
    }
    try {
      switch (plan.kind) {
        case "roles":
          return await this.uploadRoles(plan.round, roster);
        case "reveal":
          return await this.uploadReveal(plan.round, roster);
        case "result":
          return await this.fetchResult(plan.round, plan.tStar, roster);
      }
    } catch (e) {
      if (e instanceof ApiError) {
        // 409: phase moved on or duplicate upload – the caller refetches and we re-decide.
        if (e.status === 409) return { kind: "retry", message: "Zustand hat sich geändert" };
        return { kind: "retry", message: e.code === "network" ? "Keine Verbindung zum Server" : `Serverfehler (${e.code})` };
      }
      return { kind: "retry", message: e instanceof Error ? e.message : String(e) };
    }
  }

  private async disturbance(round: number, reason: DisturbanceReason): Promise<DriverStatus> {
    await this.deps.kv.set(this.key("disturb", round), { round, reason } satisfies CachedDisturbance);
    return { kind: "disturbance", round, reason };
  }

  private async uploadRoles(round: number, roster: RosterEntryInput[]): Promise<DriverStatus> {
    const { body, sig } = await this.deps.computeRoles({ seed: this.me.seed, gid: this.me.gid, round, roster });
    await this.deps.api.uploadRoles(this.me.gidB64, round, this.me.keys.authToken, body, sig);
    return { kind: "uploaded", step: 1, round };
  }

  /** Evaluation state for `round` (cached, else computed from the published R). */
  private async evaluation(round: number, roster: RosterEntryInput[]): Promise<Uint8Array | DriverStatus> {
    const k = this.key("eval", round);
    const stored = await this.deps.kv.get<string>(k);
    if (typeof stored === "string") {
      try {
        return b64uDecode(stored);
      } catch {
        /* recompute */
      }
    }
    const R = await this.deps.api.getRoles(this.me.gidB64, round);
    if (!R) return { kind: "waiting", step: 1, round };
    const ev = this.deps.wasm.evaluateRoles(this.me.keys, this.me.gid, round, roster, R);
    if (!ev.valid) return this.disturbance(round, "evaluation_mismatch");
    if (ev.ownRoleMissing) return this.disturbance(round, "own_role_missing");
    await this.deps.kv.set(k, b64uEncode(ev.state));
    return ev.state;
  }

  private async uploadReveal(round: number, roster: RosterEntryInput[]): Promise<DriverStatus> {
    const st = await this.evaluation(round, roster);
    if (!(st instanceof Uint8Array)) return st;
    let note = this.me.note();
    if (utf8Len(note) > NOTE_MAX) note = "";
    const body = this.deps.wasm.buildRevealUpload(this.me.keys, this.me.gid, round, roster, st, note);
    const sig = this.me.keys.signUpload(2, round, body);
    await this.deps.api.uploadReveal(this.me.gidB64, round, this.me.keys.authToken, body, sig);
    return { kind: "uploaded", step: 2, round };
  }

  private async fetchResult(round: number, tStar: number, roster: RosterEntryInput[]): Promise<DriverStatus> {
    const st = await this.evaluation(round, roster);
    if (!(st instanceof Uint8Array)) return st;
    const rel = await this.deps.api.getReveal(this.me.gidB64, round);
    if (!rel) return { kind: "waiting", step: 2, round };
    const sd = b64uDecodeLen(rel.selfdraw_aggregate, 256);
    if (rel.round !== round || rel.t_star !== tStar || !sd) return this.disturbance(round, "t_star_mismatch");
    const own = this.deps.wasm.selectAttempt(st, sd);
    if (own !== tStar) return this.disturbance(round, "t_star_mismatch");
    const reveals: { pid: Uint8Array; ciphertext: Uint8Array }[] = [];
    for (const r of rel.reveals) {
      const pid = b64uDecodeLen(r.pid, 16);
      const ciphertext = b64uDecodeLen(r.ciphertext, 560);
      if (pid && ciphertext) reveals.push({ pid, ciphertext });
    }
    let res;
    try {
      res = this.deps.wasm.openResult(this.me.keys, this.me.gid, round, roster, st, tStar, reveals);
    } catch {
      return this.disturbance(round, "open_failed");
    }
    const cached: CachedResult = { round, recipientPid: b64uEncode(res.recipientPid), note: res.note };
    await this.deps.kv.set(this.key("result", round), cached);
    return { kind: "result", ...cached };
  }
}

/** Runs the role-vector job on the current thread (fallback when no Worker is available). */
export function computeRolesInline(wasm: WichtelWasm): (job: RolesJob) => Promise<RolesJobResult> {
  return async (job) => {
    const keys = wasm.deriveKeys(job.seed, job.gid);
    try {
      const body = wasm.buildRolesVector(keys, job.gid, job.round, job.roster);
      const sig = keys.signUpload(1, job.round, body);
      return { body, sig };
    } finally {
      keys.free();
    }
  };
}
