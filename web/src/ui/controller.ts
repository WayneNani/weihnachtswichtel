/**
 * State holder for one group page: fetches the public view, decrypts it with GK, keeps a live
 * connection (SSE, polling fallback) and runs the protocol driver whenever something changes.
 */
import { ApiError, type Api } from "../api/client";
import { forgetGroupOnDevice } from "../forget";
import type { GroupMeta, GroupView } from "../api/types";
import { b64uEncode } from "../lib/bytes";
import type { Secrets } from "../lib/fragment";
import type { KvStore } from "../lib/idb";
import { loadGroup, saveGroup } from "../lib/storage";
import { decide, ProtocolDriver, type DriverStatus, type RolesJob, type RolesJobResult } from "../protocol/driver";
import { decodeMeta, decodeRoster, type DecodedRoster } from "../protocol/roster";
import { ensureWishEndpoint } from "../push";
import type { ParticipantKeysHandle, WichtelWasm } from "../wasm-api";

export type LiveMode = "connecting" | "sse" | "poll";

export interface Snapshot {
  loading: boolean;
  notFound: boolean;
  /** GK does not decrypt the group metadata ⇒ wrong/incomplete link. */
  badKey: boolean;
  view: GroupView | null;
  meta: GroupMeta | null;
  roster: DecodedRoster | null;
  fingerprint: string[] | null;
  /** Own pid if a seed is known on this device. */
  myPid: string | null;
  isMember: boolean;
  driver: DriverStatus | null;
  /** Human-readable step currently running (e.g. "Schritt 1 von 2 …"). */
  busy: string | null;
  live: LiveMode;
  /** Transient problem (network etc.). */
  problem: string | null;
  /** Several collision rounds in a row ⇒ hint to compare the fingerprint (Spec §11). */
  manyCollisions: boolean;
}

export interface ControllerDeps {
  api: Api;
  wasm: WichtelWasm;
  kv: KvStore;
  computeRoles(job: RolesJob): Promise<RolesJobResult>;
  /** Override for tests. */
  eventSource?: ((url: string) => EventSource) | null;
  /**
   * Spec §16.4: endpoint of the anonymous wish-hint subscription (created if missing), asked only
   * while push is switched on for the group. Default: push.ts `ensureWishEndpoint`.
   */
  wishEndpoint?: (api: Api, gidB64: string) => Promise<string>;
}

const POLL_FAST = 10_000;
const POLL_SLOW = 60_000;

export class GroupController {
  private listeners = new Set<(s: Snapshot) => void>();
  private snap: Snapshot = {
    loading: true,
    notFound: false,
    badKey: false,
    view: null,
    meta: null,
    roster: null,
    fingerprint: null,
    myPid: null,
    isMember: false,
    driver: null,
    busy: null,
    live: "connecting",
    problem: null,
    manyCollisions: false,
  };
  private keys: ParticipantKeysHandle | null = null;
  private driver: ProtocolDriver | null = null;
  private es: EventSource | null = null;
  private esErrors = 0;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private retryDelay = 3000;
  private fetching: Promise<void> | null = null;
  private refetchQueued = false;
  private driverRunning = false;
  private driverDirty = false;
  private stopped = false;
  private lastRosterKey = "";
  private forgotten = false;
  private onVisible = () => {
    if (document.visibilityState === "visible") void this.refresh();
  };

  constructor(
    private readonly deps: ControllerDeps,
    readonly gidB64: string,
    readonly gid: Uint8Array,
    private secrets: Secrets,
  ) {
    this.setSeed(secrets.s ?? null);
  }

  get snapshot(): Snapshot {
    return this.snap;
  }

  get api(): Api {
    return this.deps.api;
  }

  get wasm(): WichtelWasm {
    return this.deps.wasm;
  }

  get kv(): KvStore {
    return this.deps.kv;
  }

  get keysHandle(): ParticipantKeysHandle | null {
    return this.keys;
  }

  get currentSecrets(): Secrets {
    return this.secrets;
  }

  subscribe(fn: (s: Snapshot) => void): () => void {
    this.listeners.add(fn);
    fn(this.snap);
    return () => this.listeners.delete(fn);
  }

  private set(patch: Partial<Snapshot>): void {
    this.snap = { ...this.snap, ...patch };
    for (const fn of this.listeners) fn(this.snap);
  }

  /** Called on start and after joining with a fresh seed. */
  setSeed(seed: Uint8Array | null): void {
    this.keys?.free();
    this.keys = null;
    this.driver = null;
    this.secrets = { ...this.secrets, s: seed ?? undefined };
    if (!seed) {
      this.set({ myPid: null, isMember: false, driver: null });
      return;
    }
    this.keys = this.deps.wasm.deriveKeys(seed, this.gid);
    const keys = this.keys;
    this.driver = new ProtocolDriver(
      { wasm: this.deps.wasm, api: this.deps.api, kv: this.deps.kv, computeRoles: this.deps.computeRoles },
      {
        gidB64: this.gidB64,
        gid: this.gid,
        seed,
        keys,
        note: () => loadGroup(this.gidB64)?.note ?? "",
        contactEndpoint: async () => {
          if (loadGroup(this.gidB64)?.push !== true) return "";
          return (this.deps.wishEndpoint ?? ensureWishEndpoint)(this.deps.api, this.gidB64);
        },
      },
    );
    this.set({ myPid: b64uEncode(keys.pid) });
  }

  /** Spec §16.3: anonymous endpoint of the own Schenker for the current draw, or null. */
  async notifyEndpoint(): Promise<string | null> {
    const { view, roster } = this.snap;
    if (!this.driver || !view || !roster?.allValid) return null;
    return this.driver.findNotifyEndpoint(view, roster.entries);
  }

  start(): void {
    this.stopped = false;
    void this.refresh();
    this.connectLive();
    if (typeof document !== "undefined") document.addEventListener("visibilitychange", this.onVisible);
  }

  stop(): void {
    this.stopped = true;
    this.es?.close();
    this.es = null;
    if (this.pollTimer) clearTimeout(this.pollTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    if (typeof document !== "undefined") document.removeEventListener("visibilitychange", this.onVisible);
    this.keys?.free();
    this.keys = null;
  }

  // ------------------------------------------------------------ live updates

  private connectLive(): void {
    const factory =
      this.deps.eventSource !== undefined
        ? this.deps.eventSource
        : typeof EventSource !== "undefined"
          ? (url: string) => new EventSource(url)
          : null;
    if (!factory) {
      this.set({ live: "poll" });
      this.schedulePoll(POLL_FAST);
      return;
    }
    try {
      const es = factory(this.deps.api.eventsUrl(this.gidB64));
      this.es = es;
      es.addEventListener("open", () => {
        this.esErrors = 0;
        this.set({ live: "sse" });
      });
      es.addEventListener("update", () => {
        void this.refresh();
      });
      es.addEventListener("error", () => {
        // The stream broke (server closed it, e.g. the group was deleted, or the network dropped):
        // fetch the current state right away instead of waiting for the next poll.
        void this.refresh();
        this.esErrors++;
        if (this.esErrors >= 3 || es.readyState === 2) {
          es.close();
          this.es = null;
          this.set({ live: "poll" });
          this.schedulePoll(POLL_FAST);
        }
      });
      // Safety net even with SSE (missed events, sleeping tabs).
      this.schedulePoll(POLL_SLOW);
    } catch {
      this.set({ live: "poll" });
      this.schedulePoll(POLL_FAST);
    }
  }

  private schedulePoll(ms: number): void {
    if (this.pollTimer) clearTimeout(this.pollTimer);
    this.pollTimer = setTimeout(() => {
      if (this.stopped) return;
      const hidden = typeof document !== "undefined" && document.visibilityState === "hidden";
      void this.refresh();
      this.schedulePoll(this.es ? POLL_SLOW : hidden ? POLL_SLOW : POLL_FAST);
    }, ms);
  }

  // ------------------------------------------------------------ fetching

  /** Fetches the group view (coalesced) and runs the driver. */
  refresh(): Promise<void> {
    if (this.fetching) {
      this.refetchQueued = true;
      return this.fetching;
    }
    this.fetching = (async () => {
      do {
        this.refetchQueued = false;
        await this.fetchOnce();
      } while (this.refetchQueued && !this.stopped);
    })().finally(() => {
      this.fetching = null;
    });
    return this.fetching;
  }

  private async fetchOnce(): Promise<void> {
    let view: GroupView;
    try {
      view = await this.deps.api.getGroup(this.gidB64);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        this.set({ loading: false, notFound: true, view: null });
        this.es?.close();
        // The group was deleted (by the Spielleiter or after the event): nothing here is of use
        // any more – remove seed, note, cached results and push state from this device.
        if (!this.forgotten) {
          this.forgotten = true;
          void forgetGroupOnDevice(this.gidB64, { kv: this.deps.kv });
        }
        return;
      }
      this.set({ loading: false, problem: e instanceof ApiError && e.code === "network" ? "Keine Verbindung zum Server – neuer Versuch läuft …" : "Der Server antwortet gerade nicht richtig." });
      this.scheduleRetry();
      return;
    }
    this.applyView(view);
    void this.runDriver();
  }

  private applyView(view: GroupView): void {
    const { wasm } = this.deps;
    const gk = this.secrets.k;
    const meta = decodeMeta(wasm, gk, view.enc_meta);
    if (!meta) {
      this.set({ loading: false, badKey: true, view, problem: null });
      return;
    }
    const rosterKey = view.participants.map((p) => p.pid + p.enc_name + p.enc_wish).join("|");
    let roster = this.snap.roster;
    let fingerprint = this.snap.fingerprint;
    if (rosterKey !== this.lastRosterKey || !roster) {
      roster = decodeRoster(wasm, gk, this.gid, view.participants);
      fingerprint = null;
      try {
        if (roster.entries.length > 0) fingerprint = wasm.fingerprint(this.gid, roster.entries);
      } catch {
        fingerprint = null;
      }
      this.lastRosterKey = rosterKey;
    }
    const myPid = this.snap.myPid;
    const isMember = !!myPid && view.participants.some((p) => p.pid === myPid);

    // Collision hint: count rounds since the current draw started (Spec §11).
    let manyCollisions = false;
    if (view.state === "drawing") {
      const rec = loadGroup(this.gidB64);
      const dr = rec?.drawRound;
      if (!dr || dr.drawNo !== view.draw_no) saveGroup(this.gidB64, { drawRound: { drawNo: view.draw_no, firstRound: view.round } });
      else manyCollisions = view.round - dr.firstRound >= 3;
    }
    if (meta.title && loadGroup(this.gidB64)?.title !== meta.title && loadGroup(this.gidB64)) saveGroup(this.gidB64, { title: meta.title });

    this.set({ loading: false, notFound: false, badKey: false, view, meta, roster, fingerprint, isMember, problem: null, manyCollisions });
    this.retryDelay = 3000;
  }

  private scheduleRetry(): void {
    if (this.retryTimer || this.stopped) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.refresh();
    }, this.retryDelay);
    this.retryDelay = Math.min(this.retryDelay * 2, 60_000);
  }

  // ------------------------------------------------------------ protocol

  private async runDriver(): Promise<void> {
    if (this.driverRunning) {
      this.driverDirty = true;
      return;
    }
    this.driverRunning = true;
    try {
      do {
        this.driverDirty = false;
        const { view, roster, myPid } = this.snap;
        if (!this.driver || !view || !roster || !myPid || this.snap.badKey) {
          this.set({ driver: null, busy: null });
          break;
        }
        const plan = decide(view, myPid, { rosterValid: roster.allValid });
        const busy =
          plan.kind === "roles"
            ? "Schritt 1 von 2: Deine anonyme Rolle wird berechnet …"
            : plan.kind === "reveal"
              ? "Schritt 2 von 2: Auslosung wird geprüft und verschlüsselt …"
              : plan.kind === "result"
                ? "Dein Ergebnis wird entschlüsselt …"
                : null;
        if (busy) this.set({ busy });
        const status = await this.driver.step(view, roster.entries, roster.allValid);
        this.set({ driver: status, busy: null });
        if (status.kind === "result") {
          // The draw is complete, so the note has reached the Schenker (in the step-2 upload of the
          // final round): drop the plaintext from this device. Not right after the step-2 upload –
          // a failed attempt (no t*) moves on to round r+1, which uploads the note again.
          if (loadGroup(this.gidB64)?.note !== undefined) saveGroup(this.gidB64, { note: undefined });
        }
        if (status.kind === "uploaded") {
          await this.refresh();
        } else if (status.kind === "retry") {
          this.set({ problem: status.message === "Zustand hat sich geändert" ? null : status.message });
          this.scheduleRetry();
        }
      } while (this.driverDirty && !this.stopped);
    } finally {
      this.driverRunning = false;
    }
  }
}
