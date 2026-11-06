/**
 * Loads the crypto core. Real build: the wasm-bindgen output (`--target web`, built by
 * `scripts/build-wasm.sh`) is loaded at runtime from `/pkg/wichtel_wasm.js` (copied from
 * `web/src/wasm-pkg/` into `web/dist/pkg/` by build.mjs). Mock build: the TypeScript mock from
 * ./mock/wasm.ts – only reachable behind the `__MOCK__` define, so esbuild drops it (and the whole
 * mock module) from the real bundle.
 *
 * Error codes of the real module: ./wasm-errors.ts.
 */
import type { DrawResultJs, ParticipantKeysHandle, RolesEvaluation, RosterEntryInput, WichtelWasm } from "./wasm-api";

export const WASM_MODULE_URL = "/pkg/wichtel_wasm.js";

let cached: Promise<WichtelWasm> | null = null;

/** Loads (once per thread) and returns the WASM API. Works in the page and in the module worker. */
export function loadWasm(opts: { inWorker?: boolean } = {}): Promise<WichtelWasm> {
  if (!cached) {
    cached = __MOCK__ ? loadMock(opts.inWorker ?? false) : loadReal();
    cached.catch(() => {
      cached = null;
    });
  }
  return cached;
}

async function loadMock(inWorker: boolean): Promise<WichtelWasm> {
  if (!__MOCK__) throw new Error("mock disabled");
  const { createMockWasm } = await import("./mock/wasm");
  return createMockWasm({
    rolesDelayMs: inWorker ? 700 : 150,
    disturb: () => {
      try {
        return globalThis.localStorage?.getItem("wichtel:mock:disturb") === "1";
      } catch {
        return false;
      }
    },
  });
}

// ------------------------------------------------------------------------------------ real module

/** Shape of the wasm-bindgen glue (`web/src/wasm-pkg/wichtel_wasm.d.ts`), as far as used here. */
export interface WasmBindgenModule {
  default(init?: { module_or_path?: unknown }): Promise<unknown>;
  protocolVersion(): string;
  participantLimits(): [number, number];
  generateSecret(): Uint8Array;
  adminHash(adminSecret: Uint8Array): Uint8Array;
  deriveKeys(seed: Uint8Array, gid: Uint8Array): ParticipantKeysHandle;
  gkSeal(gk: Uint8Array, context: string, gid: Uint8Array, data: Uint8Array, pid?: Uint8Array, ipk?: Uint8Array, idh?: Uint8Array): Uint8Array;
  gkOpen(gk: Uint8Array, context: string, gid: Uint8Array, sealed: Uint8Array, pid?: Uint8Array, ipk?: Uint8Array, idh?: Uint8Array): Uint8Array;
  fingerprint(gid: Uint8Array, roster: RosterEntryInput[]): string[];
  buildRolesVector(keys: ParticipantKeysHandle, gid: Uint8Array, round: number, roster: RosterEntryInput[]): Uint8Array;
  evaluateRoles(keys: ParticipantKeysHandle, gid: Uint8Array, round: number, roster: RosterEntryInput[], r: Uint8Array): RolesEvaluation;
  buildRevealUpload(keys: ParticipantKeysHandle, gid: Uint8Array, round: number, roster: RosterEntryInput[], state: Uint8Array, note: string): Uint8Array;
  selectAttempt(state: Uint8Array, selfdrawAggregate: Uint8Array): number | null;
  openResult(
    keys: ParticipantKeysHandle,
    gid: Uint8Array,
    round: number,
    roster: RosterEntryInput[],
    state: Uint8Array,
    tStar: number,
    reveals: { pid: Uint8Array; ciphertext: Uint8Array }[],
  ): DrawResultJs;
}

async function loadReal(): Promise<WichtelWasm> {
  const url: string = WASM_MODULE_URL;
  const mod = (await import(/* webpackIgnore: true */ url)) as WasmBindgenModule;
  // Fetches /pkg/wichtel_wasm_bg.wasm relative to the glue (served as application/wasm).
  await mod.default();
  return bindWasm(mod);
}

/**
 * Maps the wasm-bindgen exports onto `WichtelWasm`. Explicit (no cast of the module object), so a
 * changed export surfaces here as a type error. `ParticipantKeysHandle` is the wasm-bindgen class
 * itself: callers must `free()` it (zeroizes the secrets in WASM memory); a finalizer exists but
 * runs late or never.
 */
export function bindWasm(m: WasmBindgenModule): WichtelWasm {
  if (m.protocolVersion() !== "wichtel/v1") throw new Error(`unsupported protocol ${m.protocolVersion()}`);
  return {
    protocolVersion: () => m.protocolVersion(),
    participantLimits: () => m.participantLimits(),
    generateSecret: () => m.generateSecret(),
    adminHash: (a) => m.adminHash(a),
    deriveKeys: (seed, gid) => m.deriveKeys(seed, gid),
    gkSeal: (gk, ctx, gid, data, pid, ipk, idh) => m.gkSeal(gk, ctx, gid, data, pid, ipk, idh),
    gkOpen: (gk, ctx, gid, sealed, pid, ipk, idh) => m.gkOpen(gk, ctx, gid, sealed, pid, ipk, idh),
    fingerprint: (gid, roster) => m.fingerprint(gid, roster),
    buildRolesVector: (keys, gid, round, roster) => m.buildRolesVector(keys, gid, round, roster),
    evaluateRoles: (keys, gid, round, roster, r) => m.evaluateRoles(keys, gid, round, roster, r),
    buildRevealUpload: (keys, gid, round, roster, st, note) => m.buildRevealUpload(keys, gid, round, roster, st, note),
    selectAttempt: (st, sd) => m.selectAttempt(st, sd),
    openResult: (keys, gid, round, roster, st, tStar, reveals) => m.openResult(keys, gid, round, roster, st, tStar, reveals),
  };
}
