/**
 * Removes everything this device knows about a group: the localStorage record (incl. seed and
 * private note), the driver's IndexedDB cache (result:/eval:/disturb:/contact:), the push link
 * and the group's service-worker registrations (round and wish hint) – and, if a seed is known,
 * the push subscription on the server (errors ignored). If push was on and the participant is
 * still a member of a finished draw, the own contact is first replaced by one with an empty
 * endpoint (Spec §16.2), so the Wichtelkind's hints no longer point to this device.
 */
import type { Api } from "./api/client";
import { b64uDecodeLen, b64uEncode } from "./lib/bytes";
import { GID_LEN, SECRET_LEN } from "./lib/fragment";
import type { KvStore } from "./lib/idb";
import { forgetGroup, loadGroup } from "./lib/storage";
import { forgetDriverState, ProtocolDriver } from "./protocol/driver";
import { decodeRoster } from "./protocol/roster";
import { forgetPush, type PushServerCtx } from "./push";
import type { ParticipantKeysHandle, WichtelWasm } from "./wasm-api";

export interface ForgetDeps {
  kv: KvStore;
  /** With `api` and `wasm`, the push subscription is also removed on the server. */
  api?: Api;
  wasm?: WichtelWasm;
}

/** Replaces the own contact of the current draw by one without endpoint (errors ignored). */
async function clearContact(deps: Required<ForgetDeps>, gidB64: string, gid: Uint8Array, gk: Uint8Array, seed: Uint8Array, keys: ParticipantKeysHandle): Promise<void> {
  try {
    const view = await deps.api.getGroup(gidB64);
    if (view.state !== "done") return;
    const roster = decodeRoster(deps.wasm, gk, gid, view.participants);
    if (!roster.allValid) return;
    const driver = new ProtocolDriver(
      { wasm: deps.wasm, api: deps.api, kv: deps.kv, computeRoles: () => Promise.reject(new Error("not needed")) },
      { gidB64, gid, seed, keys, note: () => "" },
    );
    await driver.syncContact(view, roster.entries, "");
  } catch {
    /* group gone, offline, …: nothing to do */
  }
}

/**
 * The localStorage record is removed synchronously (before the first `await`), so callers may
 * re-read `listGroups()` right after calling this without awaiting it.
 */
export async function forgetGroupOnDevice(gidB64: string, deps: ForgetDeps): Promise<void> {
  const rec = loadGroup(gidB64);
  let keys: ParticipantKeysHandle | null = null;
  let server: PushServerCtx | undefined;
  let contact: (() => Promise<void>) | null = null;
  try {
    const seed = rec?.s ? b64uDecodeLen(rec.s, SECRET_LEN) : null;
    const gid = b64uDecodeLen(gidB64, GID_LEN);
    const gk = rec?.k ? b64uDecodeLen(rec.k, SECRET_LEN) : null;
    if (deps.api && deps.wasm && seed && gid) {
      const k = deps.wasm.deriveKeys(seed, gid);
      keys = k;
      server = { api: deps.api, pidB64: b64uEncode(k.pid), token: k.authToken };
      if (rec?.push === true && gk) {
        const full = { kv: deps.kv, api: deps.api, wasm: deps.wasm };
        contact = () => clearContact(full, gidB64, gid, gk, seed, k);
      }
    }
  } catch {
    server = undefined;
    contact = null;
  }
  forgetGroup(gidB64);
  try {
    // Needs the cached evaluation state, so it runs before the driver state is deleted.
    if (contact) await contact();
    await Promise.allSettled([forgetDriverState(deps.kv, gidB64), forgetPush(gidB64, server)]);
  } finally {
    keys?.free();
  }
}
