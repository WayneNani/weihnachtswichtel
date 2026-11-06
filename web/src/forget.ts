/**
 * Removes everything this device knows about a group: the localStorage record (incl. seed and
 * private note), the driver's IndexedDB cache (result:/eval:/disturb:), the push link and the
 * group's service-worker registration – and, if a seed is known, the push subscription on the
 * server (errors ignored).
 */
import type { Api } from "./api/client";
import { b64uDecodeLen, b64uEncode } from "./lib/bytes";
import { GID_LEN, SECRET_LEN } from "./lib/fragment";
import type { KvStore } from "./lib/idb";
import { forgetGroup, loadGroup } from "./lib/storage";
import { forgetDriverState } from "./protocol/driver";
import { forgetPush, type PushServerCtx } from "./push";
import type { ParticipantKeysHandle, WichtelWasm } from "./wasm-api";

export interface ForgetDeps {
  kv: KvStore;
  /** With `api` and `wasm`, the push subscription is also removed on the server. */
  api?: Api;
  wasm?: WichtelWasm;
}

/**
 * The localStorage record is removed synchronously (before the first `await`), so callers may
 * re-read `listGroups()` right after calling this without awaiting it.
 */
export async function forgetGroupOnDevice(gidB64: string, deps: ForgetDeps): Promise<void> {
  const rec = loadGroup(gidB64);
  let keys: ParticipantKeysHandle | null = null;
  let server: PushServerCtx | undefined;
  try {
    const seed = rec?.s ? b64uDecodeLen(rec.s, SECRET_LEN) : null;
    const gid = b64uDecodeLen(gidB64, GID_LEN);
    if (deps.api && deps.wasm && seed && gid) {
      keys = deps.wasm.deriveKeys(seed, gid);
      server = { api: deps.api, pidB64: b64uEncode(keys.pid), token: keys.authToken };
    }
  } catch {
    server = undefined;
  }
  forgetGroup(gidB64);
  try {
    await Promise.allSettled([forgetDriverState(deps.kv, gidB64), forgetPush(gidB64, server)]);
  } finally {
    keys?.free();
  }
}
