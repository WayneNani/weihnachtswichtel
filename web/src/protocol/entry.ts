/**
 * Own roster entry: join request and changing name / wish list (Spec §5, §16.1, §16.3).
 *
 * After the start the name is fixed: the update re-uses the stored `enc_name` byte for byte (a new
 * seal would differ because of its random nonce) and only `enc_wish` and `join_sig` change. If the
 * wish list really changed in `done`, the anonymous endpoint of the own Schenker (from the
 * contacts) goes along as `notify_endpoint`; failing to find it never prevents saving.
 */
import type { Api } from "../api/client";
import type { GroupView, JoinRequest, UpdateParticipantRequest } from "../api/types";
import { b64uDecode, b64uEncode, utf8 } from "../lib/bytes";
import { authHash } from "../lib/hashes";
import type { ParticipantKeysHandle, WichtelWasm } from "../wasm-api";

export const NAME_LOCKED_TEXT = "Den Namen kannst du nach dem Start nicht mehr ändern";

/** Name can only be changed while the group is open (Spec §16.1). */
export function nameLocked(view: Pick<GroupView, "state">): boolean {
  return view.state !== "open";
}

/** `encName` given ⇒ re-use it unchanged (after the start); otherwise `name` is sealed anew. */
export function buildJoinRequest(
  wasm: WichtelWasm,
  gk: Uint8Array,
  gid: Uint8Array,
  keys: ParticipantKeysHandle,
  name: string,
  wish: string,
  encNameFixed?: Uint8Array,
): JoinRequest {
  const encName = encNameFixed ?? wasm.gkSeal(gk, "name", gid, utf8(name), keys.pid, keys.ipk, keys.idh);
  const encWish = wasm.gkSeal(gk, "wish", gid, utf8(wish), keys.pid, keys.ipk, keys.idh);
  return {
    ipk: b64uEncode(keys.ipk),
    idh: b64uEncode(keys.idh),
    auth_hash: b64uEncode(authHash(keys.authToken)),
    enc_name: b64uEncode(encName),
    enc_wish: b64uEncode(encWish),
    join_sig: b64uEncode(keys.signJoin(encName, encWish)),
  };
}

export interface EntryUpdateInput {
  api: Api;
  wasm: WichtelWasm;
  gk: Uint8Array;
  gid: Uint8Array;
  gidB64: string;
  keys: ParticipantKeysHandle;
  /** Current public view (decides whether the name is locked and whether to notify). */
  view: GroupView;
  /** Currently displayed plaintexts of the own entry (null = not readable). */
  current: { name: string | null; wish: string | null };
  next: { name: string; wish: string };
  /** Spec §16.3: endpoint of the own Schenker, or null. Only called for a real change in done. */
  findNotifyEndpoint?: () => Promise<string | null>;
}

export type EntryUpdateResult = { sent: false } | { sent: true; notified: boolean };

export async function submitEntryUpdate(input: EntryUpdateInput): Promise<EntryUpdateResult> {
  const { view, current, next, keys } = input;
  const pidB64 = b64uEncode(keys.pid);
  const locked = nameLocked(view);
  const nameChanged = next.name !== current.name;
  const wishChanged = next.wish !== current.wish;
  if (locked && nameChanged) throw new Error(`${NAME_LOCKED_TEXT}.`);
  if (!nameChanged && !wishChanged) return { sent: false };
  let encNameFixed: Uint8Array | undefined;
  if (locked) {
    const stored = view.participants.find((p) => p.pid === pidB64)?.enc_name;
    if (!stored) throw new Error("Du stehst nicht (mehr) in der Teilnehmerliste.");
    encNameFixed = b64uDecode(stored);
  }
  const req: UpdateParticipantRequest = buildJoinRequest(input.wasm, input.gk, input.gid, keys, next.name, next.wish, encNameFixed);
  let notified = false;
  if (view.state === "done" && wishChanged && input.findNotifyEndpoint) {
    try {
      const ep = await input.findNotifyEndpoint();
      if (ep) {
        req.notify_endpoint = ep;
        notified = true;
      }
    } catch {
      /* contacts unavailable: save without a hint */
    }
  }
  await input.api.updateParticipant(input.gidB64, pidB64, keys.authToken, req);
  return { sent: true, notified };
}
