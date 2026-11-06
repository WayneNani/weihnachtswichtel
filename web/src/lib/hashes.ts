/** Hashes the client computes itself (Spec §3, §4). */
import { utf8 } from "./bytes";
import { sha256 } from "./sha256";

/** `auth_hash = H("wichtel/v1/auth-hash" ‖ tok)` – sent on join, server stores only this. */
export function authHash(tok: Uint8Array): Uint8Array {
  return sha256(utf8("wichtel/v1/auth-hash"), tok);
}

/** `pid = H("wichtel/v1/pid" ‖ gid ‖ IPK)[0..16]`. */
export function pidFromIpk(gid: Uint8Array, ipk: Uint8Array): Uint8Array {
  return sha256(utf8("wichtel/v1/pid"), gid, ipk).slice(0, 16);
}

/**
 * The group id is assigned by the server in the response to `POST /api/groups`, but `enc_meta`
 * must be sent in that very request. The meta AAD (`"wichtel/v1/meta" ‖ gid`, Spec §6) therefore
 * uses 16 zero bytes as gid. Binding to the group is still given because GK is unique per group.
 * (Open point for spec/server: alternatively let the client choose the gid.)
 */
export const META_AAD_GID = new Uint8Array(16);
