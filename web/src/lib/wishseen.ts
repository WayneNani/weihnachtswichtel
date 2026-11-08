/**
 * In-app hint "Wunschzettel aktualisiert" (Spec §16): per group and draw, this device remembers a
 * hash of the recipient's wish list as last seen in the revealed result card. Stays on the device
 * (localStorage record of the group, removed with it).
 */
import { b64uEncode, utf8 } from "./bytes";
import { sha256 } from "./sha256";
import { loadGroup, saveGroup } from "./storage";

export interface WishSeen {
  drawNo: number;
  hash: string;
}

export function wishHash(wish: string): string {
  return b64uEncode(sha256(utf8("wichtel/local/wish-seen"), utf8(wish)).subarray(0, 16));
}

/**
 * True if the wish list differs from the one last seen in this draw. Nothing seen yet in this draw
 * (first reveal, or a new draw) ⇒ false: the list is new to the viewer, not "updated".
 */
export function wishUpdated(seen: WishSeen | undefined | null, drawNo: number, wish: string): boolean {
  return !!seen && seen.drawNo === drawNo && seen.hash !== wishHash(wish);
}

export function loadWishSeen(gidB64: string): WishSeen | undefined {
  const s = loadGroup(gidB64)?.wishSeen;
  return s && typeof s.drawNo === "number" && typeof s.hash === "string" ? s : undefined;
}

export function markWishSeen(gidB64: string, drawNo: number, wish: string): void {
  const hash = wishHash(wish);
  const prev = loadWishSeen(gidB64);
  if (prev?.drawNo === drawNo && prev.hash === hash) return;
  if (!loadGroup(gidB64)) return; // nothing stored for this group (e.g. forgotten meanwhile)
  saveGroup(gidB64, { wishSeen: { drawNo, hash } });
}
