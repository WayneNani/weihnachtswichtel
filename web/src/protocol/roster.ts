/** Decoding of the public roster: names/wishes (GK-encrypted) and protocol roster input. */
import type { GroupMeta, ParticipantView } from "../api/types";
import { b64uDecode, b64uDecodeLen, compareBytes, fromUtf8, utf8 } from "../lib/bytes";
import { META_AAD_GID } from "../lib/hashes";
import type { RosterEntryInput, WichtelWasm } from "../wasm-api";

export interface Member {
  pidB64: string;
  /** null ⇒ entry cannot be decrypted/decoded ("⚠ ungültiger Eintrag", Spec §6). */
  name: string | null;
  /** null ⇒ wish not readable; "" ⇒ no wish. */
  wish: string | null;
  valid: boolean;
  /** Another entry has the same name (after NFKC + case folding) – shown as "⚠ Name doppelt". */
  duplicate: boolean;
}

export interface DecodedRoster {
  members: Member[];
  /** Protocol input, sorted by pid (only meaningful if `allValid`). */
  entries: RosterEntryInput[];
  allValid: boolean;
}

/**
 * Invisible formatting characters that can disguise a name: bidi embeddings/overrides/isolates
 * (U+202A–U+202E, U+2066–U+2069), Arabic letter mark (U+061C), zero-width characters and
 * LRM/RLM (U+200B–U+200F), word joiner & invisible operators (U+2060–U+2064), BOM (U+FEFF).
 */
const INVISIBLE_RE = /[\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/** Name as displayed (and as sent when joining): invisible/bidi control characters removed, trimmed. */
export function cleanName(raw: string): string {
  return raw.replace(INVISIBLE_RE, "").trim();
}

/** Comparison key for duplicate names: cleaned, NFKC, case-folded, whitespace collapsed. */
export function nameKey(raw: string): string {
  return cleanName(raw).normalize("NFKC").toLowerCase().normalize("NFKC").replace(/\s+/g, " ");
}

/** Shown instead of a name that consists only of invisible characters. */
export const INVISIBLE_NAME = "⚠ unsichtbarer Name";

export function decodeRoster(wasm: WichtelWasm, gk: Uint8Array, gid: Uint8Array, participants: ParticipantView[]): DecodedRoster {
  const decoded: { m: Member; e: RosterEntryInput | null; pid: Uint8Array }[] = [];
  for (const p of participants) {
    const pid = b64uDecodeLen(p.pid, 16);
    const ipk = b64uDecodeLen(p.ipk, 32);
    const idh = b64uDecodeLen(p.idh, 32);
    let encName: Uint8Array | null = null;
    let encWish: Uint8Array | null = null;
    try {
      encName = b64uDecode(p.enc_name);
      encWish = b64uDecode(p.enc_wish);
    } catch {
      /* invalid */
    }
    let name: string | null = null;
    let wish: string | null = null;
    if (pid && ipk && idh && encName) {
      try {
        const raw = fromUtf8(wasm.gkOpen(gk, "name", gid, encName, pid, ipk, idh)).trim();
        // Validity (Spec §6) is unchanged; only the displayed text is cleaned.
        name = raw === "" ? null : cleanName(raw) || INVISIBLE_NAME;
      } catch {
        name = null;
      }
      if (encWish) {
        try {
          wish = fromUtf8(wasm.gkOpen(gk, "wish", gid, encWish, pid, ipk, idh));
        } catch {
          wish = null;
        }
      }
    }
    const valid = name !== null && pid !== null && ipk !== null && idh !== null && encName !== null;
    decoded.push({
      pid: pid ?? new Uint8Array(16),
      m: { pidB64: p.pid, name, wish, valid, duplicate: false },
      e: valid ? { pid: pid!, ipk: ipk!, idh: idh!, encName: encName! } : null,
    });
  }
  decoded.sort((a, b) => compareBytes(a.pid, b.pid));
  markDuplicates(decoded.map((d) => d.m));
  const allValid = decoded.every((d) => d.e !== null);
  return {
    members: decoded.map((d) => d.m),
    entries: decoded.flatMap((d) => (d.e ? [d.e] : [])),
    allValid,
  };
}

/** Sets `duplicate` on every valid member whose name key occurs more than once. */
export function markDuplicates(members: Member[]): void {
  const count = new Map<string, number>();
  const keyOf = (m: Member) => (m.valid && m.name !== null && m.name !== INVISIBLE_NAME ? nameKey(m.name) : null);
  for (const m of members) {
    const k = keyOf(m);
    if (k) count.set(k, (count.get(k) ?? 0) + 1);
  }
  for (const m of members) {
    const k = keyOf(m);
    m.duplicate = k !== null && (count.get(k) ?? 0) > 1;
  }
}

export function decodeMeta(wasm: WichtelWasm, gk: Uint8Array, encMeta: string): GroupMeta | null {
  try {
    const raw = fromUtf8(wasm.gkOpen(gk, "meta", META_AAD_GID, b64uDecode(encMeta)));
    const v = JSON.parse(raw) as Partial<GroupMeta>;
    return {
      title: typeof v.title === "string" ? v.title : "",
      budget: typeof v.budget === "string" ? v.budget : "",
      event_date: typeof v.event_date === "string" ? v.event_date : "",
      description: typeof v.description === "string" ? v.description : "",
    };
  } catch {
    return null;
  }
}

export function sealMeta(wasm: WichtelWasm, gk: Uint8Array, meta: GroupMeta): Uint8Array {
  return wasm.gkSeal(gk, "meta", META_AAD_GID, utf8(JSON.stringify(meta)));
}
