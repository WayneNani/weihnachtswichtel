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
  joinedAt: number;
  valid: boolean;
}

export interface DecodedRoster {
  members: Member[];
  /** Protocol input, sorted by pid (only meaningful if `allValid`). */
  entries: RosterEntryInput[];
  allValid: boolean;
}

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
        name = fromUtf8(wasm.gkOpen(gk, "name", gid, encName, pid, ipk, idh)).trim();
        if (name === "") name = null;
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
      m: { pidB64: p.pid, name, wish, joinedAt: p.joined_at, valid },
      e: valid ? { pid: pid!, ipk: ipk!, idh: idh!, encName: encName! } : null,
    });
  }
  decoded.sort((a, b) => compareBytes(a.pid, b.pid));
  const allValid = decoded.every((d) => d.e !== null);
  return {
    members: decoded.map((d) => d.m),
    entries: decoded.flatMap((d) => (d.e ? [d.e] : [])),
    allValid,
  };
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
