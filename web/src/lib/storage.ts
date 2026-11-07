/**
 * Local records per group in localStorage. Everything is wrapped in try/catch: without storage
 * the app still works, but the personal link is then the only way back to one's result.
 */
import { b64uDecodeLen, b64uEncode } from "./bytes";
import { SECRET_LEN, type Secrets } from "./fragment";

const PREFIX = "wichtel:g:";

export interface LocalGroup {
  /** GK, base64url. */
  k: string;
  /** Admin secret, base64url (only on the Spielleiter's device). */
  a?: string;
  /** Personal seed, base64url. */
  s?: string;
  /** Own pid once joined (base64url). */
  pid?: string;
  /** Title (decrypted, for the "Deine Runden" list on this device only). */
  title?: string;
  /** User confirmed that the personal link is saved. */
  linkSaved?: boolean;
  /** Private note for the Schenker (sent encrypted in step 2). */
  note?: string;
  /** Push opt-in for this group. */
  push?: boolean;
  /** The notification bell was opened at least once (hides its attention label). */
  pushPrompted?: boolean;
  /** First protocol round seen for the current draw (collision hint, Spec §11). */
  drawRound?: { drawNo: number; firstRound: number };
  updatedAt: number;
}

let memory = new Map<string, string>();

function rawGet(key: string): string | null {
  try {
    const v = globalThis.localStorage?.getItem(key);
    if (v !== null && v !== undefined) return v;
  } catch {
    /* storage blocked */
  }
  return memory.get(key) ?? null;
}

function rawSet(key: string, value: string): void {
  memory.set(key, value);
  try {
    globalThis.localStorage?.setItem(key, value);
  } catch {
    /* quota or blocked: memory copy is kept for this session */
  }
}

function rawDel(key: string): void {
  memory.delete(key);
  try {
    globalThis.localStorage?.removeItem(key);
  } catch {
    /* ignore */
  }
}

function rawKeys(): string[] {
  const keys = new Set(memory.keys());
  try {
    const ls = globalThis.localStorage;
    if (ls) for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i);
      if (k) keys.add(k);
    }
  } catch {
    /* ignore */
  }
  return [...keys];
}

/** True if localStorage actually persists (for UI hints). */
export function storageAvailable(): boolean {
  try {
    const ls = globalThis.localStorage;
    if (!ls) return false;
    ls.setItem("wichtel:probe", "1");
    ls.removeItem("wichtel:probe");
    return true;
  } catch {
    return false;
  }
}

export function loadGroup(gidB64: string): LocalGroup | null {
  const raw = rawGet(PREFIX + gidB64);
  if (!raw) return null;
  try {
    const v = JSON.parse(raw) as LocalGroup;
    if (typeof v !== "object" || v === null || typeof v.k !== "string") return null;
    return v;
  } catch {
    return null;
  }
}

export function saveGroup(gidB64: string, patch: Partial<LocalGroup>): LocalGroup {
  const prev = loadGroup(gidB64);
  const next = { ...(prev ?? { k: "" }), ...patch, updatedAt: Date.now() } as LocalGroup;
  // Drop keys explicitly set to undefined.
  for (const key of Object.keys(next) as (keyof LocalGroup)[]) if (next[key] === undefined) delete next[key];
  rawSet(PREFIX + gidB64, JSON.stringify(next));
  return next;
}

/**
 * True if localStorage itself (not just the in-memory fallback) holds exactly this GK and seed for
 * the group – only then may the seed be dropped from the address bar.
 */
export function seedPersisted(gidB64: string, k: Uint8Array, s: Uint8Array): boolean {
  try {
    const raw = globalThis.localStorage?.getItem(PREFIX + gidB64);
    if (!raw) return false;
    const v = JSON.parse(raw) as Partial<LocalGroup>;
    return v.k === b64uEncode(k) && v.s === b64uEncode(s);
  } catch {
    return false;
  }
}

/** Removes the group's localStorage record and extras (see forget.ts for the full cleanup). */
export function forgetGroup(gidB64: string): void {
  rawDel(PREFIX + gidB64);
  for (const k of rawKeys()) if (k.startsWith(`wichtel:x:${gidB64}:`)) rawDel(k);
}

export function listGroups(): { gid: string; rec: LocalGroup }[] {
  const out: { gid: string; rec: LocalGroup }[] = [];
  for (const key of rawKeys()) {
    if (!key.startsWith(PREFIX)) continue;
    const gid = key.slice(PREFIX.length);
    const rec = loadGroup(gid);
    if (rec) out.push({ gid, rec });
  }
  return out.sort((a, b) => b.rec.updatedAt - a.rec.updatedAt);
}

/**
 * Merges secrets from the URL with what this device remembers. The URL wins for GK; seed and
 * admin secret are taken from storage if the URL lacks them but GK matches.
 */
export function mergeSecrets(gidB64: string, fromUrl: Secrets): { secrets: Secrets; seedFromStorage: boolean; adminFromStorage: boolean } {
  const rec = loadGroup(gidB64);
  const secrets: Secrets = { ...fromUrl };
  let seedFromStorage = false;
  let adminFromStorage = false;
  if (rec && rec.k === b64uEncode(fromUrl.k)) {
    if (!secrets.s && rec.s) {
      const s = b64uDecodeLen(rec.s, SECRET_LEN);
      if (s) {
        secrets.s = s;
        seedFromStorage = true;
      }
    }
    if (!secrets.a && rec.a) {
      const a = b64uDecodeLen(rec.a, SECRET_LEN);
      if (a) {
        secrets.a = a;
        adminFromStorage = true;
      }
    }
  }
  return { secrets, seedFromStorage, adminFromStorage };
}

/** Small per-group extras (e.g. mock bots). */
export function loadExtra<T>(gidB64: string, name: string): T | null {
  const raw = rawGet(`wichtel:x:${gidB64}:${name}`);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function saveExtra(gidB64: string, name: string, value: unknown): void {
  rawSet(`wichtel:x:${gidB64}:${name}`, JSON.stringify(value));
}

/** For tests only. */
export function _resetMemoryStorage(): void {
  memory = new Map();
}
