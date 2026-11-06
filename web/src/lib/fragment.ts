/**
 * Routing and URL-fragment handling.
 *
 * Secrets (GK, AS, seed) live only in the fragment (`#…`), which browsers never send to the
 * server. This module never logs; callers must not send fragments anywhere either.
 */
import { b64uDecodeLen, b64uEncode } from "./bytes";

export const GID_LEN = 16;
export const SECRET_LEN = 32;

export type Route =
  | { page: "home" }
  | { page: "create" }
  | { page: "group"; gidB64: string; gid: Uint8Array; fragment: FragmentResult }
  | { page: "not_found" };

export interface Secrets {
  /** Group key GK (32 B). */
  k: Uint8Array;
  /** Admin secret AS (32 B), Spielleiter link only. */
  a?: Uint8Array;
  /** Personal seed (32 B), personal link only. */
  s?: Uint8Array;
}

export type FragmentResult =
  | { ok: true; secrets: Secrets }
  | { ok: false; error: "missing_key" | "invalid" };

/**
 * Parses `k=…[&a=…][&s=…]` (leading `#` optional). Unknown parameters are ignored, duplicate or
 * malformed known parameters make the whole fragment invalid.
 */
export function parseFragment(hash: string): FragmentResult {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (raw.trim() === "") return { ok: false, error: "missing_key" };
  const seen = new Map<string, string>();
  for (const part of raw.split("&")) {
    if (part === "") continue;
    const eq = part.indexOf("=");
    const key = eq < 0 ? part : part.slice(0, eq);
    const value = eq < 0 ? "" : part.slice(eq + 1);
    if (key !== "k" && key !== "a" && key !== "s") continue;
    if (seen.has(key)) return { ok: false, error: "invalid" };
    seen.set(key, value);
  }
  const kRaw = seen.get("k");
  if (kRaw === undefined) return { ok: false, error: "missing_key" };
  const k = b64uDecodeLen(kRaw, SECRET_LEN);
  if (!k) return { ok: false, error: "invalid" };
  const secrets: Secrets = { k };
  for (const key of ["a", "s"] as const) {
    const v = seen.get(key);
    if (v === undefined) continue;
    const b = b64uDecodeLen(v, SECRET_LEN);
    if (!b) return { ok: false, error: "invalid" };
    secrets[key] = b;
  }
  return { ok: true, secrets };
}

export function buildFragment(s: Secrets): string {
  let f = `#k=${b64uEncode(s.k)}`;
  if (s.a) f += `&a=${b64uEncode(s.a)}`;
  if (s.s) f += `&s=${b64uEncode(s.s)}`;
  return f;
}

/**
 * Fragment to show in the address bar of a group page: GK and (if present) the admin secret, but
 * the seed only if `keepSeed` – normally it lives in local storage, so the address bar (and
 * history, synced history, a shared URL) only carries the invite/admin link.
 */
export function addressBarFragment(s: Secrets, keepSeed: boolean): string {
  const shown: Secrets = { k: s.k };
  if (s.a) shown.a = s.a;
  if (keepSeed && s.s) shown.s = s.s;
  return buildFragment(shown);
}

/** Parses pathname + hash into a route. Does not touch `window`. */
export function parseRoute(pathname: string, hash: string): Route {
  if (pathname === "/" || pathname === "" || pathname === "/index.html") return { page: "home" };
  if (pathname === "/neu" || pathname === "/neu/") return { page: "create" };
  const m = /^\/g\/([A-Za-z0-9_-]{22})\/?$/.exec(pathname);
  if (m) {
    const gidB64 = m[1]!;
    const gid = b64uDecodeLen(gidB64, GID_LEN);
    if (!gid) return { page: "not_found" };
    return { page: "group", gidB64, gid, fragment: parseFragment(hash) };
  }
  return { page: "not_found" };
}

export type LinkKind = "invite" | "admin" | "personal";

/** Builds an absolute link for sharing. `origin` e.g. `https://wichteln.example`. */
export function groupLink(origin: string, gidB64: string, kind: LinkKind, s: Secrets): string {
  const secrets: Secrets = { k: s.k };
  if (kind === "admin") {
    if (!s.a) throw new Error("admin secret missing");
    secrets.a = s.a;
  }
  if (kind === "personal") {
    if (!s.s) throw new Error("seed missing");
    secrets.s = s.s;
  }
  return `${origin}/g/${gidB64}${buildFragment(secrets)}`;
}
