/**
 * Per-group service-worker scopes for Web-Push (shared by page and service worker).
 *
 * Every group gets its own registration and thus its own PushSubscription/endpoint, so the server
 * cannot link the groups of one device. `/sw.js` lives at the root, so any scope below `/` is
 * allowed without a `Service-Worker-Allowed` header. The scope `/g/<gid>/` (trailing slash) does
 * not cover the page `/g/<gid>` itself: the worker only handles push and never controls pages.
 *
 * Spec §16.4: a second registration `/g/<gid>/wish/` holds the anonymous subscription for the
 * wish-change hint. Its endpoint only goes into the encrypted contact for the own Wichtelkind,
 * never directly to the server.
 */

export function pushScope(gidB64: string): string {
  return `/g/${gidB64}/`;
}

export function wishScope(gidB64: string): string {
  return `/g/${gidB64}/wish/`;
}

export type ScopeKind = "round" | "wish";

function scopePath(scope: string): string | null {
  try {
    return new URL(scope, "https://scope.invalid").pathname;
  } catch {
    return null;
  }
}

/** Kind and gid of a registration scope (absolute or path); null e.g. for the legacy "/" scope. */
export function parseScope(scope: string): { gid: string; kind: ScopeKind } | null {
  const path = scopePath(scope);
  const m = path ? /^\/g\/([A-Za-z0-9_-]{22})\/(wish\/)?$/.exec(path) : null;
  return m ? { gid: m[1]!, kind: m[2] ? "wish" : "round" } : null;
}

/** Inverse of `pushScope`: gid of a round scope URL (absolute or path), or null (e.g. legacy "/"). */
export function gidFromScope(scope: string): string | null {
  const s = parseScope(scope);
  return s?.kind === "round" ? s.gid : null;
}

export const NOTIFICATION_TITLE = "🎁 Wichteln";
export const ROUND_NOTIFICATION_BODY = "Es gibt Neuigkeiten in deiner Runde";
export const WISH_NOTIFICATION_BODY = "Dein Wichtelkind hat seinen Wunschzettel aktualisiert";

/**
 * Fixed notification for a push (pushes carry no payload, and the service worker loads nothing on
 * receipt): chosen only by the scope of the receiving registration. A scope ending in `/wish/` is
 * the hint that the own Wichtelkind changed their wish list (Spec §16.4) – without any name.
 */
export function notificationFor(scope: string): { title: string; body: string; tag: string } {
  const gid = parseScope(scope)?.gid ?? null;
  if ((scopePath(scope) ?? "").endsWith("/wish/")) {
    return { title: NOTIFICATION_TITLE, body: WISH_NOTIFICATION_BODY, tag: gid ? `wichtel-wish-${gid}` : "wichtel-wish" };
  }
  // One notification per group (a newer one replaces the older of the same group only).
  return { title: NOTIFICATION_TITLE, body: ROUND_NOTIFICATION_BODY, tag: gid ? `wichtel-update-${gid}` : "wichtel-update" };
}
