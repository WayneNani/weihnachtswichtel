/**
 * Per-group service-worker scope for Web-Push (shared by page and service worker).
 *
 * Every group gets its own registration and thus its own PushSubscription/endpoint, so the server
 * cannot link the groups of one device. `/sw.js` lives at the root, so any scope below `/` is
 * allowed without a `Service-Worker-Allowed` header. The scope `/g/<gid>/` (trailing slash) does
 * not cover the page `/g/<gid>` itself: the worker only handles push and never controls pages.
 */

export function pushScope(gidB64: string): string {
  return `/g/${gidB64}/`;
}

/** Inverse of `pushScope`: gid of a scope URL (absolute or path), or null (e.g. legacy "/"). */
export function gidFromScope(scope: string): string | null {
  let path: string;
  try {
    path = new URL(scope, "https://scope.invalid").pathname;
  } catch {
    return null;
  }
  const m = /^\/g\/([A-Za-z0-9_-]{22})\/$/.exec(path);
  return m ? m[1]! : null;
}
