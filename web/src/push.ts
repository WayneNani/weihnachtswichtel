/**
 * Web-Push opt-in (Konzept §7.4). Off by default; only after an explicit click.
 * The server stores endpoint + keys and sends payload-less pushes to everybody in the group.
 * Every group has its own service-worker registration and PushSubscription (lib/pushscope.ts).
 */
import type { Api } from "./api/client";
import { b64uDecode, b64uEncode, bytesEqual } from "./lib/bytes";
import { idbKv, PUSH_LINKS_KEY, type PushLink } from "./lib/idb";
import { pushScope } from "./lib/pushscope";
import { saveGroup } from "./lib/storage";

export type PushSupport = "supported" | "unsupported" | "ios_homescreen" | "denied" | "insecure";

export function isIos(): boolean {
  const ua = navigator.userAgent;
  return /iPad|iPhone|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
}

export function isStandalone(): boolean {
  try {
    return (
      window.matchMedia("(display-mode: standalone)").matches ||
      (navigator as unknown as { standalone?: boolean }).standalone === true
    );
  } catch {
    return false;
  }
}

export function pushSupport(): PushSupport {
  if (typeof window === "undefined") return "unsupported";
  if (!window.isSecureContext) return "insecure";
  const hasApis = "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  if (isIos() && !isStandalone()) return "ios_homescreen";
  if (!hasApis) return "unsupported";
  if (Notification.permission === "denied") return "denied";
  return "supported";
}

const kv = idbKv();

function hasServiceWorker(): boolean {
  return typeof navigator !== "undefined" && "serviceWorker" in navigator;
}

/** Waits until `reg` has an active worker (needed for pushManager.subscribe). */
function activated(reg: ServiceWorkerRegistration): Promise<ServiceWorkerRegistration> {
  if (reg.active) return Promise.resolve(reg);
  const sw = reg.installing ?? reg.waiting;
  if (!sw) return Promise.reject(new Error("Der Service Worker konnte nicht gestartet werden."));
  return new Promise((resolve, reject) => {
    const onChange = () => {
      if (sw.state === "activated") {
        sw.removeEventListener("statechange", onChange);
        resolve(reg);
      } else if (sw.state === "redundant") {
        sw.removeEventListener("statechange", onChange);
        reject(new Error("Der Service Worker konnte nicht gestartet werden."));
      }
    };
    sw.addEventListener("statechange", onChange);
    onChange();
  });
}

/** Registration of exactly this scope (getRegistration() would fall back to a wider scope). */
async function findRegistration(scopePath: string): Promise<ServiceWorkerRegistration | null> {
  if (!hasServiceWorker()) return null;
  const want = new URL(scopePath, location.origin).href;
  const regs = await navigator.serviceWorker.getRegistrations();
  return regs.find((r) => r.scope === want) ?? null;
}

/** Unsubscribes and unregisters the registration of exactly `scopePath` (errors ignored). */
async function dropRegistration(scopePath: string): Promise<void> {
  try {
    const reg = await findRegistration(scopePath);
    if (!reg) return;
    try {
      const sub = await reg.pushManager.getSubscription();
      await sub?.unsubscribe();
    } finally {
      await reg.unregister();
    }
  } catch {
    /* ignore */
  }
}

async function setLink(entry: PushLink | null, gid: string): Promise<PushLink[]> {
  let links: PushLink[] = [];
  try {
    links = ((await kv.get<PushLink[]>(PUSH_LINKS_KEY)) ?? []).filter((l) => l.gid !== gid);
    if (entry) links.push(entry);
    await kv.set(PUSH_LINKS_KEY, links);
  } catch {
    /* storage unavailable: click falls back to "/" */
  }
  return links;
}

/** Older versions used one registration for "/" shared by all groups: drop it once unused. */
async function dropLegacyIfUnused(remaining: PushLink[]): Promise<void> {
  if (remaining.length === 0) await dropRegistration("/");
}

export interface PushContext {
  api: Api;
  gidB64: string;
  pidB64: string;
  token: Uint8Array;
  personalLink: string;
  title: string;
}

export async function enablePush(ctx: PushContext): Promise<void> {
  const perm = Notification.permission === "granted" ? "granted" : await Notification.requestPermission();
  if (perm !== "granted") throw new Error("Benachrichtigungen wurden im Browser nicht erlaubt.");
  const reg = await activated(await navigator.serviceWorker.register("/sw.js", { scope: pushScope(ctx.gidB64) }));
  const { public_key } = await ctx.api.vapidKey();
  const key = b64uDecode(public_key);
  let sub = await reg.pushManager.getSubscription();
  const current = sub?.options.applicationServerKey;
  if (sub && current && !bytesEqual(new Uint8Array(current), key)) {
    await sub.unsubscribe();
    sub = null;
  }
  if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key as BufferSource });
  const p256dh = sub.getKey("p256dh");
  const auth = sub.getKey("auth");
  if (!p256dh || !auth) throw new Error("Der Browser liefert keine Push-Schlüssel.");
  await ctx.api.putPush(ctx.gidB64, ctx.pidB64, ctx.token, {
    endpoint: sub.endpoint,
    p256dh: b64uEncode(new Uint8Array(p256dh)),
    auth: b64uEncode(new Uint8Array(auth)),
  });
  await setLink({ gid: ctx.gidB64, link: ctx.personalLink, title: ctx.title, at: Date.now() }, ctx.gidB64);
  saveGroup(ctx.gidB64, { push: true });
}

export async function disablePush(ctx: Omit<PushContext, "personalLink" | "title">): Promise<void> {
  try {
    await ctx.api.deletePush(ctx.gidB64, ctx.pidB64, ctx.token);
  } finally {
    saveGroup(ctx.gidB64, { push: false });
    await forgetPushLocally(ctx.gidB64);
  }
}

async function forgetPushLocally(gidB64: string): Promise<void> {
  const remaining = await setLink(null, gidB64);
  if (!hasServiceWorker()) return;
  await dropRegistration(pushScope(gidB64));
  await dropLegacyIfUnused(remaining);
}

/** Credentials to also unsubscribe on the server (the participant's own token). */
export interface PushServerCtx {
  api: Api;
  pidB64: string;
  token: Uint8Array;
}

/**
 * Forget push state for a group (after "vergessen", leaving or deletion): with `server`, the
 * subscription is first removed on the server (errors ignored – e.g. group already gone); then
 * the group's push link and its service-worker registration are removed on this device.
 */
export async function forgetPush(gidB64: string, server?: PushServerCtx): Promise<void> {
  if (server) {
    try {
      await server.api.deletePush(gidB64, server.pidB64, server.token);
    } catch {
      /* ignore */
    }
  }
  await forgetPushLocally(gidB64);
}
