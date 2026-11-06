/**
 * Web-Push opt-in (Konzept §7.4). Off by default; only after an explicit click.
 * The server stores endpoint + keys and sends payload-less pushes to everybody in the group.
 */
import type { Api } from "./api/client";
import { b64uDecode, b64uEncode, bytesEqual } from "./lib/bytes";
import { idbKv, PUSH_LINKS_KEY, type PushLink } from "./lib/idb";
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

async function registration(): Promise<ServiceWorkerRegistration> {
  await navigator.serviceWorker.register("/sw.js", { scope: "/" });
  return navigator.serviceWorker.ready;
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
  const reg = await registration();
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
    const remaining = await setLink(null, ctx.gidB64);
    if (remaining.length === 0 && "serviceWorker" in navigator) {
      try {
        const reg = await navigator.serviceWorker.getRegistration("/");
        const sub = await reg?.pushManager.getSubscription();
        await sub?.unsubscribe();
      } catch {
        /* ignore */
      }
    }
  }
}

/** Forget local push state for a group (e.g. after deletion or leaving). */
export async function forgetPush(gidB64: string): Promise<void> {
  await setLink(null, gidB64);
}
