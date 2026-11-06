/**
 * Service worker (served as /sw.js). Only used for Web-Push (Konzept §7.4):
 * - Pushes carry no payload; we always show the same fixed text.
 * - A click opens the personal link stored in IndexedDB (never sent anywhere).
 * No caching, no fetch handler: the app always talks to the server directly.
 */
import { idbKv, PUSH_LINKS_KEY, type PushLink } from "./lib/idb";

const sw = self as unknown as ServiceWorkerGlobalScope;
const kv = idbKv();

const NOTIFICATION_TITLE = "🎁 Wichteln";
const NOTIFICATION_BODY = "Es gibt Neuigkeiten in deiner Runde";

sw.addEventListener("install", () => {
  void sw.skipWaiting();
});

sw.addEventListener("activate", (event) => {
  event.waitUntil(sw.clients.claim());
});

sw.addEventListener("push", (event) => {
  // Payload (if any) is ignored on purpose.
  event.waitUntil(
    sw.registration.showNotification(NOTIFICATION_TITLE, {
      body: NOTIFICATION_BODY,
      icon: "/icon-192.png",
      badge: "/icon-192.png",
      tag: "wichtel-update",
      lang: "de",
    }),
  );
});

async function targetUrl(): Promise<string> {
  try {
    const links = (await kv.get<PushLink[]>(PUSH_LINKS_KEY)) ?? [];
    if (links.length === 1) return links[0]!.link;
  } catch {
    /* fall through */
  }
  // Several (or unknown) rounds: the start page lists the rounds stored on this device.
  return "/";
}

sw.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    (async () => {
      const url = await targetUrl();
      const target = new URL(url, sw.location.origin);
      const windows = await sw.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const w of windows) {
        const u = new URL(w.url);
        if (u.origin === target.origin && u.pathname === target.pathname && "focus" in w) {
          await w.focus();
          return;
        }
      }
      await sw.clients.openWindow(url);
    })(),
  );
});
