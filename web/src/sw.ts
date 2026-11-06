// Service worker (Phase-0 skeleton). Agent A3 implements: payload-less push → fixed
// notification text; click opens the personal link stored in IndexedDB.
const sw = self as unknown as ServiceWorkerGlobalScope;

sw.addEventListener("install", () => {
  void sw.skipWaiting();
});

export {};
