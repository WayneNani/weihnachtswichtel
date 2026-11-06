/**
 * Tiny key-value store on IndexedDB (shared by page and service worker).
 * Every access is wrapped in try/catch; if IndexedDB is unavailable (private mode, blocked
 * storage) an in-memory map is used instead, so the app keeps working for the session.
 */

export interface KvStore {
  get<T = unknown>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  del(key: string): Promise<void>;
  keys(prefix: string): Promise<string[]>;
}

const DB_NAME = "wichtel";
const STORE = "kv";

export function memoryKv(): KvStore {
  const m = new Map<string, unknown>();
  return {
    async get<T>(key: string) {
      return m.get(key) as T | undefined;
    },
    async set(key, value) {
      m.set(key, value);
    },
    async del(key) {
      m.delete(key);
    },
    async keys(prefix) {
      return [...m.keys()].filter((k) => k.startsWith(prefix));
    },
  };
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB open failed"));
    req.onblocked = () => reject(new Error("indexedDB blocked"));
  });
}

function wrap<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB request failed"));
  });
}

/** IndexedDB-backed store with transparent in-memory fallback. */
export function idbKv(): KvStore {
  const fallback = memoryKv();
  let dbPromise: Promise<IDBDatabase | null> | null = null;
  const db = (): Promise<IDBDatabase | null> => {
    if (!dbPromise) {
      dbPromise = (async () => {
        try {
          if (typeof indexedDB === "undefined") return null;
          return await openDb();
        } catch {
          return null;
        }
      })();
    }
    return dbPromise;
  };
  const run = async <T>(
    mode: IDBTransactionMode,
    fn: (s: IDBObjectStore) => IDBRequest<T>,
    fb: () => Promise<T>,
  ): Promise<T> => {
    const d = await db();
    if (!d) return fb();
    try {
      return await wrap(fn(d.transaction(STORE, mode).objectStore(STORE)));
    } catch {
      return fb();
    }
  };
  return {
    get: <T>(key: string) =>
      run<T | undefined>("readonly", (s) => s.get(key) as IDBRequest<T | undefined>, () => fallback.get<T>(key)),
    set: async (key, value) => {
      await fallback.set(key, value);
      await run("readwrite", (s) => s.put(value, key), async () => undefined as unknown as IDBValidKey);
    },
    del: async (key) => {
      await fallback.del(key);
      await run("readwrite", (s) => s.delete(key), async () => undefined);
    },
    keys: async (prefix) => {
      const all = await run<IDBValidKey[]>("readonly", (s) => s.getAllKeys(), async () => []);
      const mem = await fallback.keys(prefix);
      const set = new Set<string>(mem);
      for (const k of all) if (typeof k === "string" && k.startsWith(prefix)) set.add(k);
      return [...set];
    },
  };
}

/** Entry used by the service worker to open the right page on notification click. */
export interface PushLink {
  gid: string;
  /** Personal link (contains GK and seed – stays on this device). */
  link: string;
  title: string;
  at: number;
}

export const PUSH_LINKS_KEY = "push-links";
