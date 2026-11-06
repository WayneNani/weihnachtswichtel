/** Runs role-vector jobs in `/worker.js`; falls back to the main thread if workers fail. */
import type { WichtelWasm } from "../wasm-api";
import { computeRolesInline, type RolesJob, type RolesJobResult } from "./driver";

type Reply = { id: number; ok: true; body: Uint8Array; sig: Uint8Array } | { id: number; ok: false; error: string };

export function createRolesComputer(getWasm: () => Promise<WichtelWasm>): (job: RolesJob) => Promise<RolesJobResult> {
  let worker: Worker | null = null;
  let broken = typeof Worker === "undefined";
  let nextId = 1;
  const waiting = new Map<number, { resolve: (r: RolesJobResult) => void; reject: (e: Error) => void }>();

  const failAll = (msg: string) => {
    for (const w of waiting.values()) w.reject(new Error(msg));
    waiting.clear();
  };

  const getWorker = (): Worker | null => {
    if (broken) return null;
    if (worker) return worker;
    try {
      worker = new Worker("/worker.js", { type: "module", name: "wichtel-roles" });
      worker.onmessage = (ev: MessageEvent<Reply>) => {
        const w = waiting.get(ev.data.id);
        if (!w) return;
        waiting.delete(ev.data.id);
        if (ev.data.ok) w.resolve({ body: ev.data.body, sig: ev.data.sig });
        else w.reject(new Error(ev.data.error));
      };
      worker.onerror = () => {
        broken = true;
        worker?.terminate();
        worker = null;
        failAll("worker_failed");
      };
      return worker;
    } catch {
      broken = true;
      return null;
    }
  };

  return async (job) => {
    const w = getWorker();
    if (w) {
      try {
        return await new Promise<RolesJobResult>((resolve, reject) => {
          const id = nextId++;
          waiting.set(id, { resolve, reject });
          w.postMessage({ id, job });
        });
      } catch (e) {
        if (!(e instanceof Error) || e.message !== "worker_failed") throw e;
      }
    }
    return computeRolesInline(await getWasm())(job);
  };
}
