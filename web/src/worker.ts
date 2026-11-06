/**
 * Web Worker for the expensive step 1 (role vector: up to 2.4 MB and ~70 MB of ChaCha20
 * keystream for n = 30). Keys cannot cross threads, so they are re-derived from the seed here.
 */
import { computeRolesInline, type RolesJob } from "./protocol/driver";
import { loadWasm } from "./wasm";

interface WorkerScope {
  onmessage: ((ev: MessageEvent<{ id: number; job: RolesJob }>) => void) | null;
  postMessage(msg: unknown, transfer?: Transferable[]): void;
}
const scope = self as unknown as WorkerScope;

scope.onmessage = (ev) => {
  const { id, job } = ev.data;
  void (async () => {
    try {
      const wasm = await loadWasm({ inWorker: true });
      const { body, sig } = await computeRolesInline(wasm)(job);
      scope.postMessage({ id, ok: true, body, sig }, [body.buffer as ArrayBuffer]);
    } catch (e) {
      scope.postMessage({ id, ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  })();
};
