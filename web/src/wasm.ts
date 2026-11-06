/**
 * Loads the crypto core. Real build: the wasm-bindgen output (`--target web`) is expected at
 * `/pkg/wichtel_wasm.js` (copied from `web/src/wasm-pkg/` into `web/dist/pkg/` by build.mjs).
 * Mock build: the TypeScript mock from ./mock/wasm.ts (removed from the real bundle by the
 * `__MOCK__` define).
 */
import type { WichtelWasm } from "./wasm-api";

export const WASM_MODULE_URL = "/pkg/wichtel_wasm.js";

let cached: Promise<WichtelWasm> | null = null;

export function loadWasm(opts: { inWorker?: boolean } = {}): Promise<WichtelWasm> {
  if (!cached) {
    cached = __MOCK__ ? loadMock(opts.inWorker ?? false) : loadReal();
    cached.catch(() => {
      cached = null;
    });
  }
  return cached;
}

async function loadMock(inWorker: boolean): Promise<WichtelWasm> {
  const { createMockWasm } = await import("./mock/wasm");
  return createMockWasm({
    rolesDelayMs: inWorker ? 700 : 150,
    disturb: () => {
      try {
        return globalThis.localStorage?.getItem("wichtel:mock:disturb") === "1";
      } catch {
        return false;
      }
    },
  });
}

/**
 * A4 (wasm + Verdrahtung): if the generated bindings differ from `WichtelWasm` (e.g. class
 * instead of plain object, `Uint8Array` vs. `Array`), adapt them here – the UI only sees the
 * interface from ./wasm-api.ts.
 */
async function loadReal(): Promise<WichtelWasm> {
  const url: string = WASM_MODULE_URL;
  const mod = (await import(/* webpackIgnore: true */ url)) as { default: (opts?: unknown) => Promise<unknown> } & WichtelWasm;
  await mod.default();
  return mod;
}
