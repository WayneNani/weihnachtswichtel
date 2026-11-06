/**
 * Placeholder for mocks of the WASM API and the HTTP API (agent A3 fills this in).
 * Mocks must implement `WichtelWasm` from ../wasm-api.ts and use JSON fixtures that
 * match docs/api.md.
 */
import type { WichtelWasm } from "../wasm-api";

export type MockWasm = Partial<WichtelWasm>;
export const mockWasm: MockWasm = {
  protocolVersion: () => "wichtel/v1 (mock)",
  participantLimits: () => [4, 30],
};
