/**
 * Error codes of the real WASM module (`WichtelError.code`, crates/wichtel-wasm/src/error.rs) and
 * their mapping onto UI/driver states. Kept apart from ./wasm.ts so the driver does not depend on
 * the loader.
 */

/** Stable codes of a thrown `WichtelError` (crates/wichtel-wasm/src/error.rs). */
export type WichtelErrorCode =
  | "INVALID_LENGTH"
  | "INVALID_KEY"
  | "BAD_SIGNATURE"
  | "DECRYPTION_FAILED"
  | "INVALID_ENCODING"
  | "INVALID_PARTICIPANT_COUNT"
  | "NOT_IN_ROSTER"
  | "OWN_ROLE_MISSING"
  | "COLLISION"
  | "NO_VALID_ATTEMPT"
  | "ATTEMPT_MISMATCH"
  | "REVEAL_COUNT"
  | "RNG_UNAVAILABLE"
  | "INVALID_ARGUMENT"
  | "INVALID_STATE"
  | "STATE_MISMATCH";

const CODES: ReadonlySet<string> = new Set<WichtelErrorCode>([
  "INVALID_LENGTH", "INVALID_KEY", "BAD_SIGNATURE", "DECRYPTION_FAILED", "INVALID_ENCODING",
  "INVALID_PARTICIPANT_COUNT", "NOT_IN_ROSTER", "OWN_ROLE_MISSING", "COLLISION", "NO_VALID_ATTEMPT",
  "ATTEMPT_MISMATCH", "REVEAL_COUNT", "RNG_UNAVAILABLE", "INVALID_ARGUMENT", "INVALID_STATE", "STATE_MISMATCH",
]);

/** The `code` of a `WichtelError` thrown by the WASM module (also after a worker round trip), else null. */
export function wichtelErrorCode(e: unknown): WichtelErrorCode | null {
  if (!e || typeof e !== "object") return null;
  const { name, code } = e as { name?: unknown; code?: unknown };
  return name === "WichtelError" && typeof code === "string" && CODES.has(code) ? (code as WichtelErrorCode) : null;
}

/** Recreates a `WichtelError` (e.g. from a worker reply), so `wichtelErrorCode` keeps working. */
export function wichtelError(code: string, message: string): Error {
  const e = new Error(message) as Error & { code: string };
  e.name = "WichtelError";
  e.code = code;
  return e;
}

/**
 * What the protocol driver does with a WASM error (Spec §11):
 * - `roster`: the server's roster does not fit our keys or is malformed ⇒ disturbance.
 * - `data`: data from the server is malformed (lengths, encodings) ⇒ disturbance.
 * - `state`: the locally cached evaluation state is unusable ⇒ drop it and recompute.
 * - `transient`: may work on the next attempt (no CSPRNG, unknown error) ⇒ retry.
 */
export type WasmFailure = "roster" | "data" | "state" | "transient";

export function classifyWasmError(e: unknown): WasmFailure {
  switch (wichtelErrorCode(e)) {
    case "NOT_IN_ROSTER":
    case "INVALID_KEY":
    case "INVALID_PARTICIPANT_COUNT":
    case "INVALID_ENCODING":
      return "roster";
    case "INVALID_LENGTH":
    case "BAD_SIGNATURE":
    case "DECRYPTION_FAILED":
    case "OWN_ROLE_MISSING":
    case "COLLISION":
    case "NO_VALID_ATTEMPT":
    case "ATTEMPT_MISMATCH":
    case "REVEAL_COUNT":
    case "INVALID_ARGUMENT":
      return "data";
    case "INVALID_STATE":
    case "STATE_MISMATCH":
      return "state";
    default:
      return "transient";
  }
}

/** German user-facing text for a WASM error (forms: create, join, edit). */
export function wasmErrorText(code: WichtelErrorCode): string {
  switch (code) {
    case "RNG_UNAVAILABLE":
      return "Dein Browser stellt keinen sicheren Zufall bereit. Bitte nutze einen aktuellen Browser.";
    case "DECRYPTION_FAILED":
    case "INVALID_ENCODING":
      return "Die Daten der Runde lassen sich nicht entschlüsseln – ist der Link vollständig?";
    case "INVALID_PARTICIPANT_COUNT":
      return "Die Teilnehmerzahl passt nicht (4 bis 30 Personen).";
    case "NOT_IN_ROSTER":
    case "INVALID_KEY":
      return "Die Teilnehmerliste vom Server passt nicht zu deinem Link.";
    default:
      return `Interner Fehler der Verschlüsselung (${code}). Bitte lade die Seite neu.`;
  }
}
