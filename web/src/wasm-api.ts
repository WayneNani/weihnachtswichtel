/**
 * Contract for the functions exported by `crates/wichtel-wasm` (wasm-bindgen).
 *
 * Mirrors the public API of `wichtel-core` (see docs/04-protokoll-spec.md).
 * All byte values are `Uint8Array`. The UI talks only to this interface, so it can
 * run against `src/mock/` until the real WASM module exists (agent A4).
 */

/** Opaque handle to a participant's derived long-term keys (lives in WASM memory). */
export interface ParticipantKeysHandle {
  readonly pid: Uint8Array; // 16 B
  readonly ipk: Uint8Array; // 32 B
  readonly idh: Uint8Array; // 32 B
  readonly authToken: Uint8Array; // 32 B
  /** Spec §5 join signature. */
  signJoin(encName: Uint8Array, encWish: Uint8Array): Uint8Array; // 64 B
  /** Spec §12; kind 1 = roles, 2 = reveal. */
  signUpload(kind: 1 | 2, round: number, body: Uint8Array): Uint8Array; // 64 B
  free(): void;
}

export interface RosterEntryInput {
  pid: Uint8Array;
  ipk: Uint8Array;
  idh: Uint8Array;
  encName: Uint8Array; // hashed inside WASM
}

/** Public evaluation of R (Spec §7.4) plus own positions. */
export interface RolesEvaluation {
  /** false ⇒ collision round (server advances automatically). */
  valid: boolean;
  /** Attempts 1…16: whether valid. */
  attemptValid: boolean[];
  /** Own role missing although areas are valid ⇒ disturbance. */
  ownRoleMissing: boolean;
  /** Opaque serialized state needed for step 2 and the result (kept in IndexedDB). */
  state: Uint8Array;
}

export interface DrawResultJs {
  recipientPid: Uint8Array;
  note: string;
}

export interface WichtelWasm {
  protocolVersion(): string;
  participantLimits(): [number, number];

  /** 32 random bytes from the browser CSPRNG (GK, AS, seed). */
  generateSecret(): Uint8Array;
  adminHash(adminSecret: Uint8Array): Uint8Array;
  deriveKeys(seed: Uint8Array, gid: Uint8Array): ParticipantKeysHandle;

  /** Spec §6. context: "meta" | "name" | "wish". pid/ipk/idh required for name and wish. */
  gkSeal(
    gk: Uint8Array,
    context: "meta" | "name" | "wish",
    gid: Uint8Array,
    data: Uint8Array,
    pid?: Uint8Array,
    ipk?: Uint8Array,
    idh?: Uint8Array,
  ): Uint8Array;
  gkOpen(
    gk: Uint8Array,
    context: "meta" | "name" | "wish",
    gid: Uint8Array,
    sealed: Uint8Array,
    pid?: Uint8Array,
    ipk?: Uint8Array,
    idh?: Uint8Array,
  ): Uint8Array;

  /** 8 words (Spec §5). */
  fingerprint(gid: Uint8Array, roster: RosterEntryInput[]): string[];

  /** Step 1 (Spec §7): masked role vector V_i. Heavy – call from a Web Worker. */
  buildRolesVector(
    keys: ParticipantKeysHandle,
    gid: Uint8Array,
    round: number,
    roster: RosterEntryInput[],
  ): Uint8Array;

  /** Evaluate R and own positions. */
  evaluateRoles(
    keys: ParticipantKeysHandle,
    gid: Uint8Array,
    round: number,
    roster: RosterEntryInput[],
    r: Uint8Array,
  ): RolesEvaluation;

  /** Step 2 (Spec §9): SD_i ‖ C_{i,1..16} (9216 B). */
  buildRevealUpload(
    keys: ParticipantKeysHandle,
    gid: Uint8Array,
    round: number,
    roster: RosterEntryInput[],
    evaluationState: Uint8Array,
    note: string,
  ): Uint8Array;

  /** Recompute t* from the released aggregate; null ⇒ no valid attempt. */
  selectAttempt(evaluationState: Uint8Array, selfdrawAggregate: Uint8Array): number | null;

  /** Spec §9.3: open the released reveals of t*. Throws on disturbance. */
  openResult(
    keys: ParticipantKeysHandle,
    gid: Uint8Array,
    round: number,
    roster: RosterEntryInput[],
    evaluationState: Uint8Array,
    tStar: number,
    reveals: { pid: Uint8Array; ciphertext: Uint8Array }[],
  ): DrawResultJs;

  /**
   * Spec §16.2: contact for the own recipient (816 B). `endpoint` = the anonymous push endpoint
   * of the wish-scope subscription, or "" (no notification). Fresh randomness on every call.
   * `recipientIdh` = IDH of the recipient from the roster (the pid comes from openResult).
   */
  buildContact(
    keys: ParticipantKeysHandle,
    gid: Uint8Array,
    round: number,
    roster: RosterEntryInput[],
    evaluationState: Uint8Array,
    tStar: number,
    recipientIdh: Uint8Array,
    endpoint: string,
  ): Uint8Array;

  /**
   * Spec §16.2: tries all contacts (concatenation of 816-B blocks as served) and returns the
   * endpoint from the own Schenker, or null (none uploaded yet, or the Schenker has push off).
   */
  openContacts(
    keys: ParticipantKeysHandle,
    gid: Uint8Array,
    round: number,
    roster: RosterEntryInput[],
    evaluationState: Uint8Array,
    tStar: number,
    contacts: Uint8Array,
  ): string | null;
}
