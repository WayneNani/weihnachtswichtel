/**
 * JSON shapes of the HTTP API (mirror of `crates/wichtel-api/src/lib.rs`, see docs/api.md).
 * Binary fields are Base64url strings without padding.
 */

export type B64 = string;
export type Phase = "roles" | "reveal";

export type GroupStateJson =
  | { state: "open" }
  | { state: "drawing"; round: number; phase: Phase }
  | { state: "done"; round: number; t_star: number };

export interface ParticipantView {
  pid: B64;
  ipk: B64;
  idh: B64;
  enc_name: B64;
  enc_wish: B64;
}

export interface Progress {
  round: number;
  phase: Phase;
  submitted: B64[];
}

export type GroupView = GroupStateJson & {
  gid: B64;
  draw_no: number;
  enc_meta: B64;
  draw_at: number | null;
  schedule_missed: boolean;
  delete_after: number;
  created_at: number;
  participants: ParticipantView[];
  progress: Progress | null;
};

export interface CreateGroupRequest {
  admin_hash: B64;
  enc_meta: B64;
  delete_after: number;
  draw_at: number | null;
}

export interface CreateGroupResponse {
  gid: B64;
}

export interface ScheduleRequest {
  draw_at: number | null;
}

export interface JoinRequest {
  ipk: B64;
  idh: B64;
  auth_hash: B64;
  enc_name: B64;
  enc_wish: B64;
  join_sig: B64;
}

/**
 * `PUT …/participants/{pid}` (Spec §16.1): like `JoinRequest`; after the start `enc_name` must be
 * byte-identical to the stored one. `notify_endpoint` (only in `done`, §16.3): anonymous push
 * endpoint of the own Schenker from the contacts – the server pushes once and does not store it.
 */
export interface UpdateParticipantRequest extends JoinRequest {
  notify_endpoint?: string;
}

export interface JoinResponse {
  pid: B64;
}

export interface RevealEntry {
  pid: B64;
  ciphertext: B64;
}

export interface RevealRelease {
  round: number;
  selfdraw_aggregate: B64;
  t_star: number;
  reveals: RevealEntry[];
}

export interface VapidKeyResponse {
  public_key: B64;
}

export interface PushSubscriptionRequest {
  endpoint: string;
  p256dh: B64;
  auth: B64;
}

export type UpdateEvent = GroupStateJson & {
  draw_no: number;
  submitted_count: number;
  participant_count: number;
};

export type ErrorCode =
  | "bad_request"
  | "unauthorized"
  | "not_found"
  | "conflict"
  | "payload_too_large"
  | "too_many_requests"
  | "group_full"
  | "too_few_participants"
  | "internal";

export interface ErrorResponse {
  error: ErrorCode;
  message: string;
}

/** Group metadata, encrypted as `enc_meta` (Spec §6). */
export interface GroupMeta {
  title: string;
  budget: string;
  /** ISO date `YYYY-MM-DD`. */
  event_date: string;
  description: string;
}

/** Protocol constants (Spec §2). */
export const N_MIN = 4;
export const N_MAX = 30;
export const T_ATTEMPTS = 16;
export const NAME_MAX = 64;
export const WISH_MAX = 1000;
export const META_MAX = 2000;
export const NOTE_MAX = 461;
export const rolesVectorLen = (n: number): number => 2688 * n * n;
export const REVEAL_UPLOAD_LEN = 9216;
export const REVEAL_CT_LEN = 560;
export const SELFDRAW_LEN = 256;
/** Spec §16.2: contact `K_i` (HPKE enc ‖ ct) and max. endpoint bytes inside it. */
export const CONTACT_LEN = 816;
export const ENDPOINT_MAX = 700;
