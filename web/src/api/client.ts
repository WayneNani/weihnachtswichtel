/**
 * HTTP client for docs/api.md. Only paths and bodies go to the server – never URL fragments.
 */
import { b64uEncode } from "../lib/bytes";
import type {
  CreateGroupRequest,
  CreateGroupResponse,
  ErrorCode,
  GroupView,
  JoinRequest,
  JoinResponse,
  PushSubscriptionRequest,
  RevealRelease,
  VapidKeyResponse,
} from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode | "network",
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

const SIG_HEADER = "X-Wichtel-Signature";

export interface Api {
  createGroup(req: CreateGroupRequest): Promise<CreateGroupResponse>;
  getGroup(gid: string): Promise<GroupView>;
  deleteGroup(gid: string, adminSecret: Uint8Array): Promise<void>;
  setSchedule(gid: string, adminSecret: Uint8Array, drawAt: number | null): Promise<void>;
  start(gid: string, adminSecret: Uint8Array): Promise<void>;
  restart(gid: string, adminSecret: Uint8Array): Promise<void>;
  join(gid: string, req: JoinRequest): Promise<JoinResponse>;
  updateParticipant(gid: string, pid: string, token: Uint8Array, req: JoinRequest): Promise<void>;
  /** `bearer` is AS (admin) or tok (self). */
  removeParticipant(gid: string, pid: string, bearer: Uint8Array): Promise<void>;
  uploadRoles(gid: string, round: number, token: Uint8Array, body: Uint8Array, sig: Uint8Array): Promise<void>;
  /** `null` while incomplete (409). */
  getRoles(gid: string, round: number): Promise<Uint8Array | null>;
  uploadReveal(gid: string, round: number, token: Uint8Array, body: Uint8Array, sig: Uint8Array): Promise<void>;
  /** `null` while incomplete (409). */
  getReveal(gid: string, round: number): Promise<RevealRelease | null>;
  vapidKey(): Promise<VapidKeyResponse>;
  putPush(gid: string, pid: string, token: Uint8Array, sub: PushSubscriptionRequest): Promise<void>;
  deletePush(gid: string, pid: string, token: Uint8Array): Promise<void>;
  eventsUrl(gid: string): string;
}

export function createApi(fetchImpl: FetchLike = (i, init) => fetch(i, init), base = ""): Api {
  const url = (path: string) => `${base}/api${path}`;
  const enc = encodeURIComponent;
  const bearer = (secret: Uint8Array) => ({ Authorization: `Bearer ${b64uEncode(secret)}` });

  async function call(path: string, init: RequestInit = {}): Promise<Response> {
    let res: Response;
    try {
      res = await fetchImpl(url(path), {
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        ...init,
      });
    } catch {
      throw new ApiError(0, "network", "Keine Verbindung zum Server");
    }
    if (res.ok) return res;
    let code: ErrorCode = "internal";
    let message = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { error?: ErrorCode; message?: string };
      if (body.error) code = body.error;
      if (body.message) message = body.message;
    } catch {
      if (res.status === 404) code = "not_found";
      else if (res.status === 409) code = "conflict";
      else if (res.status === 401) code = "unauthorized";
    }
    throw new ApiError(res.status, code, message);
  }

  const json = (body: unknown): RequestInit => ({
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" },
  });

  const binary = (token: Uint8Array, body: Uint8Array, sig: Uint8Array): RequestInit => ({
    method: "PUT",
    body: body as unknown as BodyInit,
    headers: {
      ...bearer(token),
      [SIG_HEADER]: b64uEncode(sig),
      "Content-Type": "application/octet-stream",
    },
  });

  const nullOn409 = async <T>(f: () => Promise<T>): Promise<T | null> => {
    try {
      return await f();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) return null;
      throw e;
    }
  };

  return {
    async createGroup(req) {
      const res = await call("/groups", { method: "POST", ...json(req) });
      return (await res.json()) as CreateGroupResponse;
    },
    async getGroup(gid) {
      const res = await call(`/groups/${enc(gid)}`);
      return (await res.json()) as GroupView;
    },
    async deleteGroup(gid, as) {
      await call(`/groups/${enc(gid)}`, { method: "DELETE", headers: bearer(as) });
    },
    async setSchedule(gid, as, drawAt) {
      const init = json({ draw_at: drawAt });
      await call(`/groups/${enc(gid)}/schedule`, {
        method: "PUT",
        body: init.body,
        headers: { ...(init.headers as Record<string, string>), ...bearer(as) },
      });
    },
    async start(gid, as) {
      await call(`/groups/${enc(gid)}/start`, { method: "POST", headers: bearer(as) });
    },
    async restart(gid, as) {
      await call(`/groups/${enc(gid)}/restart`, { method: "POST", headers: bearer(as) });
    },
    async join(gid, req) {
      const res = await call(`/groups/${enc(gid)}/participants`, { method: "POST", ...json(req) });
      return (await res.json()) as JoinResponse;
    },
    async updateParticipant(gid, pid, tok, req) {
      const init = json(req);
      await call(`/groups/${enc(gid)}/participants/${enc(pid)}`, {
        method: "PUT",
        body: init.body,
        headers: { ...(init.headers as Record<string, string>), ...bearer(tok) },
      });
    },
    async removeParticipant(gid, pid, secret) {
      await call(`/groups/${enc(gid)}/participants/${enc(pid)}`, { method: "DELETE", headers: bearer(secret) });
    },
    async uploadRoles(gid, round, tok, body, sig) {
      await call(`/groups/${enc(gid)}/rounds/${round}/roles`, binary(tok, body, sig));
    },
    getRoles(gid, round) {
      return nullOn409(async () => {
        const res = await call(`/groups/${enc(gid)}/rounds/${round}/roles`);
        return new Uint8Array(await res.arrayBuffer());
      });
    },
    async uploadReveal(gid, round, tok, body, sig) {
      await call(`/groups/${enc(gid)}/rounds/${round}/reveal`, binary(tok, body, sig));
    },
    getReveal(gid, round) {
      return nullOn409(async () => {
        const res = await call(`/groups/${enc(gid)}/rounds/${round}/reveal`);
        return (await res.json()) as RevealRelease;
      });
    },
    async vapidKey() {
      const res = await call("/push/vapid-key");
      return (await res.json()) as VapidKeyResponse;
    },
    async putPush(gid, pid, tok, sub) {
      const init = json(sub);
      await call(`/groups/${enc(gid)}/participants/${enc(pid)}/push`, {
        method: "PUT",
        body: init.body,
        headers: { ...(init.headers as Record<string, string>), ...bearer(tok) },
      });
    },
    async deletePush(gid, pid, tok) {
      await call(`/groups/${enc(gid)}/participants/${enc(pid)}/push`, { method: "DELETE", headers: bearer(tok) });
    },
    eventsUrl(gid) {
      return url(`/groups/${enc(gid)}/events`);
    },
  };
}
