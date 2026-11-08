// Spec §16: wish list after the start, contacts and the anonymous hint to the Schenker.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, createApi, type Api } from "../api/client";
import type { GroupView, UpdateParticipantRequest } from "../api/types";
import { forgetGroupOnDevice } from "../forget";
import { b64uDecode, b64uEncode } from "../lib/bytes";
import { memoryKv } from "../lib/idb";
import { gidFromScope, notificationFor, parseScope, pushScope, wishScope } from "../lib/pushscope";
import { _resetMemoryStorage, loadGroup, saveGroup } from "../lib/storage";
import { loadWishSeen, markWishSeen, wishHash, wishUpdated } from "../lib/wishseen";
import { createMockWasm } from "../mock/wasm";
import { MockServer, mockFetch } from "../mock/server";
import { computeRolesInline, contactUploadNeeded, endpointHash, ProtocolDriver, type DriverStatus } from "../protocol/driver";
import { buildJoinRequest, nameLocked, submitEntryUpdate } from "../protocol/entry";
import { decodeRoster, sealMeta } from "../protocol/roster";
import type { ParticipantKeysHandle } from "../wasm-api";

interface Player {
  name: string;
  seed: Uint8Array;
  keys: ParticipantKeysHandle;
  pidB64: string;
  driver: ProtocolDriver;
  endpoint: string;
  status: DriverStatus | null;
}

async function setup(n: number) {
  const notified: string[] = [];
  let now = Math.floor(Date.now() / 1000);
  const server = new MockServer({ onNotify: (ep) => notified.push(ep), now: () => now });
  const base = createApi(mockFetch(server));
  const uploads: string[] = []; // pid of every contact upload
  const updates: UpdateParticipantRequest[] = [];
  const api: Api = {
    ...base,
    uploadContact: async (gid, drawNo, tok, body, sig) => {
      await base.uploadContact(gid, drawNo, tok, body, sig);
      const p = players.find((x) => b64uEncode(x.keys.authToken) === b64uEncode(tok));
      uploads.push(`${p?.name}@${drawNo}`);
    },
    updateParticipant: (gid, pid, tok, req) => {
      updates.push(req);
      return base.updateParticipant(gid, pid, tok, req);
    },
  };
  const wasm = createMockWasm();
  const kv = memoryKv();
  const k = wasm.generateSecret();
  const a = wasm.generateSecret();
  const { gid: gidB64 } = await api.createGroup({
    admin_hash: b64uEncode(wasm.adminHash(a)),
    enc_meta: b64uEncode(sealMeta(wasm, k, { title: "T", budget: "", event_date: "2026-12-24", description: "" })),
    delete_after: now + 30 * 86400,
    draw_at: null,
  });
  const gid = b64uDecode(gidB64);
  const players: Player[] = [];
  const newDriver = (p: Pick<Player, "seed" | "keys" | "endpoint">) =>
    new ProtocolDriver(
      { wasm, api, kv, computeRoles: computeRolesInline(wasm) },
      { gidB64, gid, seed: p.seed, keys: p.keys, note: () => "", contactEndpoint: async () => (p as Player).endpoint },
    );
  for (let i = 0; i < n; i++) {
    const seed = wasm.generateSecret();
    const keys = wasm.deriveKeys(seed, gid);
    await api.join(gidB64, buildJoinRequest(wasm, k, gid, keys, `P${i}`, `Wunsch ${i}`));
    const p = { name: `P${i}`, seed, keys, pidB64: b64uEncode(keys.pid), endpoint: "", status: null } as unknown as Player;
    p.driver = newDriver(p);
    players.push(p);
  }
  const roster = async () => {
    const v = await api.getGroup(gidB64);
    return { v, r: decodeRoster(wasm, k, gid, v.participants) };
  };
  const stepAll = async () => {
    for (const p of players) {
      const { v, r } = await roster();
      p.status = await p.driver.step(v, r.entries, r.allValid);
    }
  };
  const runAll = async () => {
    for (let i = 0; i < 40 && !players.every((p) => p.status?.kind === "result"); i++) await stepAll();
    assert.ok(players.every((p) => p.status?.kind === "result"));
  };
  /** Player whose recipient is `p` (only for test assertions). */
  const schenkerOf = (p: Player) => players.find((x) => x.status?.kind === "result" && x.status.recipientPid === p.pidB64)!;
  const advance = (s: number) => (now += s);
  return { server, api, wasm, kv, k, a, gid, gidB64, players, uploads, updates, notified, roster, stepAll, runAll, schenkerOf, newDriver, advance };
}

test("contact: exactly one upload per participant and draw, also after a reload", async () => {
  const s = await setup(4);
  await s.api.start(s.gidB64, s.a);
  await s.runAll();
  assert.deepEqual([...s.uploads].sort(), ["P0@1", "P1@1", "P2@1", "P3@1"]);
  // Further visits (live updates) do not upload again.
  await s.stepAll();
  await s.stepAll();
  assert.equal(s.uploads.length, 4);
  // Reload: a fresh driver on the same device remembers the upload (IndexedDB).
  const p0 = s.players[0]!;
  const again = s.newDriver(p0);
  const { v, r } = await s.roster();
  assert.equal((await again.step(v, r.entries, true)).kind, "result");
  assert.equal(s.uploads.length, 4);
  assert.deepEqual(await s.kv.get(`contact:${s.gidB64}:${p0.pidB64}:1`), { drawNo: 1, endpointHash: endpointHash("") });
  // The server hands out all contacts, without pids; nobody has an endpoint yet.
  const all = await s.api.getContacts(s.gidB64, 1);
  assert.equal(all.length, 4 * 816);
  for (const p of s.players) assert.equal(await p.driver.findNotifyEndpoint(v, r.entries), null);
});

test("contact: re-upload when the endpoint changes; only the Wichtelkind can open it", async () => {
  const s = await setup(5);
  await s.api.start(s.gidB64, s.a);
  await s.runAll();
  const giver = s.players[2]!;
  const recipient = s.players.find((p) => giver.status?.kind === "result" && p.pidB64 === giver.status.recipientPid)!;
  giver.endpoint = "https://push.example/wish-abc";
  await s.stepAll();
  assert.equal(s.uploads.filter((u) => u === "P2@1").length, 2, "re-uploaded once after push was switched on");
  await s.stepAll();
  assert.equal(s.uploads.filter((u) => u === "P2@1").length, 2, "unchanged endpoint ⇒ no further upload");
  const { v, r } = await s.roster();
  assert.equal(await recipient.driver.findNotifyEndpoint(v, r.entries), "https://push.example/wish-abc");
  for (const p of s.players) if (p !== recipient) assert.equal(await p.driver.findNotifyEndpoint(v, r.entries), null, `${p.name} must not find it`);
  // Switched off again ⇒ contact with an empty endpoint.
  giver.endpoint = "";
  await s.stepAll();
  assert.equal(s.uploads.filter((u) => u === "P2@1").length, 3);
  assert.equal(await recipient.driver.findNotifyEndpoint(v, r.entries), null);
  // A new draw needs a new contact from everybody.
  await s.api.restart(s.gidB64, s.a);
  for (const p of s.players) p.status = null;
  await s.runAll();
  assert.equal(s.uploads.filter((u) => u.endsWith("@2")).length, 5);
});

test("contactUploadNeeded: once per draw, again only for another endpoint", () => {
  assert.equal(contactUploadNeeded(undefined, 1, ""), true);
  assert.equal(contactUploadNeeded({ drawNo: 1, endpointHash: endpointHash("") }, 1, ""), false);
  assert.equal(contactUploadNeeded({ drawNo: 1, endpointHash: endpointHash("") }, 1, "https://p/x"), true);
  assert.equal(contactUploadNeeded({ drawNo: 1, endpointHash: endpointHash("https://p/x") }, 1, "https://p/x"), false);
  assert.equal(contactUploadNeeded({ drawNo: 1, endpointHash: endpointHash("") }, 2, ""), true);
});

test("contact upload failure does not hide the result and is retried", async () => {
  const s = await setup(4);
  await s.api.start(s.gidB64, s.a);
  const p0 = s.players[0]!;
  const realUpload = s.api.uploadContact;
  let fail = true;
  const api: Api = {
    ...s.api,
    uploadContact: (...args) => (fail ? Promise.reject(new ApiError(404, "not_found", "old server")) : realUpload(...args)),
  };
  const d = new ProtocolDriver({ wasm: s.wasm, api, kv: s.kv, computeRoles: computeRolesInline(s.wasm) }, { gidB64: s.gidB64, gid: s.gid, seed: p0.seed, keys: p0.keys, note: () => "" });
  p0.driver = d;
  await s.runAll();
  assert.equal(p0.status?.kind, "result");
  assert.ok(!s.uploads.includes("P0@1"));
  fail = false;
  await s.stepAll();
  assert.ok(s.uploads.includes("P0@1"));
});

// ------------------------------------------------------------ changing the entry

function me(s: Awaited<ReturnType<typeof setup>>, v: GroupView, p: Player) {
  const r = decodeRoster(s.wasm, s.k, s.gid, v.participants);
  const m = r.members.find((x) => x.pidB64 === p.pidB64)!;
  return { name: m.name, wish: m.wish };
}

test("name is read-only after the start; the stored enc_name is re-used byte for byte", async () => {
  const s = await setup(4);
  const p = s.players[1]!;
  let { v } = await s.roster();
  assert.equal(nameLocked(v), false);
  // Before the start: name and wish can change.
  await submitEntryUpdate({ api: s.api, wasm: s.wasm, gk: s.k, gid: s.gid, gidB64: s.gidB64, keys: p.keys, view: v, current: me(s, v, p), next: { name: "Paula", wish: "Tee" } });
  ({ v } = await s.roster());
  assert.deepEqual(me(s, v, p), { name: "Paula", wish: "Tee" });

  await s.api.start(s.gidB64, s.a);
  ({ v } = await s.roster());
  assert.equal(nameLocked(v), true);
  const encName = v.participants.find((x) => x.pid === p.pidB64)!.enc_name;
  await assert.rejects(
    submitEntryUpdate({ api: s.api, wasm: s.wasm, gk: s.k, gid: s.gid, gidB64: s.gidB64, keys: p.keys, view: v, current: me(s, v, p), next: { name: "Paul", wish: "Tee" } }),
    /Namen kannst du nach dem Start nicht mehr ändern/,
  );
  const res = await submitEntryUpdate({ api: s.api, wasm: s.wasm, gk: s.k, gid: s.gid, gidB64: s.gidB64, keys: p.keys, view: v, current: me(s, v, p), next: { name: "Paula", wish: "Kaffee" } });
  assert.deepEqual(res, { sent: true, notified: false });
  assert.equal(s.updates.at(-1)!.enc_name, encName);
  assert.equal(s.updates.at(-1)!.notify_endpoint, undefined, "no hint while drawing");
  ({ v } = await s.roster());
  assert.equal(v.participants.find((x) => x.pid === p.pidB64)!.enc_name, encName);
  assert.deepEqual(me(s, v, p), { name: "Paula", wish: "Kaffee" });
  // A freshly sealed name (different bytes) is refused by the server after the start.
  await assert.rejects(
    s.api.updateParticipant(s.gidB64, p.pidB64, p.keys.authToken, buildJoinRequest(s.wasm, s.k, s.gid, p.keys, "Paula", "Kaffee")),
    (e: unknown) => e instanceof ApiError && e.status === 409,
  );
});

test("notify_endpoint only for a real wish change in done; lookup errors never block saving", async () => {
  const s = await setup(4);
  await s.api.start(s.gidB64, s.a);
  await s.runAll();
  const kid = s.players[0]!;
  const giver = s.schenkerOf(kid);
  giver.endpoint = "https://push.example/anon-1";
  await s.stepAll();
  let { v, r } = await s.roster();
  let lookups = 0;
  const base = { api: s.api, wasm: s.wasm, gk: s.k, gid: s.gid, gidB64: s.gidB64, keys: kid.keys };
  const find = () => {
    lookups++;
    return kid.driver.findNotifyEndpoint(v, r.entries);
  };

  // Unchanged: nothing is sent, the contacts are not even fetched.
  const same = await submitEntryUpdate({ ...base, view: v, current: me(s, v, kid), next: { name: "P0", wish: "Wunsch 0" }, findNotifyEndpoint: find });
  assert.deepEqual(same, { sent: false });
  assert.equal(lookups, 0);
  const before = s.updates.length;

  // Real change: the Schenker's anonymous endpoint goes along, the server pushes once.
  const changed = await submitEntryUpdate({ ...base, view: v, current: me(s, v, kid), next: { name: "P0", wish: "Neuer Wunsch" }, findNotifyEndpoint: find });
  assert.deepEqual(changed, { sent: true, notified: true });
  assert.equal(s.updates.length, before + 1);
  assert.equal(s.updates.at(-1)!.notify_endpoint, "https://push.example/anon-1");
  assert.deepEqual(s.notified, ["https://push.example/anon-1"]);
  ({ v, r } = await s.roster());
  assert.equal(me(s, v, kid).wish, "Neuer Wunsch");

  // Rate limit (mock server): a second hint within 10 minutes is dropped, the wish is saved.
  await submitEntryUpdate({ ...base, view: v, current: me(s, v, kid), next: { name: "P0", wish: "Noch neuer" }, findNotifyEndpoint: find });
  assert.equal(s.notified.length, 1);
  ({ v, r } = await s.roster());
  assert.equal(me(s, v, kid).wish, "Noch neuer");
  s.advance(601);

  // Contacts unavailable: saved anyway, without a hint.
  const failing = await submitEntryUpdate({
    ...base,
    view: v,
    current: me(s, v, kid),
    next: { name: "P0", wish: "Trotzdem gespeichert" },
    findNotifyEndpoint: () => Promise.reject(new Error("offline")),
  });
  assert.deepEqual(failing, { sent: true, notified: false });
  assert.equal(s.updates.at(-1)!.notify_endpoint, undefined);
  ({ v, r } = await s.roster());
  assert.equal(me(s, v, kid).wish, "Trotzdem gespeichert");

  // Schenker without push: no endpoint, no hint.
  giver.endpoint = "";
  await s.stepAll();
  ({ v, r } = await s.roster());
  const res = await submitEntryUpdate({ ...base, view: v, current: me(s, v, kid), next: { name: "P0", wish: "Ohne Push" }, findNotifyEndpoint: find });
  assert.deepEqual(res, { sent: true, notified: false });
  assert.equal(s.notified.length, 1);
});

test("forgetting the group with push on replaces the own contact by one without endpoint", async () => {
  _resetMemoryStorage();
  const s = await setup(4);
  await s.api.start(s.gidB64, s.a);
  await s.runAll();
  const kid = s.players[3]!;
  const giver = s.schenkerOf(kid);
  giver.endpoint = "https://push.example/anon-2";
  await s.stepAll();
  const { v, r } = await s.roster();
  assert.equal(await kid.driver.findNotifyEndpoint(v, r.entries), "https://push.example/anon-2");
  saveGroup(s.gidB64, { k: b64uEncode(s.k), s: b64uEncode(giver.seed), pid: giver.pidB64, push: true });
  await forgetGroupOnDevice(s.gidB64, { kv: s.kv, api: s.api, wasm: s.wasm });
  assert.equal(loadGroup(s.gidB64), null);
  assert.equal(await kid.driver.findNotifyEndpoint(v, r.entries), null);
  assert.deepEqual(await s.kv.keys(`contact:${s.gidB64}:`), [], "contact records forgotten with the group");
});

// ------------------------------------------------------------ service worker scope

test("service worker: the wish scope shows the fixed wish text, other scopes are unchanged", () => {
  const gid = b64uEncode(new Uint8Array(16).fill(9));
  assert.equal(wishScope(gid), `/g/${gid}/wish/`);
  assert.deepEqual(parseScope(`https://w.example${wishScope(gid)}`), { gid, kind: "wish" });
  assert.deepEqual(parseScope(pushScope(gid)), { gid, kind: "round" });
  assert.equal(parseScope("https://w.example/"), null);
  // gidFromScope keeps meaning "round registration" only.
  assert.equal(gidFromScope(wishScope(gid)), null);

  const wish = notificationFor(`https://w.example/g/${gid}/wish/`);
  assert.equal(`${wish.title}: ${wish.body}`, "🎁 Wichteln: Dein Wichtelkind hat seinen Wunschzettel aktualisiert");
  assert.equal(wish.tag, `wichtel-wish-${gid}`);
  const round = notificationFor(`https://w.example/g/${gid}/`);
  assert.equal(`${round.title}: ${round.body}`, "🎁 Wichteln: Es gibt Neuigkeiten in deiner Runde");
  assert.equal(round.tag, `wichtel-update-${gid}`);
  assert.equal(notificationFor("https://w.example/").tag, "wichtel-update");
  // Any scope ending in /wish/ gets the wish text – and never a name.
  assert.equal(notificationFor("https://w.example/something/wish/").body, wish.body);
  assert.ok(!/P\d|Wunsch \d/.test(wish.body));
});

// ------------------------------------------------------------ "aktualisiert"

test("wishUpdated: only a change since the last look in the same draw counts", () => {
  assert.equal(wishUpdated(undefined, 1, "Tee"), false, "first look");
  const seen = { drawNo: 1, hash: wishHash("Tee") };
  assert.equal(wishUpdated(seen, 1, "Tee"), false);
  assert.equal(wishUpdated(seen, 1, "Tee und Kekse"), true);
  assert.equal(wishUpdated(seen, 1, ""), true, "wish list removed");
  assert.equal(wishUpdated(seen, 2, "Kaffee"), false, "new draw ⇒ new recipient, nothing to compare");

  _resetMemoryStorage();
  const gid = b64uEncode(new Uint8Array(16).fill(3));
  markWishSeen(gid, 1, "Tee");
  assert.equal(loadWishSeen(gid), undefined, "nothing stored for unknown groups");
  saveGroup(gid, { k: "k" });
  markWishSeen(gid, 1, "Tee");
  assert.equal(wishUpdated(loadWishSeen(gid), 1, "Tee"), false);
  assert.equal(wishUpdated(loadWishSeen(gid), 1, "Socken"), true);
  markWishSeen(gid, 1, "Socken");
  assert.equal(wishUpdated(loadWishSeen(gid), 1, "Socken"), false, "seen after revealing");
  assert.ok(!JSON.stringify(loadGroup(gid)).includes("Socken"), "only a hash is stored");
});
