import assert from "node:assert/strict";
import { test } from "node:test";
import { createApi, type Api } from "../api/client";
import type { GroupView } from "../api/types";
import { b64uDecode, b64uEncode } from "../lib/bytes";
import { memoryKv } from "../lib/idb";
import { createMockWasm } from "../mock/wasm";
import { MockServer, mockFetch } from "../mock/server";
import { computeRolesInline, decide, ProtocolDriver, type DriverStatus } from "../protocol/driver";
import { decodeMeta, decodeRoster, sealMeta } from "../protocol/roster";
import { buildJoinRequest } from "../ui/join";
import type { ParticipantKeysHandle, WichtelWasm } from "../wasm-api";

// ------------------------------------------------------------ pure decision

function view(partial: Partial<GroupView> & Pick<GroupView, "state">): GroupView {
  return {
    gid: "g",
    draw_no: 1,
    enc_meta: "",
    draw_at: null,
    schedule_missed: false,
    delete_after: 0,
    created_at: 0,
    participants: ["A", "B", "C", "D"].map((pid) => ({ pid, ipk: "", idh: "", enc_name: "", enc_wish: "", joined_at: 0 })),
    progress: null,
    ...partial,
  } as GroupView;
}

test("decide: open / not member / invalid roster", () => {
  assert.deepEqual(decide(view({ state: "open" }), "A", { rosterValid: true }), { kind: "nothing", status: { kind: "inactive", reason: "open" } });
  assert.deepEqual(decide(view({ state: "open" }), "Z", { rosterValid: true }).kind, "nothing");
  const v = view({ state: "drawing", round: 1, phase: "roles", progress: { round: 1, phase: "roles", submitted: [] } } as Partial<GroupView> & { state: "drawing" });
  assert.deepEqual(decide(v, "Z", { rosterValid: true }), { kind: "nothing", status: { kind: "inactive", reason: "not_member" } });
  assert.deepEqual(decide(v, "A", { rosterValid: false }), { kind: "nothing", status: { kind: "inactive", reason: "invalid_roster" } });
});

test("decide: step 1, step 2, result", () => {
  const roles = view({ state: "drawing", round: 3, phase: "roles", progress: { round: 3, phase: "roles", submitted: ["B"] } } as never);
  assert.deepEqual(decide(roles, "A", { rosterValid: true }), { kind: "roles", round: 3 });
  assert.deepEqual(decide(roles, "B", { rosterValid: true }), { kind: "nothing", status: { kind: "waiting", step: 1, round: 3 } });
  const reveal = view({ state: "drawing", round: 3, phase: "reveal", progress: { round: 3, phase: "reveal", submitted: ["A"] } } as never);
  assert.deepEqual(decide(reveal, "B", { rosterValid: true }), { kind: "reveal", round: 3 });
  assert.deepEqual(decide(reveal, "A", { rosterValid: true }), { kind: "nothing", status: { kind: "waiting", step: 2, round: 3 } });
  const done = view({ state: "done", round: 3, t_star: 5 } as never);
  assert.deepEqual(decide(done, "A", { rosterValid: true }), { kind: "result", round: 3, tStar: 5 });
  assert.deepEqual(decide(done, "A", { rosterValid: true, resultRound: 3 }).kind, "nothing");
  // a cached result of an older round does not count
  assert.deepEqual(decide(done, "A", { rosterValid: true, resultRound: 2 }).kind, "result");
  // disturbance of this round blocks further steps
  assert.deepEqual(decide(roles, "A", { rosterValid: true, disturbedRound: 3 }).kind, "nothing");
});

test("decide: progress of another phase is ignored", () => {
  const v = view({ state: "drawing", round: 4, phase: "roles", progress: { round: 3, phase: "reveal", submitted: ["A"] } } as never);
  assert.deepEqual(decide(v, "A", { rosterValid: true }), { kind: "roles", round: 4 });
});

// ------------------------------------------------------------ end-to-end against the mock server

interface Player {
  name: string;
  keys: ParticipantKeysHandle;
  driver: ProtocolDriver;
  status: DriverStatus | null;
}

async function setup(opts: { n: number; random?: () => number; collisionRate?: number; wasm?: WichtelWasm; now?: () => number }) {
  const server = new MockServer({ collisionRate: opts.collisionRate ?? 0, random: opts.random, now: opts.now });
  const api: Api = createApi(mockFetch(server));
  const wasm = opts.wasm ?? createMockWasm();
  const kv = memoryKv();
  const k = wasm.generateSecret();
  const a = wasm.generateSecret();
  const now = Math.floor(Date.now() / 1000);
  const meta = { title: "Test", budget: "20 €", event_date: "2026-12-24", description: "" };
  const { gid: gidB64 } = await api.createGroup({
    admin_hash: b64uEncode(wasm.adminHash(a)),
    enc_meta: b64uEncode(sealMeta(wasm, k, meta)),
    delete_after: now + 30 * 86400,
    draw_at: null,
  });
  const g = await api.getGroup(gidB64);
  assert.deepEqual(decodeMeta(wasm, k, g.enc_meta), meta);
  const gid = b64uDecode(gidB64);
  assert.equal(gid.length, 16);
  const players: Player[] = [];
  const addPlayer = async (name: string) => {
    const seed = wasm.generateSecret();
    const keys = wasm.deriveKeys(seed, gid);
    const res = await api.join(gidB64, buildJoinRequest(wasm, k, gid, keys, name, `Wunsch von ${name}`));
    assert.equal(res.pid, b64uEncode(keys.pid));
    const driver = new ProtocolDriver(
      { wasm, api, kv, computeRoles: computeRolesInline(wasm) },
      { gidB64, gid, seed, keys, note: () => `Notiz von ${name}` },
    );
    players.push({ name, keys, driver, status: null });
  };
  for (let i = 0; i < opts.n; i++) await addPlayer(`P${i}`);

  /** Runs all drivers (like repeated visits) until every player has a result or `maxVisits` is hit. */
  const runAll = async (maxVisits = 40) => {
    for (let visit = 0; visit < maxVisits; visit++) {
      for (const p of players) {
        const v = await api.getGroup(gidB64);
        const roster = decodeRoster(wasm, k, gid, v.participants);
        p.status = await p.driver.step(v, roster.entries, roster.allValid);
      }
      if (players.every((p) => p.status?.kind === "result" || p.status?.kind === "disturbance")) return;
    }
  };
  return { server, api, wasm, kv, k, a, gid, gidB64, players, addPlayer, runAll };
}

function checkDerangement(players: Player[]) {
  const pids = players.map((p) => b64uEncode(p.keys.pid));
  const recipients = players.map((p) => {
    assert.equal(p.status?.kind, "result", `${p.name}: ${JSON.stringify(p.status)}`);
    return (p.status as Extract<DriverStatus, { kind: "result" }>).recipientPid;
  });
  assert.deepEqual([...recipients].sort(), [...pids].sort(), "every participant is drawn exactly once");
  players.forEach((p, i) => assert.notEqual(recipients[i], pids[i], `${p.name} draws themselves`));
  // The note comes from the recipient.
  players.forEach((p, i) => {
    const r = players[pids.indexOf(recipients[i]!)]!;
    assert.equal((p.status as Extract<DriverStatus, { kind: "result" }>).note, `Notiz von ${r.name}`);
  });
}

test("full draw with 6 participants: everyone gets exactly one recipient, nobody themselves", async () => {
  const s = await setup({ n: 6 });
  await s.api.start(s.gidB64, s.a);
  await s.runAll();
  const v = await s.api.getGroup(s.gidB64);
  assert.equal(v.state, "done");
  assert.equal(v.draw_no, 1);
  checkDerangement(s.players);
  // Revisiting returns the cached result without network uploads.
  const roster = decodeRoster(s.wasm, s.k, s.gid, v.participants);
  const again = await s.players[0]!.driver.step(v, roster.entries, true);
  assert.equal(again.kind, "result");
});

test("start requires admin and at least 4 participants", async () => {
  const s = await setup({ n: 3 });
  await assert.rejects(s.api.start(s.gidB64, s.wasm.generateSecret()));
  await assert.rejects(s.api.start(s.gidB64, s.a));
  await s.addPlayer("P3");
  await s.api.start(s.gidB64, s.a);
  assert.equal((await s.api.getGroup(s.gidB64)).state, "drawing");
});

test("collision round: server advances to r+1 without a new draw number", async () => {
  const seq = [0, 1, 1, 1, 1, 1, 1];
  const s = await setup({ n: 4, collisionRate: 0.5, random: () => seq.shift() ?? 1 });
  await s.api.start(s.gidB64, s.a);
  await s.runAll();
  const v = await s.api.getGroup(s.gidB64);
  assert.equal(v.state, "done");
  assert.ok("round" in v && v.round >= 2, "at least one extra round");
  assert.equal(v.draw_no, 1);
  checkDerangement(s.players);
});

test("restart by admin gives a new draw (Verlosung Nr. 2) with fresh results", async () => {
  const s = await setup({ n: 5 });
  await s.api.start(s.gidB64, s.a);
  await s.runAll();
  const first = await s.api.getGroup(s.gidB64);
  await s.api.restart(s.gidB64, s.a);
  const v = await s.api.getGroup(s.gidB64);
  assert.equal(v.state, "drawing");
  assert.equal(v.draw_no, 2);
  assert.ok("round" in v && "round" in first && v.round > first.round);
  await s.runAll();
  checkDerangement(s.players);
});

test("leaving after the draw triggers a new draw for the rest", async () => {
  const s = await setup({ n: 5 });
  await s.api.start(s.gidB64, s.a);
  await s.runAll();
  const leaver = s.players.pop()!;
  await s.api.removeParticipant(s.gidB64, b64uEncode(leaver.keys.pid), leaver.keys.authToken);
  const v = await s.api.getGroup(s.gidB64);
  assert.equal(v.state, "drawing");
  assert.equal(v.draw_no, 2);
  assert.equal(v.participants.length, 4);
  await s.runAll();
  checkDerangement(s.players);
});

test("duplicate upload with a stale view is answered with retry, not a crash", async () => {
  const s = await setup({ n: 4 });
  await s.api.start(s.gidB64, s.a);
  const v = await s.api.getGroup(s.gidB64);
  const roster = decodeRoster(s.wasm, s.k, s.gid, v.participants);
  const p = s.players[0]!;
  assert.deepEqual(await p.driver.step(v, roster.entries, true), { kind: "uploaded", step: 1, round: 1 });
  const again = await p.driver.step(v, roster.entries, true);
  assert.equal(again.kind, "retry");
});

test("disturbance when the result cannot be opened is remembered for the round", async () => {
  let disturb = false;
  const wasm = createMockWasm({ disturb: () => disturb });
  const s = await setup({ n: 4, wasm });
  await s.api.start(s.gidB64, s.a);
  // Everybody does steps 1 and 2.
  for (let i = 0; i < 3; i++) {
    for (const p of s.players) {
      const v = await s.api.getGroup(s.gidB64);
      const roster = decodeRoster(wasm, s.k, s.gid, v.participants);
      if (v.state !== "done") p.status = await p.driver.step(v, roster.entries, true);
    }
  }
  const v = await s.api.getGroup(s.gidB64);
  assert.equal(v.state, "done");
  disturb = true;
  const roster = decodeRoster(wasm, s.k, s.gid, v.participants);
  const st = await s.players[0]!.driver.step(v, roster.entries, true);
  assert.deepEqual(st, { kind: "disturbance", round: (v as { round: number }).round, reason: "open_failed" });
  disturb = false;
  const st2 = await s.players[0]!.driver.step(v, roster.entries, true);
  assert.equal(st2.kind, "disturbance", "stays disturbed until the admin restarts");
});

test("schedule: draw starts at draw_at, or is marked missed with too few participants", async () => {
  let now = Math.floor(Date.now() / 1000);
  const s = await setup({ n: 3, now: () => now });
  await s.api.setSchedule(s.gidB64, s.a, now + 600);
  now += 601;
  s.server.tick();
  let v = await s.api.getGroup(s.gidB64);
  assert.equal(v.state, "open");
  assert.equal(v.schedule_missed, true);
  assert.equal(v.draw_at, null);
  await s.addPlayer("P3");
  await s.api.setSchedule(s.gidB64, s.a, now + 60);
  v = await s.api.getGroup(s.gidB64);
  assert.equal(v.schedule_missed, false);
  now += 61;
  s.server.tick();
  v = await s.api.getGroup(s.gidB64);
  assert.equal(v.state, "drawing");
});

test("join after start is rejected; invalid name entries block participation", async () => {
  const s = await setup({ n: 4 });
  // A participant whose name was sealed with a different GK (e.g. injected by a server).
  const evilSeed = s.wasm.generateSecret();
  const keys = s.wasm.deriveKeys(evilSeed, s.gid);
  await s.api.join(s.gidB64, buildJoinRequest(s.wasm, s.wasm.generateSecret(), s.gid, keys, "Eve", ""));
  const v = await s.api.getGroup(s.gidB64);
  const roster = decodeRoster(s.wasm, s.k, s.gid, v.participants);
  assert.equal(roster.allValid, false);
  assert.equal(roster.members.filter((m) => !m.valid).length, 1);
  await s.api.start(s.gidB64, s.a);
  const v2 = await s.api.getGroup(s.gidB64);
  const st = await s.players[0]!.driver.step(v2, roster.entries, roster.allValid);
  assert.deepEqual(st, { kind: "inactive", reason: "invalid_roster" });
  await assert.rejects(s.api.join(s.gidB64, buildJoinRequest(s.wasm, s.k, s.gid, s.wasm.deriveKeys(s.wasm.generateSecret(), s.gid), "Late", "")));
});
