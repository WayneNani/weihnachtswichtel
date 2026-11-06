// Client hardening: local cleanup, seed-free address bar, per-group push scope, name display.
import assert from "node:assert/strict";
import { test } from "node:test";
import { createApi, type Api } from "../api/client";
import type { ParticipantView } from "../api/types";
import { forgetGroupOnDevice } from "../forget";
import { b64uDecode, b64uEncode, utf8 } from "../lib/bytes";
import { addressBarFragment, parseFragment } from "../lib/fragment";
import { memoryKv } from "../lib/idb";
import { gidFromScope, pushScope } from "../lib/pushscope";
import { _resetMemoryStorage, listGroups, loadGroup, saveExtra, saveGroup, seedPersisted } from "../lib/storage";
import { createMockWasm } from "../mock/wasm";
import { MockServer, mockFetch } from "../mock/server";
import { computeRolesInline, forgetDriverState, ProtocolDriver } from "../protocol/driver";
import { cleanName, decodeRoster, INVISIBLE_NAME, nameKey, sealMeta } from "../protocol/roster";
import { buildJoinRequest } from "../ui/join";
import { GroupController } from "../ui/controller";

const K = new Uint8Array(32).fill(1);
const A = new Uint8Array(32).fill(2);
const S = new Uint8Array(32).fill(3);

const tick = () => new Promise((r) => setTimeout(r, 0));
async function until(cond: () => boolean, what: string, tries = 500): Promise<void> {
  for (let i = 0; i < tries; i++) {
    if (cond()) return;
    await tick();
  }
  assert.ok(false, `timed out waiting for ${what}`);
}

// ------------------------------------------------------------ address bar (finding 8)

test("addressBarFragment drops the seed unless it must be kept, keeps GK and admin secret", () => {
  const f = addressBarFragment({ k: K, s: S }, false);
  const p = parseFragment(f);
  assert.ok(p.ok);
  assert.deepEqual(p.secrets.k, K);
  assert.equal(p.secrets.s, undefined);
  assert.ok(!f.includes("s="));
  const adm = parseFragment(addressBarFragment({ k: K, a: A, s: S }, false));
  assert.ok(adm.ok);
  assert.deepEqual(adm.secrets.a, A);
  assert.equal(adm.secrets.s, undefined);
  // Without persistent storage the seed stays (only way back).
  const kept = parseFragment(addressBarFragment({ k: K, s: S }, true));
  assert.ok(kept.ok);
  assert.deepEqual(kept.secrets.s, S);
});

test("seedPersisted only trusts real localStorage with matching GK and seed", () => {
  const gid = b64uEncode(new Uint8Array(16).fill(5));
  _resetMemoryStorage();
  // No localStorage (Node): the in-memory fallback does not count.
  saveGroup(gid, { k: b64uEncode(K), s: b64uEncode(S) });
  assert.equal(seedPersisted(gid, K, S), false);
  const store = new Map<string, string>();
  const fake = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
    key: (i: number) => [...store.keys()][i] ?? null,
    get length() {
      return store.size;
    },
  };
  const g = globalThis as unknown as { localStorage?: unknown };
  g.localStorage = fake;
  try {
    saveGroup(gid, { k: b64uEncode(K), s: b64uEncode(S) });
    assert.equal(seedPersisted(gid, K, S), true);
    assert.equal(seedPersisted(gid, K, A), false, "another seed");
    assert.equal(seedPersisted(gid, A, S), false, "another GK");
    // The stored record is what a bookmark of the invite link (#k=… only) relies on.
    saveGroup(gid, { s: undefined });
    assert.equal(seedPersisted(gid, K, S), false);
  } finally {
    delete g.localStorage;
    _resetMemoryStorage();
  }
});

// ------------------------------------------------------------ push scope (finding 10)

test("push scope is per group and maps back to the gid", () => {
  const gid = b64uEncode(new Uint8Array(16).fill(7));
  assert.equal(pushScope(gid), `/g/${gid}/`);
  assert.equal(gidFromScope(`https://wichteln.example/g/${gid}/`), gid);
  assert.equal(gidFromScope(pushScope(gid)), gid);
  assert.equal(gidFromScope("https://wichteln.example/"), null, "legacy root registration");
  assert.equal(gidFromScope(`https://wichteln.example/g/${gid}`), null);
  assert.notEqual(pushScope(gid), pushScope(b64uEncode(new Uint8Array(16).fill(8))));
});

// ------------------------------------------------------------ names (finding 14)

test("cleanName strips bidi and zero-width characters", () => {
  assert.equal(cleanName("‮Anna‬"), "Anna");
  assert.equal(cleanName("An​na‍ ﻿"), "Anna");
  assert.equal(cleanName("⁦Bob⁩‎‏"), "Bob");
  assert.equal(cleanName("  Jörg  "), "Jörg");
  assert.equal(cleanName("​‮"), "");
  // Ordinary text (incl. emoji with ZWJ removed) stays readable.
  assert.equal(cleanName("Zoë 🎄"), "Zoë 🎄");
});

test("nameKey: NFKC + case folding + invisible characters", () => {
  assert.equal(nameKey("ANNA"), nameKey("anna"));
  assert.equal(nameKey("Ａｎｎａ"), nameKey("anna")); // full-width
  assert.equal(nameKey("Jörg"), nameKey("Jörg")); // combining diaeresis
  assert.equal(nameKey("An​na"), nameKey("Anna"));
  assert.equal(nameKey("Anna  Lena"), nameKey("anna lena"));
  assert.notEqual(nameKey("Anna"), nameKey("Anne"));
});

test("decodeRoster cleans names and marks duplicates", () => {
  const wasm = createMockWasm();
  const gk = wasm.generateSecret();
  const gid = new Uint8Array(16).fill(4);
  const entry = (name: string, i: number): ParticipantView => {
    const keys = wasm.deriveKeys(wasm.generateSecret(), gid);
    const encName = wasm.gkSeal(gk, "name", gid, utf8(name), keys.pid, keys.ipk, keys.idh);
    const encWish = wasm.gkSeal(gk, "wish", gid, utf8(""), keys.pid, keys.ipk, keys.idh);
    return {
      pid: b64uEncode(keys.pid),
      ipk: b64uEncode(keys.ipk),
      idh: b64uEncode(keys.idh),
      enc_name: b64uEncode(encName),
      enc_wish: b64uEncode(encWish),
    };
  };
  const names = ["Anna", "‮anna", "Bernd", "​‌", "Carla"];
  const roster = decodeRoster(wasm, gk, gid, names.map(entry));
  const byName = (n: string) => roster.members.filter((m) => m.name === n);
  assert.equal(byName("Anna").length + byName("anna").length, 2);
  for (const m of [...byName("Anna"), ...byName("anna")]) assert.equal(m.duplicate, true);
  assert.equal(byName("Bernd")[0]!.duplicate, false);
  assert.equal(byName("Carla")[0]!.duplicate, false);
  // Only invisible characters: shown as such, validity (Spec §6) unchanged.
  const invisible = byName(INVISIBLE_NAME);
  assert.equal(invisible.length, 1);
  assert.equal(invisible[0]!.valid, true);
  assert.equal(invisible[0]!.duplicate, false);
  assert.ok(roster.allValid);
  for (const m of roster.members) assert.ok(!/[​-‏‪-‮⁦-⁩﻿]/.test(m.name ?? ""));
});

// ------------------------------------------------------------ local cleanup (findings 4 and 9)

test("forgetDriverState removes result:/eval:/disturb: of that group only", async () => {
  const kv = memoryKv();
  const g1 = "G1G1G1G1G1G1G1G1G1G1G1";
  const g2 = "G2G2G2G2G2G2G2G2G2G2G2";
  for (const g of [g1, g2]) {
    await kv.set(`result:${g}:P:3`, { round: 3 });
    await kv.set(`eval:${g}:P:3`, "AAAA");
    await kv.set(`disturb:${g}:P:2`, { round: 2 });
  }
  await kv.set("push-links", []);
  await forgetDriverState(kv, g1);
  for (const kind of ["result", "eval", "disturb"]) assert.deepEqual(await kv.keys(`${kind}:${g1}:`), []);
  assert.equal((await kv.keys(`result:${g2}:`)).length, 1);
  assert.equal((await kv.keys(`eval:${g2}:`)).length, 1);
  assert.equal((await kv.keys(`disturb:${g2}:`)).length, 1);
  assert.deepEqual(await kv.get("push-links"), []);
});

async function groupWithPlayers(n: number) {
  const pushes: string[] = [];
  const server = new MockServer({ onPush: (sub) => pushes.push(sub.endpoint) });
  const api: Api = createApi(mockFetch(server));
  const wasm = createMockWasm();
  const kv = memoryKv();
  const k = wasm.generateSecret();
  const a = wasm.generateSecret();
  const { gid: gidB64 } = await api.createGroup({
    admin_hash: b64uEncode(wasm.adminHash(a)),
    enc_meta: b64uEncode(sealMeta(wasm, k, { title: "T", budget: "", event_date: "2026-12-24", description: "" })),
    delete_after: Math.floor(Date.now() / 1000) + 86400,
    draw_at: null,
  });
  const gid = b64uDecode(gidB64);
  const players: { seed: Uint8Array; pidB64: string; driver: ProtocolDriver }[] = [];
  for (let i = 0; i < n; i++) {
    const seed = wasm.generateSecret();
    const keys = wasm.deriveKeys(seed, gid);
    await api.join(gidB64, buildJoinRequest(wasm, k, gid, keys, `P${i}`, ""));
    const driver = new ProtocolDriver({ wasm, api, kv, computeRoles: computeRolesInline(wasm) }, { gidB64, gid, seed, keys, note: () => `Notiz ${i}` });
    players.push({ seed, pidB64: b64uEncode(keys.pid), driver });
  }
  return { server, api, wasm, kv, k, a, gid, gidB64, players, pushes };
}

test("forgetGroupOnDevice: unsubscribes push on the server, clears storage and IndexedDB", async () => {
  _resetMemoryStorage();
  const s = await groupWithPlayers(2);
  const me = s.players[0]!;
  const keys = s.wasm.deriveKeys(me.seed, s.gid);
  await s.api.putPush(s.gidB64, me.pidB64, keys.authToken, {
    endpoint: "https://push.invalid/me",
    p256dh: b64uEncode(new Uint8Array(65).fill(4)),
    auth: b64uEncode(new Uint8Array(16).fill(5)),
  });
  // Sanity: a state change pushes to the subscription.
  const other = s.wasm.deriveKeys(s.wasm.generateSecret(), s.gid);
  await s.api.join(s.gidB64, buildJoinRequest(s.wasm, s.k, s.gid, other, "Vorher", ""));
  assert.deepEqual(s.pushes, ["https://push.invalid/me"]);
  saveGroup(s.gidB64, { k: b64uEncode(s.k), s: b64uEncode(me.seed), pid: me.pidB64, push: true, note: "geheim" });
  saveExtra(s.gidB64, "bots", [1]);
  await s.kv.set(`result:${s.gidB64}:${me.pidB64}:1`, { round: 1 });
  await s.kv.set(`eval:${s.gidB64}:${me.pidB64}:1`, "AAAA");
  await s.kv.set(`disturb:${s.gidB64}:${me.pidB64}:1`, { round: 1 });

  const calls: string[] = [];
  const api: Api = {
    ...s.api,
    deletePush: (gid, pid, tok) => {
      calls.push(`${gid}/${pid}/${b64uEncode(tok)}`);
      return s.api.deletePush(gid, pid, tok);
    },
  };
  const done = forgetGroupOnDevice(s.gidB64, { kv: s.kv, api, wasm: s.wasm });
  // The local record is gone synchronously (the home page re-reads the list right away).
  assert.equal(loadGroup(s.gidB64), null);
  assert.equal(listGroups().length, 0);
  await done;
  assert.deepEqual(calls, [`${s.gidB64}/${me.pidB64}/${b64uEncode(keys.authToken)}`]);
  for (const kind of ["result", "eval", "disturb"]) assert.deepEqual(await s.kv.keys(`${kind}:${s.gidB64}:`), []);
  // The server no longer pushes to the forgotten subscription.
  s.pushes.length = 0;
  const extra = s.wasm.deriveKeys(s.wasm.generateSecret(), s.gid);
  await s.api.join(s.gidB64, buildJoinRequest(s.wasm, s.k, s.gid, extra, "Neu", ""));
  assert.deepEqual(s.pushes, []);
});

test("forgetGroupOnDevice ignores server errors (group already deleted)", async () => {
  _resetMemoryStorage();
  const s = await groupWithPlayers(1);
  saveGroup(s.gidB64, { k: b64uEncode(s.k), s: b64uEncode(s.players[0]!.seed), push: true });
  await s.api.deleteGroup(s.gidB64, s.a);
  await forgetGroupOnDevice(s.gidB64, { kv: s.kv, api: s.api, wasm: s.wasm });
  assert.equal(loadGroup(s.gidB64), null);
});

function controllerFor(s: Awaited<ReturnType<typeof groupWithPlayers>>, seed: Uint8Array | undefined) {
  return new GroupController(
    { api: s.api, wasm: s.wasm, kv: s.kv, computeRoles: computeRolesInline(s.wasm), eventSource: null },
    s.gidB64,
    s.gid,
    { k: s.k, s: seed },
  );
}

test("controller: a deleted group (404) is forgotten on this device", async () => {
  _resetMemoryStorage();
  const s = await groupWithPlayers(1);
  const me = s.players[0]!;
  saveGroup(s.gidB64, { k: b64uEncode(s.k), s: b64uEncode(me.seed), pid: me.pidB64, note: "geheim" });
  await s.kv.set(`result:${s.gidB64}:${me.pidB64}:1`, { round: 1 });
  const ctrl = controllerFor(s, me.seed);
  await s.api.deleteGroup(s.gidB64, s.a);
  await ctrl.refresh();
  assert.equal(ctrl.snapshot.notFound, true);
  assert.equal(loadGroup(s.gidB64), null, "seed and note removed");
  for (let i = 0; i < 20 && (await s.kv.keys(`result:${s.gidB64}:`)).length > 0; i++) await tick();
  assert.deepEqual(await s.kv.keys(`result:${s.gidB64}:`), []);
  ctrl.stop();
});

test("controller: the private note is removed once the own result is there", async () => {
  _resetMemoryStorage();
  const s = await groupWithPlayers(4);
  const me = s.players[0]!;
  saveGroup(s.gidB64, { k: b64uEncode(s.k), s: b64uEncode(me.seed), pid: me.pidB64, note: "Notiz 0" });
  await s.api.start(s.gidB64, s.a);
  // Everybody else runs their drivers; this device uploads through its controller.
  const ctrl = controllerFor(s, me.seed);
  for (let visit = 0; visit < 40; visit++) {
    await ctrl.refresh();
    await until(() => ctrl.snapshot.busy === null, "driver idle");
    const v = await s.api.getGroup(s.gidB64);
    if (v.state === "drawing") {
      // The note is still needed while the draw runs (a failed attempt repeats step 2).
      assert.equal(loadGroup(s.gidB64)?.note, "Notiz 0");
      const roster = decodeRoster(s.wasm, s.k, s.gid, v.participants);
      for (const p of s.players.slice(1)) await p.driver.step(v, roster.entries, roster.allValid);
    }
    if (ctrl.snapshot.driver?.kind === "result") break;
  }
  assert.equal(ctrl.snapshot.driver?.kind, "result");
  assert.equal(loadGroup(s.gidB64)?.note, undefined, "note removed after the draw");
  assert.equal(loadGroup(s.gidB64)?.s, b64uEncode(me.seed), "seed stays");
  // The Schenker of P0 received the note.
  const v = await s.api.getGroup(s.gidB64);
  const roster = decodeRoster(s.wasm, s.k, s.gid, v.participants);
  const notes = [];
  for (const p of s.players.slice(1)) {
    const st = await p.driver.step(v, roster.entries, true);
    if (st.kind === "result" && st.recipientPid === me.pidB64) notes.push(st.note);
  }
  assert.deepEqual(notes, ["Notiz 0"]);
  ctrl.stop();
});
