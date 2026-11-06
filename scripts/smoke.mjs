#!/usr/bin/env node
// Smoke test without a browser (Node 22, standard library + the project's own build tools):
//
//   scripts/build-all.sh && node scripts/smoke.mjs
//
// 1. bundles the UI's protocol building blocks (web/src: api client, roster decoding, join request,
//    protocol driver, WASM binding) for Node with esbuild from web/node_modules,
// 2. binds the built WASM with `wasm-bindgen --target nodejs` (temp directory),
// 3. starts the wichtel-server binary with a temporary database on a free port,
// 4. checks that the web UI is served (index, app, /pkg/*.wasm as application/wasm),
// 5. runs a complete draw with 4 simulated clients over HTTP – create, join, start, roles,
//    reveal, result – and checks: everybody has exactly one recipient, nobody themselves, notes
//    arrive, re-visits answer from the cache.
//
// Environment: WICHTEL_SERVER (server binary; default $CARGO_TARGET_DIR/debug/wichtel-server),
// WICHTEL_WASM (wichtel_wasm.wasm; default cargo wasm-release output), WASM_BINDGEN,
// SMOKE_N (participants, default 4), SMOKE_KEEP=1 (keep temp dir and server log).

import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TARGET_DIR = process.env.CARGO_TARGET_DIR || path.join(ROOT, "target");
const SERVER = process.env.WICHTEL_SERVER || path.join(TARGET_DIR, "debug", "wichtel-server");
const WASM =
  process.env.WICHTEL_WASM ||
  path.join(TARGET_DIR, "wasm32-unknown-unknown", "wasm-release", "wichtel_wasm.wasm");
const BINDGEN =
  process.env.WASM_BINDGEN ||
  (() => {
    const home = path.join(os.homedir(), ".cargo", "bin", "wasm-bindgen");
    return fs.existsSync(home) ? home : "wasm-bindgen";
  })();
const N = Number(process.env.SMOKE_N || 4);
const KEEP = process.env.SMOKE_KEEP === "1";

for (const [what, p, hint] of [
  ["server binary", SERVER, "scripts/build-all.sh"],
  ["wasm", WASM, "scripts/build-wasm.sh"],
  ["web/node_modules", path.join(ROOT, "web", "node_modules", "esbuild"), "cd web && npm ci"],
]) {
  if (!fs.existsSync(p)) {
    console.error(`${what} not found: ${p}\nrun ${hint} first`);
    process.exit(1);
  }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wichtel-smoke-"));
let server = null;
let serverLog = "";
const cleanup = () => {
  if (server && server.exitCode === null) server.kill("SIGTERM");
  if (!KEEP) fs.rmSync(tmp, { recursive: true, force: true });
};
process.on("exit", cleanup);
process.on("SIGINT", () => process.exit(130));

const step = (msg) => console.log(`- ${msg}`);

// ---------------------------------------------------------------------------------------------
// 1. UI building blocks, bundled for Node
// ---------------------------------------------------------------------------------------------

const src = (p) => JSON.stringify(path.join(ROOT, "web", "src", p));
const entry = path.join(tmp, "ui-entry.ts");
fs.writeFileSync(
  entry,
  [
    `export { createApi } from ${src("api/client.ts")};`,
    `export { memoryKv } from ${src("lib/idb.ts")};`,
    `export { b64uDecode, b64uEncode } from ${src("lib/bytes.ts")};`,
    `export { computeRolesInline, ProtocolDriver } from ${src("protocol/driver.ts")};`,
    `export { decodeMeta, decodeRoster, sealMeta } from ${src("protocol/roster.ts")};`,
    `export { buildJoinRequest } from ${src("ui/join.tsx")};`,
    `export { bindWasm } from ${src("wasm.ts")};`,
  ].join("\n"),
);
const esbuild = createRequire(path.join(ROOT, "web", "package.json"))("esbuild");
await esbuild.build({
  entryPoints: [entry],
  outfile: path.join(tmp, "ui.mjs"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  jsx: "automatic",
  jsxImportSource: "preact",
  // Same switch as the real build: no mock code.
  define: { __MOCK__: "false" },
  nodePaths: [path.join(ROOT, "web", "node_modules")],
  logLevel: "warning",
});
const ui = await import(pathToFileURL(path.join(tmp, "ui.mjs")).href);
assert.ok(!fs.readFileSync(path.join(tmp, "ui.mjs"), "utf8").includes("createMockWasm"), "mock code in real bundle");
step("UI protocol modules bundled (web/src, __MOCK__ = false)");

// ---------------------------------------------------------------------------------------------
// 2. WASM (nodejs target)
// ---------------------------------------------------------------------------------------------

const pkgDir = path.join(tmp, "pkg");
execFileSync(BINDGEN, ["--target", "nodejs", "--out-dir", pkgDir, WASM], { stdio: "inherit" });
const wasm = ui.bindWasm(createRequire(import.meta.url)(path.join(pkgDir, path.basename(WASM, ".wasm") + ".js")));
step(`WASM loaded (${wasm.protocolVersion()})`);

// ---------------------------------------------------------------------------------------------
// 3. Server
// ---------------------------------------------------------------------------------------------

const port = await new Promise((resolve, reject) => {
  const s = net.createServer();
  s.once("error", reject);
  s.listen(0, "127.0.0.1", () => {
    const { port } = s.address();
    s.close(() => resolve(port));
  });
});
const base = `http://127.0.0.1:${port}`;
server = spawn(SERVER, [], {
  env: {
    ...process.env,
    WICHTEL_ADDR: `127.0.0.1:${port}`,
    WICHTEL_DB: path.join(tmp, "smoke.db"),
    WICHTEL_PUBLIC_URL: base,
    RUST_LOG: process.env.RUST_LOG || "warn",
  },
  stdio: ["ignore", "pipe", "pipe"],
});
server.stdout.on("data", (d) => (serverLog += d));
server.stderr.on("data", (d) => (serverLog += d));
server.on("exit", (code, sig) => {
  if (code !== null && code !== 0) console.error(`server exited with ${code ?? sig}\n${serverLog}`);
});

const deadline = Date.now() + 30_000;
for (;;) {
  if (server.exitCode !== null) throw new Error(`server did not start:\n${serverLog}`);
  try {
    const r = await fetch(`${base}/api/health`);
    if (r.ok) break;
  } catch {
    /* not up yet */
  }
  if (Date.now() > deadline) throw new Error(`server not healthy after 30 s:\n${serverLog}`);
  await new Promise((r) => setTimeout(r, 100));
}
step(`server up on ${base} (temp DB)`);

// ---------------------------------------------------------------------------------------------
// 4. Static assets
// ---------------------------------------------------------------------------------------------

{
  const index = await fetch(`${base}/`);
  assert.equal(index.status, 200);
  assert.match(index.headers.get("content-type") ?? "", /text\/html/);
  assert.match(index.headers.get("content-security-policy") ?? "", /wasm-unsafe-eval/);
  const html = await index.text();
  for (const asset of ["/app.js", "/worker.js", "/pkg/wichtel_wasm.js"]) {
    const r = await fetch(base + asset);
    assert.equal(r.status, 200, `${asset} (index refers to app.js: ${html.includes("app.js")})`);
    assert.match(r.headers.get("content-type") ?? "", /javascript/, asset);
    await r.arrayBuffer();
  }
  const w = await fetch(`${base}/pkg/wichtel_wasm_bg.wasm`);
  assert.equal(w.status, 200);
  assert.equal(w.headers.get("content-type"), "application/wasm");
  const bytes = new Uint8Array(await w.arrayBuffer());
  assert.equal(Buffer.from(bytes.subarray(0, 4)).toString("latin1"), "\0asm");
  assert.ok(WebAssembly.validate(bytes), "served wasm validates");
  const app = await (await fetch(`${base}/app.js`)).text();
  assert.ok(!/createMockWasm|mock-badge/.test(app), "served app.js contains mock code");
  step("web UI served (index, app.js, worker.js, /pkg/*.wasm as application/wasm, no mock code)");
}

// ---------------------------------------------------------------------------------------------
// 5. Complete draw over HTTP with simulated clients
// ---------------------------------------------------------------------------------------------

const api = ui.createApi((input, init) => fetch(input, init), base);
const k = wasm.generateSecret();
const a = wasm.generateSecret();
const meta = { title: "Smoke-Test", budget: "20 €", event_date: "2026-12-24", description: "Node" };
const { gid: gidB64 } = await api.createGroup({
  admin_hash: ui.b64uEncode(wasm.adminHash(a)),
  enc_meta: ui.b64uEncode(ui.sealMeta(wasm, k, meta)),
  delete_after: Math.floor(Date.now() / 1000) + 30 * 86400,
  draw_at: null,
});
const gid = ui.b64uDecode(gidB64);
assert.equal(gid.length, 16);
assert.deepEqual(ui.decodeMeta(wasm, k, (await api.getGroup(gidB64)).enc_meta), meta);
step(`group created (meta decrypts)`);

const names = ["Anna", "Ben", "Clara", "David", "Emil", "Frieda", "Greta", "Hannes"];
const players = [];
for (let i = 0; i < N; i++) {
  const name = names[i] ?? `P${i}`;
  const kv = ui.memoryKv(); // every client has its own device storage
  const seed = wasm.generateSecret();
  const keys = wasm.deriveKeys(seed, gid);
  const res = await api.join(gidB64, ui.buildJoinRequest(wasm, k, gid, keys, name, `Wunsch von ${name}`));
  assert.equal(res.pid, ui.b64uEncode(keys.pid));
  const driver = new ui.ProtocolDriver(
    { wasm, api, kv, computeRoles: ui.computeRolesInline(wasm) },
    { gidB64, gid, seed, keys, note: () => `Grüße von ${name}` },
  );
  players.push({ name, keys, driver, status: null });
}
{
  const v = await api.getGroup(gidB64);
  const fps = new Set(players.map(() => wasm.fingerprint(gid, ui.decodeRoster(wasm, k, gid, v.participants).entries).join(" ")));
  assert.equal(fps.size, 1);
  const roster = ui.decodeRoster(wasm, k, gid, v.participants);
  assert.ok(roster.allValid);
  assert.deepEqual(roster.members.map((m) => m.name).sort(), players.map((p) => p.name).sort());
  step(`${N} participants joined (names decrypt, fingerprint ${[...fps][0]})`);
}

await assert.rejects(api.start(gidB64, wasm.generateSecret()), "start with a wrong admin secret");
await api.start(gidB64, a);
step("draw started by admin");

const t0 = performance.now();
const seen = [];
for (let visit = 0; visit < 40; visit++) {
  for (const p of players) {
    const v = await api.getGroup(gidB64);
    const roster = ui.decodeRoster(wasm, k, gid, v.participants);
    p.status = await p.driver.step(v, roster.entries, roster.allValid);
    const tag = `${v.state}${"round" in v ? ` r${v.round}` : ""}${"phase" in v ? ` ${v.phase}` : ""}`;
    if (seen.at(-1) !== tag) seen.push(tag);
    assert.notEqual(p.status.kind, "disturbance", `${p.name}: ${JSON.stringify(p.status)}`);
  }
  if (players.every((p) => p.status?.kind === "result")) break;
}
const ms = performance.now() - t0;
step(`server states: ${seen.join(" → ")} (${ms.toFixed(0)} ms)`);

const final = await api.getGroup(gidB64);
assert.equal(final.state, "done");
assert.equal(final.draw_no, 1);
const pids = players.map((p) => ui.b64uEncode(p.keys.pid));
const recipients = players.map((p) => {
  assert.equal(p.status?.kind, "result", `${p.name}: ${JSON.stringify(p.status)}`);
  return p.status.recipientPid;
});
assert.deepEqual([...recipients].sort(), [...pids].sort(), "every participant is drawn exactly once");
players.forEach((p, i) => {
  assert.notEqual(recipients[i], pids[i], `${p.name} draws themselves`);
  const r = players[pids.indexOf(recipients[i])];
  assert.equal(p.status.note, `Grüße von ${r.name}`, "note comes from the recipient");
});
console.log(`  ${players.map((p, i) => `${p.name} → ${players[pids.indexOf(recipients[i])].name}`).join(", ")}`);
step("every participant has exactly one recipient, nobody themselves, notes arrive");

{
  const roster = ui.decodeRoster(wasm, k, gid, final.participants);
  const again = await players[0].driver.step(final, roster.entries, true);
  assert.equal(again.kind, "result");
  assert.equal(again.recipientPid, recipients[0]);
  step("re-visit answers from the local cache");
}

players.forEach((p) => p.keys.free());
server.kill("SIGTERM");
await new Promise((r) => (server.exitCode !== null ? r() : server.once("exit", r)));
console.log(`\nsmoke test passed${KEEP ? ` (temp dir kept: ${tmp})` : ""}`);
