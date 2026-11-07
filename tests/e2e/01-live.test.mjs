// Szenario 1 (Live-Modus, n = 4) und Szenario 5 (Datensparsamkeit) im echten Browser.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import {
  adminStart,
  assertDerangement,
  bodyText,
  createGroup,
  Device,
  fingerprint,
  join,
  launchBrowser,
  readResult,
  setNote,
  startServer,
  waitForRoster,
  withScreenshots,
} from "./lib/harness.mjs";

let server;
let browser;
const devices = [];
const secrets = {}; // label → base64url secret that must never leave the browser
const plaintexts = []; // strings that must never reach the server in clear
let gid;
const results = {};

const TITLE = "Zebrastreifen-Wichteln Quokka";
const BUDGET = "37 Taler";
const DESCRIPTION = "Bescherung im Kaminzimmer Xylophon";
const EVENT_DATE = "2026-12-24";
const PEOPLE = [
  { label: "admin", name: "Annegret Spielleitung", wish: "Wunsch Bergkristall", note: "Notiz Lindenallee 17" },
  { label: "p2", name: "Bertold Kranich", wish: "Wunsch Origami-Papier", note: "Notiz Konfektionsgröße 52" },
  { label: "p3", name: "Cordula Zitronenfalter", wish: "Wunsch Earl-Grey-Tee", note: "Notiz Packstation 4711" },
  { label: "p4", name: "Detlef Wombat", wish: "Wunsch Kletterseil", note: "Notiz Hinterhof links" },
];

before(async () => {
  server = await startServer();
  browser = await launchBrowser();
});

after(async () => {
  for (const d of devices) await d.close().catch(() => undefined);
  await browser?.close();
  await server?.stop();
});

test("Szenario 1: Live-Modus mit 4 Teilnehmern", async () => {
  await withScreenshots("live", async () => {
    const admin = await Device.open(browser, "admin");
    devices.push(admin);
    const group = await createGroup(admin, server.base, { title: TITLE, budget: BUDGET, eventDate: EVENT_DATE, description: DESCRIPTION });
    gid = group.gid;
    secrets.k = group.k;
    secrets.a = group.a;
    plaintexts.push(TITLE, BUDGET, DESCRIPTION, EVENT_DATE);

    // Everybody joins (the Spielleiter on the admin link, the others on the invite link).
    const joined = {};
    for (const [i, p] of PEOPLE.entries()) {
      const dev = i === 0 ? admin : await Device.open(browser, p.label);
      if (i > 0) {
        devices.push(dev);
        await dev.goto(group.invite);
        await dev.page.getByRole("heading", { name: TITLE }).waitFor();
      }
      const res = await join(dev, { name: p.name, wish: p.wish });
      joined[p.label] = res;
      secrets[`s:${p.label}`] = res.seed;
      plaintexts.push(p.name, p.wish, p.note);
      // The address bar never shows the seed: invite-link visitors keep the invite link (a bookmark
      // of it works on this device with the stored seed); the personal link is only in the dialog.
      if (i > 0) assert.equal(new URL(dev.page.url()).hash, new URL(group.invite).hash);
      else assert.equal(new URL(dev.page.url()).hash, new URL(group.admin).hash);
      await setNote(dev, p.note);
    }

    // Live roster: everybody sees all four names without reloading.
    for (const d of devices) {
      await waitForRoster(d, 4);
      const text = await d.page.locator(".roster").innerText();
      for (const p of PEOPLE) assert.ok(text.includes(p.name), `${d.label} sees ${p.name}`);
    }

    // Notification bell in the top bar: visible for members, with an attention label until it was
    // opened once; opens a dialog, Escape closes it again.
    for (const d of devices) assert.equal(await d.page.locator(".topbar [data-testid=push-bell]").count(), 1, `${d.label}: bell in top bar`);
    const bell = admin.page.getByTestId("push-bell");
    assert.match(await bell.innerText(), /Benachrichtigen\?/);
    await bell.click();
    const bellDialog = admin.page.getByRole("dialog", { name: "Benachrichtigungen" });
    await bellDialog.getByRole("button", { name: /Ja, benachrichtigen/ }).waitFor();
    await admin.page.keyboard.press("Escape");
    await bellDialog.waitFor({ state: "detached" });
    assert.equal((await bell.innerText()).includes("Benachrichtigen?"), false, "label gone after first open");

    // Same fingerprint (8 words) everywhere.
    const fps = await Promise.all(devices.map((d) => fingerprint(d)));
    assert.equal(new Set(fps).size, 1, `fingerprints differ: ${fps.join(" | ")}`);
    assert.equal(fps[0].split(" ").length, 8);

    // Only the Spielleiter sees the admin panel.
    assert.equal(await admin.page.getByRole("heading", { name: /Spielleitung/ }).count(), 1);
    for (const d of devices.slice(1)) assert.equal(await d.page.getByRole("heading", { name: /Spielleitung/ }).count(), 0);

    const urls = devices.map((d) => d.page.url());
    await adminStart(admin);

    // Results arrive on every page without reload.
    const read = await Promise.all(devices.map((d) => readResult(d)));
    devices.forEach((d, i) => assert.equal(d.page.url(), urls[i], `${d.label} did not navigate/reload`));
    PEOPLE.forEach((p, i) => (results[p.name] = read[i].name));
    assertDerangement(results);

    // Each sees exactly one name; the private note shown is the one of their recipient.
    for (const [i, d] of devices.entries()) {
      const recipient = PEOPLE.find((p) => p.name === read[i].name);
      assert.equal(read[i].note, recipient.note, `${d.label} gets the note of ${recipient.name}`);
      const text = await bodyText(d);
      assert.equal(text.split("Du beschenkst").length - 1, 1, `${d.label}: exactly one result line`);
      assert.equal(await d.page.locator(".result-name").count(), 1);
      // Nobody sees anyone else's assignment or another person's private note.
      for (const p of PEOPLE) if (p !== recipient) assert.ok(!text.includes(p.note), `${d.label} must not see the note of ${p.name}`);
      for (const [giver, rec] of Object.entries(results)) {
        if (giver === PEOPLE[i].name) continue;
        assert.ok(!text.includes(`${giver} → ${rec}`) && !text.includes(`${giver} beschenkt`), `${d.label} sees assignment of ${giver}`);
      }
    }

    const view = await server.getGroup(gid);
    assert.equal(view.state, "done");
    assert.equal(view.draw_no, 1);
    console.log(`# ${Object.entries(results).map(([g, r]) => `${g.split(" ")[0]} → ${r.split(" ")[0]}`).join(", ")}`);

    // Re-opening the personal link on a NEW device shows the same result.
    const fresh = await Device.open(browser, "p2-new-device");
    devices.push(fresh);
    await fresh.goto(joined.p2.link);
    const again = await readResult(fresh);
    assert.equal(again.name, results[PEOPLE[1].name], "personal link reproduces the result on another device");
    // The seed was taken over into local storage and dropped from the address bar …
    assert.equal(new URL(fresh.page.url()).hash, new URL(group.invite).hash, "seed removed from the address bar");
    // … and reloading that (invite) URL – like a bookmark – still shows the own result.
    await fresh.page.reload();
    const reloaded = await readResult(fresh);
    assert.equal(reloaded.name, results[PEOPLE[1].name], "invite URL + stored seed shows the result after reload");
    // The note stays on the original device; the result itself is reproducible.
  }, server);
});

test("Szenario 5: Datensparsamkeit (DB roh, Requests, fremde Hosts)", async () => {
  assert.ok(gid, "scenario 1 ran");
  await withScreenshots("privacy", async () => {
    // Wait for in-flight header lookups, then check every recorded request.
    await Promise.race([Promise.all(devices.flatMap((d) => d.requests.map((r) => r.allHeaders))), new Promise((r) => setTimeout(r, 3000))]);
    const origin = new URL(server.base).origin;
    const needles = [];
    for (const [label, b64] of Object.entries(secrets)) {
      needles.push({ label, text: b64, bytes: Buffer.from(b64, "base64url") });
    }
    let count = 0;
    const foreign = new Set();
    for (const d of devices) {
      for (const r of d.requests) {
        count++;
        if (r.url.startsWith("data:") || r.url.startsWith("blob:")) continue;
        const u = new URL(r.url);
        if (u.origin !== origin) foreign.add(u.origin);
        assert.equal(u.hash, "", `fragment sent in URL: ${r.url}`);
        for (const n of needles) {
          // The admin secret AS is the Bearer token of admin endpoints by design (docs/api.md:
          // the server compares its hash) – but only there, never in URL, other headers or body.
          const headers = Object.entries(r.headers ?? {}).filter(([k]) => !(n.label === "a" && k.toLowerCase() === "authorization"));
          const headerText = headers.map(([k, v]) => `${k}: ${v}`).join("\n");
          assert.ok(!r.url.includes(n.text), `secret ${n.label} in URL ${r.url}`);
          assert.ok(!headerText.includes(n.text), `secret ${n.label} in headers of ${r.method} ${r.url}`);
          if (r.body) {
            assert.ok(!r.body.includes(n.bytes), `secret ${n.label} (raw) in body of ${r.method} ${r.url}`);
            assert.ok(!r.body.toString("latin1").includes(n.text), `secret ${n.label} in body of ${r.method} ${r.url}`);
          }
        }
        const referer = r.headers?.referer;
        if (referer) assert.ok(!referer.includes("#"), `Referer with fragment: ${referer}`);
        for (const p of plaintexts) {
          if (r.body) assert.ok(!r.body.includes(Buffer.from(p, "utf8")), `plaintext "${p}" in body of ${r.method} ${r.url}`);
          assert.ok(!decodeURIComponent(r.url).includes(p), `plaintext "${p}" in URL ${r.url}`);
        }
      }
    }
    assert.deepEqual([...foreign], [], "requests to foreign hosts");
    assert.ok(count > 20, `requests recorded: ${count}`);

    // Raw database files (DB, WAL, anything else the store writes into the temp directory).
    const files = fs.readdirSync(server.dir).filter((f) => !f.endsWith(".log"));
    assert.ok(files.some((f) => f.startsWith("e2e.db")), `db files: ${files}`);
    // Positive control: the search does find what the server legitimately stores (the raw gid).
    const gidBytes = Buffer.from(gid, "base64url");
    assert.ok(files.some((f) => fs.readFileSync(path.join(server.dir, f)).includes(gidBytes)), "gid found in the DB files");
    let bytes = 0;
    for (const f of files) {
      const buf = fs.readFileSync(path.join(server.dir, f));
      bytes += buf.length;
      for (const p of plaintexts) {
        for (const enc of ["utf8", "utf16le"]) {
          assert.ok(!buf.includes(Buffer.from(p, enc)), `"${p}" (${enc}) in clear in ${f}`);
        }
        // Single first names too (partial leaks).
        const first = p.split(" ")[0];
        if (first.length >= 6) assert.ok(!buf.includes(Buffer.from(first, "utf8")), `"${first}" in clear in ${f}`);
      }
      for (const n of needles) assert.ok(!buf.includes(n.bytes) && !buf.includes(Buffer.from(n.text)), `secret ${n.label} in ${f}`);
    }
    console.log(`# ${count} requests checked, ${files.length} DB files (${bytes} B) searched`);
  }, server);
});
