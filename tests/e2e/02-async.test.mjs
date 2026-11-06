// Szenario 2: Asynchron-Modus mit 5 Teilnehmern. Zwischen den Schritten werden alle Geräte
// geschlossen; jeder Besuch ist ein neuer, leerer Browser-Kontext (= neues Gerät), der nur den
// persönlichen Link kennt. Die Fortschrittsanzeige muss zum Serverzustand passen.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import {
  adminStart,
  assertDerangement,
  createGroup,
  Device,
  join,
  launchBrowser,
  readResult,
  sleep,
  startServer,
  waitForRoster,
  withScreenshots,
} from "./lib/harness.mjs";

let server;
let browser;

before(async () => {
  server = await startServer();
  browser = await launchBrowser();
});

after(async () => {
  for (const d of [...Device.all]) await d.close().catch(() => undefined);
  await browser?.close();
  await server?.stop();
});

const NAMES = ["Agathe Async", "Bruno Briefkasten", "Carla Cello", "Dieter Dachs", "Elfriede Eule"];

/** Expected progress texts for a `drawing` view, given pid → name. */
function expectedProgress(view, nameOf) {
  const submitted = new Set(view.progress?.submitted ?? []);
  const n = view.participants.length;
  const done = view.participants.filter((p) => submitted.has(p.pid)).length;
  const missing = view.participants.filter((p) => !submitted.has(p.pid)).map((p) => nameOf[p.pid]);
  return { step: view.phase === "roles" ? 1 : 2, done, n, missing };
}

/** Polls until the page's progress card shows exactly what the server says. */
async function assertProgressMatches(dev, nameOf, { timeout = 15_000 } = {}) {
  const deadline = Date.now() + timeout;
  let last = "";
  for (;;) {
    const view = await server.getGroup(dev.gid);
    if (view.state !== "drawing") return view;
    const exp = expectedProgress(view, nameOf);
    const card = dev.page.locator("section.status-card");
    if (await card.count()) {
      const text = await card.innerText();
      const okCount = text.includes(`Schritt ${exp.step} von 2: ${exp.done} von ${exp.n} haben ihren Teil erledigt.`);
      const missingText = (await card.locator(".missing").count()) ? await card.locator(".missing").innerText() : "";
      const shown = missingText.replace(/^Es fehlen noch:\s*/, "").split(", ").filter(Boolean);
      const okMissing = [...shown].sort().join("|") === [...exp.missing].sort().join("|");
      const progress = await card.locator("progress").getAttribute("value");
      if (okCount && okMissing && Number(progress) === exp.done) return view;
      last = `UI: ${text.split("\n").slice(0, 6).join(" / ")} | expected step ${exp.step}, ${exp.done}/${exp.n}, missing ${exp.missing.join(", ")}`;
    } else last = "no progress card";
    if (Date.now() > deadline) assert.fail(`progress does not match the server: ${last}`);
    await sleep(250);
  }
}

test("Szenario 2: Asynchron-Modus mit 5 Teilnehmern über persönliche Links", async () => {
  await withScreenshots("async", async () => {
    // --- joining: every device is closed right afterwards
    const adminDev = await Device.open(browser, "admin-create");
    const group = await createGroup(adminDev, server.base, { title: "Asynchrone Runde" });
    const people = [];
    {
      const r = await join(adminDev, { name: NAMES[0], wish: "Kerzen" });
      people.push({ name: NAMES[0], ...r });
      await adminDev.close();
    }
    for (const name of NAMES.slice(1)) {
      const dev = await Device.open(browser, `join-${name.split(" ")[0]}`);
      await dev.goto(group.invite);
      const r = await join(dev, { name });
      people.push({ name, ...r });
      await dev.close();
    }
    const nameOf = Object.fromEntries(people.map((p) => [p.pid, p.name]));

    // --- Spielleiter starts from a new device that only knows the admin link (not a member there)
    {
      const dev = await Device.open(browser, "admin-start");
      await dev.goto(group.admin);
      await waitForRoster(dev, 5);
      await adminStart(dev);
      await dev.page.locator("section.status-card").waitFor();
      dev.gid = group.gid;
      const view = await assertProgressMatches(dev, nameOf);
      assert.equal(view.state, "drawing");
      assert.equal(view.progress.submitted.length, 0, "nobody has a page open ⇒ nothing submitted");
      const missing = await dev.page.locator(".missing").innerText();
      for (const n of NAMES) assert.ok(missing.includes(n), `${n} listed as missing`);
      // The admin device is not a member: no own step, no result.
      assert.equal(await dev.page.getByText("Dein Browser erledigt deinen Schritt automatisch.").count(), 0);
      await dev.close();
    }

    // --- visits: round robin over everybody whose step is still open; one fresh device per visit
    let visits = 0;
    const stepsSeen = [];
    for (let guard = 0; guard < 40; guard++) {
      const view = await server.getGroup(group.gid);
      if (view.state === "done") break;
      assert.equal(view.state, "drawing", JSON.stringify(view));
      const tag = `r${view.round} ${view.phase}`;
      if (stepsSeen.at(-1) !== tag) stepsSeen.push(tag);
      const submitted = new Set(view.progress.submitted);
      const next = people.find((p) => !submitted.has(p.pid));
      assert.ok(next, "someone must still be missing");

      const dev = await Device.open(browser, `visit-${++visits}-${next.name.split(" ")[0]}`);
      dev.gid = group.gid;
      await dev.goto(next.link);
      await dev.page.getByRole("heading", { name: "Asynchrone Runde" }).waitFor();
      // Wait until this visit has done its part (or everything is finished).
      const deadline = Date.now() + 60_000;
      for (;;) {
        const v = await server.getGroup(group.gid);
        // Submitted in the current phase (the last visitor of step 1 also does step 2 right away).
        if (v.state === "done" || v.progress.submitted.includes(next.pid)) break;
        if (Date.now() > deadline) assert.fail(`visit of ${next.name} did not submit (${JSON.stringify(v.progress)})`);
        await sleep(200);
      }
      const after = await server.getGroup(group.gid);
      if (after.state === "drawing") {
        await dev.page.getByText("✓ Dein Teil ist erledigt.").waitFor();
        await assertProgressMatches(dev, nameOf);
      } else {
        // The last upload of step 2 finishes the draw: this visitor sees the result right away.
        await dev.page.locator("section.result-card").waitFor({ timeout: 30_000 });
      }
      await dev.close();
    }
    const final = await server.getGroup(group.gid);
    assert.equal(final.state, "done", `draw finished after ${visits} visits`);
    console.log(`# ${visits} visits, phases: ${stepsSeen.join(" → ")}`);
    // 2 phases × 5 people, minus the visits that did two steps in one go (last of step 1).
    assert.ok(visits >= 9, `visits: ${visits}`);

    // --- results: everybody opens the personal link on yet another new device
    const results = {};
    for (const p of people) {
      const dev = await Device.open(browser, `result-${p.name.split(" ")[0]}`);
      await dev.goto(p.link);
      const r = await readResult(dev);
      results[p.name] = r.name;
      assert.equal(await dev.page.locator(".result-name").count(), 1);
      await dev.close();
    }
    assertDerangement(results);
    console.log(`# ${Object.entries(results).map(([g, r]) => `${g.split(" ")[0]} → ${r.split(" ")[0]}`).join(", ")}`);
  }, server);
});
