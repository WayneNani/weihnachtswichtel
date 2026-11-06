// Szenario 4: Austritt nach dem Ergebnis ⇒ Warnung ⇒ Neuverlosung für alle, Rundenzähler.
// 6 Teilnehmer: Verlosung 1 (6) → jemand tritt selbst aus → Verlosung 2 (5) → der Spielleiter
// entfernt jemanden → Verlosung 3 (4). Alle Verbliebenen sehen jeweils ihr neues Ergebnis ohne
// Neuladen.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import {
  adminStart,
  assertDerangement,
  bodyText,
  createGroup,
  Device,
  join,
  launchBrowser,
  readResult,
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

const NAMES = ["Leonie Leitung", "Malte Mandel", "Nora Nuss", "Oskar Orange", "Paula Pflaume", "Quentin Quitte"];

async function allResults(people, drawNo) {
  const read = await Promise.all(people.map((p) => readResult(p.dev, { drawNo })));
  const results = {};
  people.forEach((p, i) => (results[p.name] = read[i].name));
  assertDerangement(results);
  for (const [i, p] of people.entries()) {
    if (drawNo > 1) assert.ok(read[i].cardText.includes("Ergebnisse früherer Verlosungen gelten nicht mehr"), `${p.name}: hint about the new draw`);
    assert.equal(await p.dev.page.locator(".result-name").count(), 1);
  }
  return results;
}

test("Szenario 4: Austritt nach dem Ergebnis führt zur Neuverlosung", async () => {
  await withScreenshots("leave", async () => {
    const admin = await Device.open(browser, "admin");
    const group = await createGroup(admin, server.base, { title: "Austritts-Runde" });
    const people = [];
    await join(admin, { name: NAMES[0] });
    people.push({ name: NAMES[0], dev: admin });
    for (const name of NAMES.slice(1)) {
      const dev = await Device.open(browser, name.split(" ")[0]);
      await dev.goto(group.invite);
      await join(dev, { name });
      people.push({ name, dev });
    }
    for (const p of people) await waitForRoster(p.dev, 6);
    const urls = people.map((p) => p.dev.page.url());

    // --- Verlosung 1
    await adminStart(admin);
    const r1 = await allResults(people, 1);
    assert.equal((await server.getGroup(group.gid)).draw_no, 1);

    // --- Quentin leaves on his own after seeing the result: warning first.
    const quentin = people.pop();
    const q = quentin.dev.page;
    const leaveCard = q.locator("section", { has: q.getByRole("heading", { name: "Aussteigen" }) });
    await leaveCard.getByText("Wenn du jetzt austrittst, wird für alle anderen neu ausgelost.").waitFor();
    await leaveCard.getByRole("button", { name: "Austreten" }).click();
    const warning = leaveCard.locator(".confirm-box");
    await warning.getByText("Alle bekommen eine neue Person zugelost").waitFor();
    assert.ok((await warning.innerText()).includes("Verlosung Nr. 2"), "warning names the next draw number");
    await warning.getByRole("button", { name: "Ja, austreten" }).click();
    await q.locator("section.result-card").waitFor({ state: "detached" });
    assert.ok(!(await bodyText(quentin.dev)).includes("Du beschenkst"), "the leaver no longer sees a result");
    // The leaver is told that they left – not asked to open their personal link.
    await q.getByText("Du bist ausgetreten").waitFor();
    assert.equal(await q.getByText("öffne bitte deinen").count(), 0, "no request to open the personal link");
    await quentin.dev.close();

    // --- Verlosung 2 runs live for the remaining five; the draw counter is visible.
    const r2 = await allResults(people, 2);
    let view = await server.getGroup(group.gid);
    assert.equal(view.state, "done");
    assert.equal(view.draw_no, 2);
    assert.equal(view.participants.length, 5);
    assert.ok(!Object.values(r2).includes(quentin.name));

    // --- The Spielleiter removes Paula: the browser confirm warns about the new draw.
    const paula = people.pop();
    let dialogText = "";
    admin.page.once("dialog", (d) => {
      dialogText = d.message();
      void d.accept();
    });
    await admin.page.getByRole("button", { name: `${paula.name} entfernen` }).click();
    const r3 = await allResults(people, 3);
    assert.match(dialogText, /Alle bekommen dann eine neue Person zugelost \(Verlosung Nr\. 3\)/);
    view = await server.getGroup(group.gid);
    assert.equal(view.draw_no, 3);
    assert.equal(view.participants.length, 4);
    // Paula's page: no result any more, she is told she is no longer part of the draw.
    await paula.dev.page.getByText("Du bist nicht mehr dabei").waitFor();
    assert.ok(!(await bodyText(paula.dev)).includes("Du beschenkst"));
    await paula.dev.close();

    // Nobody reloaded during all three draws.
    people.forEach((p, i) => assert.equal(p.dev.page.url(), urls[i], `${p.name} did not navigate`));
    // Finally the Spielleiter deletes the group: open pages learn it right away (SSE stream ends).
    const adminPanel = admin.page.locator("section.admin");
    await adminPanel.getByRole("button", { name: "Runde endgültig löschen" }).click();
    await adminPanel.getByRole("button", { name: "Ja, alles löschen" }).click();
    for (const p of people.slice(1)) await p.dev.page.getByText("Diese Runde gibt es nicht (mehr)").waitFor({ timeout: 8_000 });
    // … and forget the group on their device (seed, note, cached results).
    for (const p of people.slice(1)) {
      const rec = await p.dev.page.evaluate((gid) => localStorage.getItem(`wichtel:g:${gid}`), group.gid);
      assert.equal(rec, null, `${p.name}: local record removed after the deletion`);
    }
    const gone = await fetch(`${server.base}/api/groups/${group.gid}`);
    assert.equal(gone.status, 404);

    console.log(`# Verlosung 1: ${JSON.stringify(r1)}\n# Verlosung 2: ${JSON.stringify(r2)}\n# Verlosung 3: ${JSON.stringify(r3)}`);
  }, server);
});
