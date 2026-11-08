// Szenario 7: Wunschzettel nach der Verlosung ändern (Spec §16) – Name ist gesperrt, nur der
// Schenker sieht live „aktualisiert“, jeder hat genau einen Kontakt hochgeladen, die Kontakte
// kommen ohne pid zurück.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { adminStart, createGroup, Device, join, launchBrowser, readResult, startServer, waitForRoster, withScreenshots } from "./lib/harness.mjs";

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

const PEOPLE = [
  { label: "w-admin", name: "Wilma", wish: "Tee" },
  { label: "w-2", name: "Xaver", wish: "Socken" },
  { label: "w-3", name: "Yvonne", wish: "Kekse" },
  { label: "w-4", name: "Zeno", wish: "Bücher" },
];
const L_K = 816;

test("Szenario 7: Wunschzettel nach der Verlosung ändern, nur der Schenker sieht den Hinweis", async () => {
  await withScreenshots("wish", async () => {
    const devices = [];
    const admin = await Device.open(browser, PEOPLE[0].label);
    devices.push(admin);
    const group = await createGroup(admin, server.base, { title: "Wunschzettel-Runde" });
    for (const [i, p] of PEOPLE.entries()) {
      const dev = i === 0 ? admin : await Device.open(browser, p.label);
      if (i > 0) {
        devices.push(dev);
        await dev.goto(group.invite);
        await dev.page.locator("#jname").waitFor();
      }
      await join(dev, { name: p.name, wish: p.wish });
    }
    await waitForRoster(admin, 4);
    await adminStart(admin);

    // Everybody reveals the result (this also marks the current wish list as seen).
    const results = [];
    for (const d of devices) results.push((await readResult(d)).name);

    // Every member uploads exactly one contact; the download carries no pids, only 816-B blocks.
    const contactsUrl = `${server.base}/api/groups/${group.gid}/draws/1/contacts`;
    const deadline = Date.now() + 30_000;
    let size = 0;
    while (Date.now() < deadline) {
      const res = await fetch(contactsUrl);
      if (res.ok) size = (await res.arrayBuffer()).byteLength;
      if (size === 4 * L_K) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    assert.equal(size, 4 * L_K, "one contact per member");

    // Xaver changes the wish list after the draw; the name is locked.
    const xaver = devices[1];
    const giverIdx = results.indexOf("Xaver");
    assert.ok(giverIdx >= 0 && giverIdx !== 1, "somebody (else) gives to Xaver");
    await xaver.page.getByRole("button", { name: "Name / Wunschzettel ändern" }).first().click();
    const nameField = xaver.page.locator("#jname");
    await nameField.waitFor();
    assert.equal(await nameField.evaluate((el) => el.readOnly), true, "name is read-only after the start");
    const newWish = "Wollsocken, Größe 43";
    await xaver.page.locator("#jwish").fill(newWish);
    await xaver.page.getByRole("button", { name: "Speichern" }).click();
    await nameField.waitFor({ state: "detached" });

    // Only Xaver's Schenker sees the update – live, without reloading.
    const giver = devices[giverIdx];
    const card = giver.page.locator("section.result-card");
    await card.getByTestId("wish-updated").waitFor({ timeout: 20_000 });
    assert.ok((await card.innerText()).includes(newWish), "Schenker sees the new wish list");
    for (const [i, d] of devices.entries()) {
      if (i === giverIdx) continue;
      assert.equal(await d.page.locator("section.result-card [data-testid=wish-updated]").count(), 0, `${d.label} sees no update hint`);
    }

    // After a reload the Schenker has seen it: no stale hint, still the new wish list.
    await giver.page.reload();
    const res = await readResult(giver);
    assert.equal(res.name, "Xaver");
    assert.ok(res.cardText.includes(newWish));
  }, server);
});
