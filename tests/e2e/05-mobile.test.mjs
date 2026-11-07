// Szenario 6: Mobiler Viewport (390×844) – Kernseiten ohne horizontales Scrollen, auch mit langen
// Namen, Links und QR-Codes.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import {
  adminStart,
  createGroup,
  Device,
  horizontalOverflow,
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

const MOBILE = { viewport: { width: 390, height: 844 }, mobile: true };
const LONG = "Maximilian-Alexander-Friedrich-Wilhelm-Hohenzollern-Sigmaringen"; // 63 B, NAME_MAX = 64
const LONG_WISH = "https://www.example.com/wunschliste/sehr-lange-adresse-ohne-leerzeichen-damit-nichts-umbricht-1234567890";

async function noOverflow(dev, what) {
  // Wait for layout/fonts to settle.
  await dev.page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
  const m = await horizontalOverflow(dev.page);
  assert.ok(m.scrollWidth <= m.clientWidth, `${what}: horizontal scrolling (${m.scrollWidth} > ${m.clientWidth}): ${m.offenders.join(", ")}`);
  assert.deepEqual(m.offenders, [], `${what}: elements wider than the viewport`);
}

test("Szenario 6: Kernseiten auf 390×844 ohne horizontales Scrollen", async () => {
  await withScreenshots("mobile", async () => {
    const admin = await Device.open(browser, "m-admin", MOBILE);
    await admin.goto(`${server.base}/`);
    await admin.page.getByRole("button", { name: "Neue Runde anlegen" }).waitFor();
    await noOverflow(admin, "Startseite");
    await admin.page.getByRole("button", { name: "Neue Runde anlegen" }).click();
    await admin.page.locator("#title").waitFor();
    await noOverflow(admin, "Neue Runde");

    // Created view with both QR codes open.
    const created = admin.page;
    await created.locator("#title").fill("Mobile Runde mit einem ziemlich langen Titel für kleine Bildschirme");
    await created.locator("#budget").fill("25 €");
    await created.locator("#event").fill("2026-12-24");
    await created.locator("#desc").fill(LONG_WISH);
    await created.getByRole("button", { name: "Runde anlegen" }).click();
    await created.getByRole("heading", { name: /Deine Runde ist angelegt/ }).waitFor();
    await created.getByRole("button", { name: "QR-Code zeigen" }).first().click();
    await created.getByRole("button", { name: "QR-Code zeigen" }).first().click();
    await created.locator("svg.qr").nth(1).waitFor();
    await noOverflow(admin, "Runde angelegt (mit QR-Codes)");
    // Continue with the regular flow (new group).
    const group = await createGroup(admin, server.base, { title: "Mobile Runde", budget: "25 €", description: LONG_WISH });
    await noOverflow(admin, "Gruppenseite Spielleiter (Beitritt)");
    await join(admin, { name: LONG, wish: LONG_WISH });
    await noOverflow(admin, "Gruppenseite nach Beitritt");
    // Notification bell (top right) with its panel open.
    await admin.page.getByTestId("push-bell").click();
    await admin.page.getByRole("dialog", { name: "Benachrichtigungen" }).waitFor();
    await noOverflow(admin, "Benachrichtigungs-Panel");
    await admin.page.getByRole("button", { name: "Schließen" }).click();

    const others = [];
    for (const name of ["Ole", "Pia", "Rudi"]) {
      const dev = await Device.open(browser, `m-${name}`, MOBILE);
      await dev.goto(group.invite);
      await dev.page.locator("#jname").waitFor();
      if (name === "Ole") await noOverflow(dev, "Einladungslink (Beitrittsformular)");
      // Save dialog with QR code.
      await dev.page.locator("#jname").fill(name);
      await dev.page.getByRole("button", { name: "Mitmachen" }).click();
      const dialog = dev.page.locator("dialog.modal[open]");
      await dialog.getByRole("button", { name: "QR-Code zeigen" }).click();
      await dialog.locator("svg.qr").waitFor();
      if (name === "Ole") await noOverflow(dev, "Dialog persönlicher Link (mit QR-Code)");
      await dialog.getByRole("button", { name: "Kopieren" }).click();
      await dialog.locator("input[type=checkbox]").check();
      await dialog.getByRole("button", { name: "Weiter" }).click();
      await dev.page.getByRole("heading", { name: /Du bist dabei/ }).waitFor();
      others.push(dev);
    }
    await waitForRoster(admin, 4);
    // Open every wish list and the private note.
    for (const s of await admin.page.locator("details.wish summary").all()) await s.click();
    await admin.page.locator("details.note-box summary").click();
    await noOverflow(admin, "Gruppenseite mit Teilnehmerliste, Fingerabdruck, Spielleitung");
    await others[0].page.locator("details.wish summary").first().click();
    await noOverflow(others[0], "Gruppenseite Teilnehmer");

    await adminStart(admin);
    const res = await readResult(admin);
    assert.ok(res.name);
    await noOverflow(admin, "Ergebnis (Spielleiter)");
    for (const d of others) {
      await readResult(d);
      await noOverflow(d, `Ergebnis (${d.label})`);
    }
  }, server);
});
