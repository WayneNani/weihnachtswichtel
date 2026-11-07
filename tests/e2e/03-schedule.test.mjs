// Szenario 3: Verlosungstermin – Termin beim Anlegen und im Spielleiter-Bereich setzen, Countdown
// bei allen, automatischer Start durch den minütlichen Server-Job; parallel eine zweite Runde mit
// nur 3 Teilnehmern ⇒ „Termin verpasst“.
//
// Der Server-Job läuft fest im Minutentakt (keine Test-Variable). Damit der Test nicht bis zu drei
// Minuten wartet, wird der Termin zuletzt über die API (mit dem Spielleiter-Geheimnis, wie die UI)
// auf den nächsten Job-Tick gelegt. Die UI-Wege (Anlegen mit Termin, Termin ändern) werden vorher
// durchlaufen.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import {
  assertDerangement,
  createGroup,
  Device,
  isoDate,
  join,
  launchBrowser,
  localInput,
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

const now = () => Math.floor(Date.now() / 1000);

async function setScheduleApi(gid, a, drawAt) {
  const r = await fetch(`${server.base}/api/groups/${gid}/schedule`, {
    method: "PUT",
    headers: { authorization: `Bearer ${a}`, "content-type": "application/json" },
    body: JSON.stringify({ draw_at: drawAt }),
  });
  assert.equal(r.status, 204, await r.text());
}

/** Countdown value in seconds as announced (`Verlosung in MM:SS Min.` / `Verlosung in H:MM:SS Std.`). */
async function countdownSeconds(dev) {
  const text = await dev.page.locator(".countdown .countdown-value").innerText();
  let m = /^(?:Verlosung )?in (\d\d):(\d\d) Min\.$/.exec(text);
  if (m) return Number(m[1]) * 60 + Number(m[2]);
  m = /^(?:Verlosung )?in (\d+):(\d\d):(\d\d) Std\.$/.exec(text);
  if (m) return Number(m[1]) * 3600 + Number(m[2]) * 60 + Number(m[3]);
  assert.fail(`unexpected countdown: ${text}`);
}

/** Waits until the countdown of `dev` shows `drawAt - now` (±3 s). */
async function waitCountdownFor(dev, drawAt) {
  const deadline = Date.now() + 15_000;
  for (;;) {
    const shown = await countdownSeconds(dev).catch(() => null);
    if (shown !== null && Math.abs(shown - (drawAt - now())) <= 3) return shown;
    if (Date.now() > deadline) assert.fail(`${dev.label}: countdown ${shown}s, expected ≈ ${drawAt - now()}s`);
    await sleep(250);
  }
}

test("Szenario 3: Verlosungstermin mit Countdown und automatischem Start", async () => {
  await withScreenshots("schedule", async () => {
    // Created with a schedule ≈ 3 minutes ahead (minute precision, as the form offers it).
    const firstAt = Math.ceil((now() + 180) / 60) * 60;
    const admin = await Device.open(browser, "admin");
    const group = await createGroup(admin, server.base, { title: "Termin-Runde", eventDate: isoDate(10), drawAt: localInput(firstAt) });
    const devices = [admin];
    await join(admin, { name: "Theodor Termin" });
    for (const name of ["Ursula Uhr", "Viktor Wecker", "Wilma Zeiger"]) {
      const dev = await Device.open(browser, name.split(" ")[0]);
      devices.push(dev);
      await dev.goto(group.invite);
      await join(dev, { name });
    }
    for (const d of devices) await waitForRoster(d, 4);
    let view = await server.getGroup(group.gid);
    assert.equal(view.draw_at, firstAt, "draw_at from the create form");
    for (const d of devices) {
      await waitCountdownFor(d, firstAt);
      assert.ok((await d.page.getByText("Die Verlosung startet zum Termin automatisch.").count()) === 1, `${d.label}: hint about the automatic start`);
    }
    // The countdown runs.
    const c1 = await countdownSeconds(devices[1]);
    await sleep(2100);
    const c2 = await countdownSeconds(devices[1]);
    assert.ok(c2 <= c1 - 1, `countdown runs (${c1} → ${c2})`);

    // Spielleiter changes the schedule in the admin panel; all countdowns follow without reload.
    const secondAt = firstAt + 120;
    await admin.page.locator("#admin-drawat").fill(localInput(secondAt));
    await admin.page.getByRole("button", { name: "Termin speichern" }).click();
    await admin.page.getByRole("button", { name: "✓ Gespeichert" }).waitFor();
    view = await server.getGroup(group.gid);
    assert.equal(view.draw_at, secondAt, "draw_at from the admin panel");
    for (const d of devices) await waitCountdownFor(d, secondAt);

    // Second group with only 3 participants and the same tick ⇒ "Termin verpasst".
    const small = await Device.open(browser, "small-admin");
    const smallGroup = await createGroup(small, server.base, { title: "Kleine Runde" });
    await join(small, { name: "Xaver Klein" });
    for (const name of ["Yvonne Klein", "Zacharias Klein"]) {
      const dev = await Device.open(browser, `small-${name.split(" ")[0]}`);
      await dev.goto(smallGroup.invite);
      await join(dev, { name });
      await dev.close();
    }

    // Move both schedules onto the next server job tick (≥ 10 s ahead).
    const tick = server.nextTick(now() + 10);
    await setScheduleApi(group.gid, group.a, tick);
    await setScheduleApi(smallGroup.gid, smallGroup.a, tick);
    for (const d of devices) await waitCountdownFor(d, tick);
    await waitCountdownFor(small, tick);
    console.log(`# draw_at = server tick in ${tick - now()} s`);

    // Automatic start + live protocol: everybody sees the result without doing anything.
    const results = {};
    const names = ["Theodor Termin", "Ursula Uhr", "Viktor Wecker", "Wilma Zeiger"];
    const read = await Promise.all(devices.map((d) => readResult(d, { timeout: 150_000 })));
    read.forEach((r, i) => (results[names[i]] = r.name));
    assertDerangement(results);
    view = await server.getGroup(group.gid);
    assert.equal(view.state, "done");
    assert.equal(view.draw_at, null);
    for (const d of devices) assert.equal(await d.page.locator(".countdown").count(), 0, `${d.label}: countdown gone`);

    // The small group was not started.
    const smallView = await server.getGroup(smallGroup.gid);
    assert.equal(smallView.state, "open");
    assert.equal(smallView.schedule_missed, true);
    await small.page.getByText("Zum Termin waren weniger als 4 Personen dabei.").waitFor();
    assert.equal(await small.page.locator(".countdown").count(), 0, "no countdown after a missed schedule");
    {
      const member = await Device.open(browser, "small-member");
      await member.goto(smallGroup.invite);
      await member.page.getByText("Zum Verlosungstermin waren zu wenige dabei").waitFor();
      await member.close();
    }
  }, server);
});
