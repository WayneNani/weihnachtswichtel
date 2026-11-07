// Shared harness for the browser end-to-end tests (tests/e2e/*.test.mjs).
//
//   scripts/build-all.sh && node --test --test-concurrency=1 tests/e2e/
//
// - starts the debug wichtel-server with a temporary database on a free port (like scripts/smoke.mjs),
// - launches ONE Chromium process per test file (playwright library, preinstalled; no @playwright/test),
// - every participant is an isolated browser context (= own device, own storage),
// - records every HTTP request of every context (URL, all headers, body) for privacy checks,
// - takes screenshots of all open pages only when a test fails (tests/e2e/artifacts/).
//
// Environment: WICHTEL_SERVER (server binary; default $CARGO_TARGET_DIR/debug/wichtel-server),
// E2E_HEADED=1 (visible browser), E2E_SLOWMO=<ms>, E2E_KEEP=1 (keep temp dir with DB and server log).

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const TARGET_DIR = process.env.CARGO_TARGET_DIR || "/home/user/wichtel-target";
export const SERVER_BIN = process.env.WICHTEL_SERVER || path.join(TARGET_DIR, "debug", "wichtel-server");
const ARTIFACTS = path.join(ROOT, "tests", "e2e", "artifacts");
const KEEP = process.env.E2E_KEEP === "1";

function loadPlaywright() {
  const require = createRequire(import.meta.url);
  try {
    return require("playwright");
  } catch {
    // Globally installed package next to the running node binary.
    return require(path.join(path.dirname(process.execPath), "..", "lib", "node_modules", "playwright"));
  }
}
const { chromium } = loadPlaywright();

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------------------------

async function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/**
 * Starts wichtel-server with a fresh temporary database. Web-Push is effectively disabled: only the
 * unreachable host `push.invalid` is allowed as push service, and no test subscribes.
 *
 * `spawnedAt` (Unix seconds, floor) is a lower bound for the server's minutely job ticks: the first
 * tick runs right after start, then every 60 s (tokio interval).
 */
export async function startServer() {
  if (!fs.existsSync(SERVER_BIN)) throw new Error(`server binary not found: ${SERVER_BIN} – run scripts/build-all.sh first`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wichtel-e2e-"));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const dbPath = path.join(dir, "e2e.db");
  let log = "";
  const spawnedAt = Math.floor(Date.now() / 1000);
  const proc = spawn(SERVER_BIN, [], {
    env: {
      ...process.env,
      WICHTEL_ADDR: `127.0.0.1:${port}`,
      WICHTEL_DB: dbPath,
      WICHTEL_PUBLIC_URL: base,
      WICHTEL_PUSH_HOSTS: "push.invalid",
      RUST_LOG: process.env.RUST_LOG || "warn",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  proc.stdout.on("data", (d) => (log += d));
  proc.stderr.on("data", (d) => (log += d));
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (proc.exitCode !== null) throw new Error(`server did not start:\n${log}`);
    try {
      const r = await fetch(`${base}/api/health`);
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error(`server not healthy after 30 s:\n${log}`);
    await sleep(100);
  }
  return {
    base,
    dir,
    dbPath,
    spawnedAt,
    get log() {
      return log;
    },
    async getGroup(gid) {
      const r = await fetch(`${base}/api/groups/${gid}`);
      assert.equal(r.status, 200, `GET group ${gid}`);
      return r.json();
    },
    /** Next server job tick at or after `minTime` (Unix seconds), as a safe lower bound. */
    nextTick(minTime) {
      let t = spawnedAt;
      while (t < minTime) t += 60;
      return t;
    },
    async stop() {
      if (proc.exitCode === null) {
        proc.kill("SIGTERM");
        await new Promise((r) => (proc.exitCode !== null ? r() : proc.once("exit", r)));
      }
      if (!KEEP) fs.rmSync(dir, { recursive: true, force: true });
      else console.log(`# kept ${dir}`);
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Browser, devices (contexts) and request recording
// ---------------------------------------------------------------------------------------------

export async function launchBrowser() {
  return chromium.launch({
    headless: process.env.E2E_HEADED !== "1",
    slowMo: Number(process.env.E2E_SLOWMO || 0),
  });
}

/**
 * A device = an isolated browser context (own localStorage / IndexedDB) with one page.
 * All requests of the context (page, worker, service worker) are recorded.
 */
export class Device {
  static all = new Set();

  constructor(context, page, label) {
    this.context = context;
    this.page = page;
    this.label = label;
    this.requests = [];
    this.consoleErrors = [];
    Device.all.add(this);
  }

  static async open(browser, label, { viewport = { width: 1100, height: 900 }, mobile = false } = {}) {
    const context = await browser.newContext({
      viewport,
      deviceScaleFactor: 1,
      isMobile: mobile,
      hasTouch: mobile,
      locale: "de-DE",
      timezoneId: "Europe/Berlin",
      permissions: ["clipboard-read", "clipboard-write"],
    });
    context.setDefaultTimeout(20_000);
    // Headless Chromium reports Notification.permission = "denied" (even with the permission
    // granted); real browsers start at "default", where the bell invites to opt in. Push itself
    // is never subscribed in these tests.
    await context.addInitScript(() => {
      try {
        Object.defineProperty(Notification, "permission", { get: () => "default", configurable: true });
      } catch {
        /* no Notification API */
      }
    });
    const page = await context.newPage();
    const dev = new Device(context, page, label);
    const record = (req) => {
      const entry = { url: req.url(), method: req.method(), headers: req.headers(), body: req.postDataBuffer() };
      dev.requests.push(entry);
      // Full header set (incl. Referer) as actually sent; resolves once the request went out.
      entry.allHeaders = req.allHeaders().then(
        (h) => (entry.headers = h),
        () => undefined,
      );
    };
    context.on("request", record);
    page.on("console", (m) => {
      if (m.type() === "error") dev.consoleErrors.push(m.text());
    });
    page.on("pageerror", (e) => dev.consoleErrors.push(String(e)));
    return dev;
  }

  async goto(url) {
    await this.page.goto(url);
  }

  async close() {
    Device.all.delete(this);
    if (this.consoleErrors.length && process.env.E2E_DEBUG) console.log(`# console (${this.label}): ${this.consoleErrors.join(" | ")}`);
    await Promise.race([Promise.all(this.requests.map((r) => r.allHeaders)), sleep(2000)]);
    await this.context.close();
  }
}

/** Runs `fn`; on failure, screenshots every open page into tests/e2e/artifacts/ and rethrows. */
export async function withScreenshots(name, fn, server) {
  try {
    return await fn();
  } catch (err) {
    fs.mkdirSync(ARTIFACTS, { recursive: true });
    const slug = name.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
    for (const d of Device.all) {
      try {
        await d.page.screenshot({ path: path.join(ARTIFACTS, `${slug}-${d.label}.png`), fullPage: true });
      } catch {
        /* page gone */
      }
      if (d.consoleErrors.length) console.log(`# console errors (${d.label}):\n#   ${d.consoleErrors.join("\n#   ")}`);
    }
    if (server) fs.writeFileSync(path.join(ARTIFACTS, `${slug}-server.log`), server.log);
    throw err;
  }
}

// ---------------------------------------------------------------------------------------------
// UI flows
// ---------------------------------------------------------------------------------------------

export function isoDate(daysFromNow) {
  const d = new Date(Date.now() + daysFromNow * 86400_000);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** `<input type="datetime-local">` value for a Unix time (Europe/Berlin, the contexts' time zone). */
export function localInput(unix) {
  const parts = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Europe/Berlin",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).format(new Date(unix * 1000));
  return parts.replace(" ", "T");
}

export function parseGroupLink(link) {
  const u = new URL(link);
  const m = /^\/g\/([A-Za-z0-9_-]{22})$/.exec(u.pathname);
  assert.ok(m, `group link: ${link}`);
  const frag = new URLSearchParams(u.hash.slice(1));
  return { gid: m[1], k: frag.get("k"), a: frag.get("a"), s: frag.get("s"), path: u.pathname + u.hash };
}

/**
 * Spielleiter creates a group through the UI. Returns invite and admin link; the device ends on
 * the group page (admin view, not joined yet).
 */
export async function createGroup(dev, base, { title, budget = "", eventDate = isoDate(30), description = "", drawAt = "" }) {
  const { page } = dev;
  await dev.goto(`${base}/`);
  await page.getByRole("button", { name: "Neue Runde anlegen" }).click();
  await page.locator("#title").fill(title);
  if (budget) await page.locator("#budget").fill(budget);
  await page.locator("#event").fill(eventDate);
  if (drawAt) await page.locator("#drawat").fill(drawAt);
  if (description) await page.locator("#desc").fill(description);
  await page.getByRole("button", { name: "Runde anlegen" }).click();
  await page.getByRole("heading", { name: /Deine Runde ist angelegt/ }).waitFor();
  const invite = await page.locator(".copy-field", { hasText: "Einladungslink" }).locator("input").inputValue();
  const adminField = page.locator(".copy-field", { hasText: "Spielleiter-Link" });
  const admin = await adminField.locator("input").inputValue();
  const continueBtn = page.getByRole("button", { name: "Weiter zur Runde" });
  assert.equal(await continueBtn.isDisabled(), true, "continue is blocked until the admin link is saved");
  await adminField.getByRole("button", { name: "Kopieren" }).click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), admin, "admin link copied");
  assert.equal(await page.locator("label.check input[type=checkbox]").isChecked(), true, "copying confirms the checkbox");
  await continueBtn.click();
  await page.locator("#jname").waitFor();
  assert.equal(new URL(page.url()).hash, new URL(admin).hash, "admin page keeps the admin link in the address bar");
  const inv = parseGroupLink(invite);
  const adm = parseGroupLink(admin);
  assert.equal(inv.gid, adm.gid);
  assert.equal(inv.k, adm.k);
  assert.equal(inv.a, null, "invite link carries no admin secret");
  assert.ok(adm.a, "admin link carries the admin secret");
  return { gid: inv.gid, invite, admin, k: inv.k, a: adm.a };
}

/**
 * Joins on the current group page (invite or admin link already open) and goes through the forced
 * "save your personal link" dialog (copy + confirm). Returns the personal link and own pid.
 */
export async function join(dev, { name, wish = "" }) {
  const { page } = dev;
  await page.locator("#jname").fill(name);
  if (wish) await page.locator("#jwish").fill(wish);
  await page.getByRole("button", { name: "Mitmachen" }).click();
  const dialog = page.locator("dialog.modal[open]");
  await dialog.getByRole("heading", { name: "Speichere deinen persönlichen Link" }).waitFor();
  const link = await dialog.locator(".copy-field input").inputValue();
  const weiter = dialog.getByRole("button", { name: "Weiter" });
  await dialog.locator("input[type=checkbox]").check();
  assert.equal(await weiter.isDisabled(), true, "dialog cannot be closed before the link was copied");
  await dialog.getByRole("button", { name: "Kopieren" }).click();
  assert.equal(await page.evaluate(() => navigator.clipboard.readText()), link, "personal link copied");
  await weiter.click();
  await dialog.waitFor({ state: "detached" }).catch(() => undefined);
  await page.locator("dialog.modal[open]").waitFor({ state: "hidden" });
  await page.getByRole("heading", { name: /Du bist dabei/ }).waitFor();
  const parsed = parseGroupLink(link);
  assert.ok(parsed.s, "personal link carries the seed");
  assert.equal(parsed.a, null, "personal link carries no admin secret");
  const pid = await page.evaluate((gid) => JSON.parse(localStorage.getItem(`wichtel:g:${gid}`) ?? "{}").pid ?? null, parsed.gid);
  assert.ok(pid, "own pid stored on the device");
  return { link, pid, seed: parsed.s };
}

export async function setNote(dev, note) {
  const { page } = dev;
  const box = page.locator("details.note-box").first();
  await box.locator("summary").click();
  await box.locator("#note").fill(note);
  await box.getByRole("button", { name: "Nachricht speichern" }).click();
  await box.getByRole("button", { name: "✓ Gespeichert" }).waitFor();
}

export async function fingerprint(dev) {
  const words = dev.page.locator(".fp-words li");
  await words.first().waitFor();
  return (await words.allInnerTexts()).join(" ");
}

/** Waits until the roster shows `n` participants. */
export async function waitForRoster(dev, n) {
  await dev.page.locator("#roster-title .count", { hasText: `(${n})` }).waitFor();
}

export async function adminStart(dev) {
  const { page } = dev;
  await page.getByRole("button", { name: "Verlosung jetzt starten" }).click();
  await page.getByRole("button", { name: "Ja, jetzt starten" }).click();
}

/** Waits for the result card, reveals it and returns the recipient's name (+ visible note). */
export async function readResult(dev, { timeout = 60_000, drawNo = 1 } = {}) {
  const { page } = dev;
  // From draw 2 on, the card names the draw number – wait for that one, not a stale card.
  const card = drawNo > 1 ? page.locator("section.result-card", { hasText: `Verlosung Nr. ${drawNo}` }) : page.locator("section.result-card");
  await card.waitFor({ timeout });
  await card.getByRole("button", { name: /Aufdecken/ }).click();
  const name = await card.locator(".result-name").innerText();
  const note = (await card.locator(".result-block.private .pre").count()) ? await card.locator(".result-block.private .pre").innerText() : null;
  return { name, note, cardText: await card.innerText() };
}

/** The assignment giver → recipient must be a permutation without fixed points. */
export function assertDerangement(results) {
  const givers = Object.keys(results);
  const recipients = Object.values(results);
  assert.deepEqual([...recipients].sort(), [...givers].sort(), `every participant is drawn exactly once: ${JSON.stringify(results)}`);
  for (const g of givers) assert.notEqual(results[g], g, `${g} draws themselves`);
}

/** Visible text of the whole page (innerText of body). */
export async function bodyText(dev) {
  return dev.page.locator("body").innerText();
}

/** True if the page has no horizontal overflow. Returns the measurement for messages. */
export async function horizontalOverflow(page) {
  return page.evaluate(() => {
    const doc = document.documentElement;
    const width = doc.clientWidth;
    const offenders = [];
    for (const el of document.querySelectorAll("body *")) {
      const r = el.getBoundingClientRect();
      // Only the right edge matters: content left of 0 (e.g. the off-screen skip link) does not scroll.
      if (r.width > 0 && r.right > width + 1) {
        const s = getComputedStyle(el);
        if (s.position === "fixed" || s.visibility === "hidden") continue;
        // Skip elements clipped by an ancestor with overflow hidden/auto.
        let clipped = false;
        for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
          const o = getComputedStyle(p).overflowX;
          if (o !== "visible") {
            clipped = true;
            break;
          }
        }
        if (!clipped) offenders.push(`${el.tagName.toLowerCase()}${el.id ? "#" + el.id : ""}.${[...el.classList].join(".")} [${Math.round(r.left)}..${Math.round(r.right)}]`);
      }
    }
    return { scrollWidth: doc.scrollWidth, clientWidth: width, offenders: offenders.slice(0, 10) };
  });
}
