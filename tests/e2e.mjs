// End-to-end UI test with Playwright against a running portvakt dev server.
//
//   BASE=http://127.0.0.1:18443 PV_USER=admin PV_PASS=dev-password-123 node tests/e2e.mjs
//
// Optional: SHOTS=<dir> saves screenshots (used for the website), THEME=dark|light.
// Exercises login, overview, file editing with validation + rollback (needs nginx
// installed), task manager, monitor, terminal, CSRF rejection and the audit log.
// Steps whose prerequisites are missing on the host are reported as SKIP.

import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const BASE = process.env.BASE || "http://127.0.0.1:18443";
const USER = process.env.PV_USER || "admin";
const PASS = process.env.PV_PASS || "dev-password-123";
const SHOTS = process.env.SHOTS || "";
const THEME = process.env.THEME || "dark";

let failed = 0;
const pass = (m) => console.log("PASS", m);
const skip = (m) => console.log("SKIP", m);
const fail = (m) => { failed++; console.log("FAIL", m); };
const check = (cond, m) => (cond ? pass(m) : fail(m));

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, colorScheme: THEME });
const errors = [];
page.on("pageerror", (e) => errors.push(e.message));
const shot = async (name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${name}.png` }); };
const api = (method, path, body, csrf) => page.evaluate(async ([method, path, body, csrf]) => {
  const headers = { "content-type": "application/json" };
  if (csrf) headers["x-portvakt-csrf"] = csrf;
  const r = await fetch("/api" + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json().catch(() => null) };
}, [method, path, body, csrf]);

try {
  await page.goto(BASE);
  await page.fill("input[name=username]", USER);
  await page.fill("input[name=password]", "wrong-password");
  await page.click("button[type=submit]");
  await page.waitForSelector(".login .error:not(:empty)");
  check((await page.textContent(".login .error")).includes("invalid"), "wrong password is rejected");
  await shot("login");

  await page.fill("input[name=password]", PASS);
  await page.click("button[type=submit]");
  await page.waitForSelector(".page-h h1");
  pass("login");
  const session = (await api("GET", "/session")).body;

  await page.waitForTimeout(500);
  await shot("overview");
  const names = await page.locator(".sidebar .row .name").allTextContents();
  check(names.includes("System") && names.includes("Task Manager"), "sidebar lists detected apps: " + names.join(", "));

  // CSRF: a state-changing request without the token header must be refused.
  const noCsrf = await api("POST", "/rescan");
  check(noCsrf.status === 403, "POST without CSRF token is refused (" + noCsrf.status + ")");
  const withCsrf = await api("POST", "/rescan", undefined, session.csrf);
  check(withCsrf.status === 200, "POST with CSRF token is accepted");

  // Files outside a plugin's declared globs are refused.
  const shadow = await api("GET", "/apps/system/file?path=" + encodeURIComponent("/etc/shadow"));
  check(shadow.status === 400, "reading an undeclared file is refused");

  // Task manager
  await page.click('.activity button[title*="Task Manager"]');
  await page.waitForSelector("table.grid tbody tr");
  check((await page.locator("table.grid tbody tr").count()) > 3, "task manager lists processes");
  await shot("task-manager");

  // System monitor (needs a couple of samples)
  await page.click('.activity button[title*="System Monitor"]');
  await page.waitForTimeout(6500);
  check((await page.locator(".chart").count()) === 8, "monitor shows 8 charts");
  await shot("monitor");

  // nginx: edit config, broken save is rolled back, valid save goes through.
  if (names.includes("nginx")) {
    await page.click('.sidebar .row:has-text("nginx")');
    await page.waitForSelector('.list .item:has-text("/etc/nginx/nginx.conf")');
    await shot("app-nginx");
    await page.click('.list .item:has-text("/etc/nginx/nginx.conf")');
    await page.waitForSelector(".code textarea");
    const ta = page.locator(".code textarea");
    const original = await ta.inputValue();
    await ta.fill("this is not valid nginx;\n" + original);
    await page.keyboard.press("Control+s");
    await page.waitForSelector(".toast.err");
    const onDisk = await api("GET", "/apps/nginx/file?path=" + encodeURIComponent("/etc/nginx/nginx.conf"));
    check(onDisk.body.content === original, "invalid nginx config is rolled back");
    await shot("editor-rollback");
    await ta.fill("# edited by portvakt e2e\n" + original);
    await page.keyboard.press("Control+s");
    await page.waitForSelector('.toast.ok:has-text("Saved")');
    const after = await api("GET", "/apps/nginx/file?path=" + encodeURIComponent("/etc/nginx/nginx.conf"));
    check(after.body.content.startsWith("# edited by portvakt e2e"), "valid nginx config is saved");
    // Restore the original (sha from the last read).
    await api("PUT", "/apps/nginx/file", { path: "/etc/nginx/nginx.conf", content: original, sha256: after.body.sha256 }, session.csrf);
  } else skip("nginx not installed: file edit/rollback");

  // Terminal
  if (session.terminal) {
    await page.keyboard.press("Control+`");
    await page.waitForSelector(".xterm-rows");
    await page.waitForTimeout(1200);
    await page.keyboard.type("echo portvakt-$((6*7))\n");
    await page.waitForTimeout(800);
    check((await page.locator(".xterm-rows").innerText()).includes("portvakt-42"), "terminal runs commands");
    await shot("terminal");
  } else skip("terminal disabled");

  // Audit log
  await page.click('.activity button[title="Audit log"]');
  await page.waitForSelector(".audit tbody tr");
  const audit = await page.locator(".audit").innerText();
  check(audit.includes("login") && audit.includes("csrf.token"), "audit log records logins and CSRF rejections");

  // Command palette
  await page.keyboard.press("Control+Shift+P");
  await page.waitForSelector(".quick input");
  await page.keyboard.type("monitor");
  await page.waitForSelector(".quick .qi", { timeout: 5000 }).catch(() => {});
  check((await page.locator(".quick .qi").count()) > 0, "command palette finds commands");
  await shot("palette");
  await page.keyboard.press("Escape");

  check(errors.length === 0, "no JavaScript errors" + (errors.length ? ": " + errors.join(" | ") : ""));
} catch (e) {
  fail("exception: " + e.message);
  await shot("failure");
} finally {
  await browser.close();
}
console.log(failed ? `${failed} check(s) failed` : "all checks passed");
process.exit(failed ? 1 : 0);
