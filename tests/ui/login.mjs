// Browser test of the login (doc §21.5 F11): a server with one user shows
// the login form, refuses a wrong password, lets the user in, names them
// in the header, and logs them out again; with no script errors or CSP
// violations beyond the refused login itself.
//
//   node tests/ui/login.mjs target/debug/routelith [screenshot-dir]
//
// Needs the `playwright` package and its Chromium.

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const bin = resolve(process.argv[2] || "target/debug/routelith");
const shots = process.argv[3];
const port = 19000 + Math.floor(Math.random() * 1000);
const base = `http://127.0.0.1:${port}`;
const dir = mkdtempSync(join(tmpdir(), "routelith-login-"));
const cfg = join(dir, "routelith.toml");
const password = "correct horse battery";
writeFileSync(
  cfg,
  `[server]
data_dir = ${JSON.stringify(join(dir, "data"))}
listen_ui = "127.0.0.1:${port}"

[[group]]
name = "local"

[[group.target]]
name = "web-ui"
host = "127.0.0.1"
probe = "tcp"
port = ${port}
step = "2s"
pings = 2
spread = "500ms"
timeout = "500ms"
`
);

let failed = false;
function check(cond, msg) {
  if (!cond) {
    failed = true;
    console.error("FAIL: " + msg);
  } else {
    console.log("ok: " + msg);
  }
}

const add = spawnSync(bin, ["ctl", "user", "add", "ann", "--role", "operator", "--password-stdin", "-c", cfg], {
  input: password + "\n",
  encoding: "utf8",
});
check(add.status === 0, "ctl user add: " + (add.stdout + add.stderr).trim());

const server = spawn(bin, ["server", "-c", cfg, "--stats-interval", "0"], { stdio: ["ignore", "inherit", "inherit"] });
let spawnError = null;
server.once("error", (e) => (spawnError = e));

async function waitFor(fn, what, ms = 15000) {
  const end = Date.now() + ms;
  for (;;) {
    if (spawnError) throw new Error("the server did not start: " + spawnError.message);
    try {
      const v = await fn();
      if (v) return v;
    } catch (_) {
      /* not yet */
    }
    if (Date.now() > end) throw new Error("timed out waiting for " + what);
    await new Promise((r) => setTimeout(r, 250));
  }
}

let browser;
try {
  await waitFor(async () => (await fetch(base + "/healthz")).ok, "the server");
  check((await fetch(base + "/api/v1/series")).status === 401, "the API needs a login");

  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1000, height: 700 }, deviceScaleFactor: 2 });
  const problems = [];
  page.on("console", (m) => {
    // The browser logs the refused login's 401 itself.
    if (m.type() === "error" && !/status of 401/.test(m.text())) problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(String(e)));

  await page.goto(base + "/");
  await page.waitForSelector("form.login");
  check(true, "the login form is shown first");
  if (shots) await page.screenshot({ path: join(shots, "login.png") });

  await page.fill("#login-name", "ann");
  await page.fill("#login-password", "not the password");
  await page.click("form.login button[type=submit]");
  await page.waitForFunction(() => document.querySelector("form.login .error")?.textContent !== "", null, { polling: 100 }).catch(() => {});
  const err = await page.textContent("form.login .error");
  check(/wrong user name or password/.test(err), "a wrong password is refused (" + JSON.stringify(err) + ")");

  await page.fill("#login-password", password);
  await page.click("form.login button[type=submit]");
  await page.waitForSelector("table.matrix");
  check(true, "the overview loads after the login");
  const whoText = await page.textContent("#who");
  check(/ann · operator/.test(whoText), "the header names the user (" + JSON.stringify(whoText) + ")");
  const cookies = await page.context().cookies();
  const c = cookies.find((k) => k.name === "rl_session");
  check(c && c.httpOnly && c.sameSite === "Strict", "the session cookie is HttpOnly and SameSite=Strict");

  // A reload keeps the session.
  await page.reload();
  await page.waitForSelector("table.matrix");
  check(true, "the session survives a reload");

  await page.click("#who button");
  await page.waitForSelector("form.login");
  check((await page.textContent("#who")).trim() === "", "logging out shows the form again");
  check((await fetch(base + "/api/v1/series", { headers: { Cookie: "rl_session=" + (c ? c.value : "") } })).status === 401, "the old session no longer works");

  check(problems.length === 0, "no script errors or CSP violations" + (problems.length ? ": " + problems.join(" | ") : ""));
} catch (e) {
  failed = true;
  console.error("FAIL: " + e.message);
} finally {
  if (browser) await browser.close();
  if (server.pid !== undefined && server.exitCode === null && server.signalCode === null) {
    const exited = new Promise((r) => server.once("exit", r));
    server.kill("SIGINT");
    await exited;
  }
  rmSync(dir, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
