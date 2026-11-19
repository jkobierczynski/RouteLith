// Browser test of the web UI (architecture doc §21.4): start a real
// `routelith server` measuring TCP connect time to its own UI port, then
// check in Chromium that the overview matrix fills in and that the target
// view's canvas draws a smoke graph and shows this machine's health
// snapshot, with no script errors or CSP violations.
//
//   node tests/ui/smoke-graph.mjs target/debug/routelith [screenshot-dir]
//
// Needs the `playwright` package and its Chromium.

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const bin = resolve(process.argv[2] || "target/debug/routelith");
const shots = process.argv[3];
const port = 18000 + Math.floor(Math.random() * 1000);
const base = `http://127.0.0.1:${port}`;
const dir = mkdtempSync(join(tmpdir(), "routelith-ui-"));
const cfg = join(dir, "routelith.toml");
writeFileSync(
  cfg,
  `[server]
data_dir = ${JSON.stringify(join(dir, "data"))}
vantage = "ci"
listen_ui = "127.0.0.1:${port}"

[[group]]
name = "local"

[[group.target]]
name = "web-ui"
host = "127.0.0.1"
probe = "tcp"
port = ${port}
step = "2s"
pings = 5
spread = "500ms"
timeout = "500ms"

[[group.target]]
name = "closed-port"
host = "127.0.0.1"
probe = "tcp"
port = 9
step = "2s"
pings = 2
spread = "500ms"
timeout = "500ms"
`
);

const server = spawn(bin, ["server", "-c", cfg, "--stats-interval", "0"], { stdio: ["ignore", "inherit", "inherit"] });
let failed = false;
function check(cond, msg) {
  if (!cond) {
    failed = true;
    console.error("FAIL: " + msg);
  } else {
    console.log("ok: " + msg);
  }
}

async function waitFor(fn, what, ms = 15000) {
  const end = Date.now() + ms;
  for (;;) {
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

// page.waitForFunction runs its predicate through eval in the page, which
// the UI's CSP (no 'unsafe-eval') refuses with some Playwright versions;
// page.evaluate goes through the debugger protocol and is not affected.
function waitInPage(page, fn, arg, ms = 30000) {
  return waitFor(() => page.evaluate(fn, arg), "the page", ms);
}

let browser;
try {
  await waitFor(async () => (await fetch(base + "/healthz")).ok, "the server");
  // A few rounds, so the graph has columns.
  await waitFor(async () => {
    const l = await (await fetch(base + "/api/v1/latest")).json();
    return l.latest.length === 2;
  }, "the first rounds");
  await new Promise((r) => setTimeout(r, 4000));

  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1000, height: 800 }, deviceScaleFactor: 2 });
  const problems = [];
  page.on("console", (m) => {
    if (m.type() === "error") problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(String(e)));

  const resp = await page.goto(base + "/");
  check(resp.ok(), "the page loads");
  check((resp.headers()["content-security-policy"] || "").includes("script-src 'self'"), "the page carries its CSP");
  await waitInPage(page, () => [...document.querySelectorAll("td.cell span.v")].every((s) => s.textContent && s.textContent !== "…"));
  const cells = await page.$$eval("td.cell span.v", (s) => s.map((e) => e.textContent));
  check(cells.length === 2, "the matrix has a cell per series (" + cells.join(", ") + ")");
  check(cells.some((c) => / ms$/.test(c)), "the reachable target shows a median");
  check(cells.includes("lost"), "the closed port shows as lost");
  if (shots) await page.screenshot({ path: join(shots, "overview.png") });

  await page.click("text=web-ui");
  await waitInPage(page, () => {
    const c = document.querySelector("section.graph canvas");
    return c && Number(c.dataset.points) > 0;
  });
  const drawn = await page.$eval("section.graph canvas", (c) => {
    const ctx = c.getContext("2d");
    const { data } = ctx.getImageData(0, 0, c.width, c.height);
    let painted = 0;
    let coloured = 0;
    for (let i = 0; i < data.length; i += 4) {
      if (data[i + 3] > 0) painted++;
      // The median line: a saturated colour, not grey smoke or grid.
      const [r, g, b] = [data[i], data[i + 1], data[i + 2]];
      if (data[i + 3] > 200 && Math.max(r, g, b) - Math.min(r, g, b) > 80) coloured++;
    }
    return { points: Number(c.dataset.points), painted, coloured };
  });
  check(drawn.points >= 1, "the graph has points (" + drawn.points + ")");
  check(drawn.painted > 1000, "the canvas is drawn (" + drawn.painted + " pixels)");
  check(drawn.coloured > 0, "median lines are drawn (" + drawn.coloured + " pixels)");
  const summary = await page.textContent("section.graph .summary");
  check(/^median .* ms · loss 0 % · MOS 4\.\d\d · \d+ rounds · every round/.test(summary), "the summary reads " + JSON.stringify(summary));

  // The health snapshot taken at start-up: the panel and the hover tip.
  await page.waitForSelector("section.host:not([hidden])");
  const hostText = await page.textContent("section.host");
  check(/This machine \(ci\)/.test(hostText) && /CPU|snapshots/.test(hostText), "the health panel reads " + JSON.stringify(hostText));
  const box = await page.$eval("section.graph canvas", (c) => {
    const r = c.getBoundingClientRect();
    return { right: r.left + r.width - 13, y: r.top + r.height / 2 };
  });
  // Move in from the right edge until the pointer is over a column.
  let tipText = "";
  for (let dx = 0; dx < 300 && !tipText; dx += 1) {
    await page.mouse.move(box.right - dx, box.y);
    if (await page.isVisible("section.graph .tip")) tipText = await page.textContent("section.graph .tip");
  }
  check(/gateway .* · DNS /.test(tipText), "the hover tip shows the network state (" + JSON.stringify(tipText) + ")");

  for (const r of ["30h", "10d"]) {
    await page.click(`.ranges button:text("${r}")`);
    await waitInPage(page, (r) => location.hash.endsWith("range=" + r) && Number(document.querySelector("section.graph canvas")?.dataset.points) > 0, r);
  }
  check(true, "the 30h and 10d ranges load");
  await page.click(`.ranges button:text("3h")`);
  await waitInPage(page, () => Number(document.querySelector("section.graph canvas")?.dataset.points) > 0);
  if (shots) await page.screenshot({ path: join(shots, "target.png") });

  check(problems.length === 0, "no script errors or CSP violations" + (problems.length ? ": " + problems.join(" | ") : ""));
} catch (e) {
  failed = true;
  console.error("FAIL: " + e.message);
} finally {
  if (browser) await browser.close();
  if (server.exitCode === null && server.signalCode === null) {
    const exited = new Promise((r) => server.once("exit", r));
    server.kill("SIGINT");
    await exited;
  }
  rmSync(dir, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
