// Browser test of the multi-vantage UI (doc §21.7 G6, G12) with a real
// agent: the overview marks the agent's column as connected, the agents
// page lists it with its clock and spool and the series its allow-list
// refused, an admin makes an enrollment token there, the target view
// stacks one graph per vantage and can share one y-axis, and revoking
// the agent from the page shows it revoked. On the way, a rule with
// min_vantages = 2 raises one alert for a port closed from both vantages,
// naming both (§21.7 G13).
//
//   node tests/ui/agents.mjs target/debug/routelith [screenshot-dir]
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
const port = 20000 + Math.floor(Math.random() * 1000);
const agentPort = port + 1000;
const base = `http://127.0.0.1:${port}`;
const dir = mkdtempSync(join(tmpdir(), "routelith-agents-"));
const cfg = join(dir, "routelith.toml");
const agentCfg = join(dir, "agent.toml");
const password = "correct horse battery";
writeFileSync(
  cfg,
  `[server]
data_dir = ${JSON.stringify(join(dir, "data"))}
vantage = "home"
listen_ui = "127.0.0.1:${port}"
listen_agents = "127.0.0.1:${agentPort}"

[[alert]]
name = "down-everywhere"
metric = "loss"
condition = ">= 100%"
for = "1 round"
min_vantages = 2

[[group]]
name = "local"
vantages = ["home", "plant-genk"]

[[group.target]]
name = "web-ui"
host = "127.0.0.1"
probe = "tcp"
port = ${port}
step = "2s"
pings = 2
spread = "500ms"
timeout = "500ms"

# Closed from both vantages: one correlated alert.
[[group.target]]
name = "closed-both"
host = "127.0.0.1"
probe = "tcp"
port = ${port + 3}
step = "2s"
pings = 2
spread = "500ms"
timeout = "500ms"
alerts = ["down-everywhere"]

# The agent's allow-list takes only these ports, so it refuses this.
[[group.target]]
name = "closed-port"
host = "127.0.0.1"
probe = "tcp"
port = ${port + 2}
step = "2s"
pings = 2
spread = "500ms"
timeout = "500ms"
`
);
writeFileSync(
  agentCfg,
  `server = "127.0.0.1:${agentPort}"
data_dir = ${JSON.stringify(join(dir, "agent"))}
allow = ["127.0.0.0/8", "tcp:${port}", "tcp:${port + 3}"]
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

const add = spawnSync(bin, ["ctl", "user", "add", "ada", "--role", "admin", "--password-stdin", "-c", cfg], {
  input: password + "\n",
  encoding: "utf8",
});
check(add.status === 0, "ctl user add: " + (add.stdout + add.stderr).trim());
const tok = spawnSync(bin, ["ctl", "agent", "add", "plant-genk", "-c", cfg], { encoding: "utf8" });
const token = (tok.stdout.match(/rlt1-\S+/) || [])[0];
check(tok.status === 0 && token, "ctl agent add: " + (tok.stdout + tok.stderr).trim().split("\n")[0]);

const procs = [];
function start(args) {
  const p = spawn(bin, args, { stdio: ["ignore", "inherit", "inherit"] });
  p.once("error", (e) => (spawnError = e));
  procs.push(p);
  return p;
}
let spawnError = null;

async function waitFor(fn, what, ms = 20000) {
  const end = Date.now() + ms;
  for (;;) {
    if (spawnError) throw new Error("a process did not start: " + spawnError.message);
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
  start(["server", "-c", cfg, "--stats-interval", "0"]);
  await waitFor(async () => (await fetch(base + "/healthz")).ok, "the server");
  const enroll = spawnSync(bin, ["agent", "enroll", "-c", agentCfg, "--token", token], { encoding: "utf8" });
  check(enroll.status === 0, "agent enroll: " + (enroll.stdout + enroll.stderr).trim());
  start(["agent", "run", "-c", agentCfg]);

  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 800 }, deviceScaleFactor: 2 });
  const problems = [];
  page.on("console", (m) => {
    if (m.type() === "error") problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(String(e)));

  await page.goto(base + "/");
  await page.waitForSelector("form.login");
  await page.fill("#login-name", "ada");
  await page.fill("#login-password", password);
  await page.click("form.login button[type=submit]");
  await page.waitForSelector("table.matrix");
  // Before the first agent connects there is already a way to the page.
  check(await page.waitForSelector("main a[href='#/agents']").then(() => true), "the overview links to the Agents page");

  // The overview: the agent's column head gets a green dot once it is up.
  await waitFor(async () => (await page.$("table.matrix thead a .dot.up")) !== null, "the agent's column to show connected", 30000);
  check(/plant-genk/.test(await page.textContent("table.matrix thead")), "the overview has a column for the agent");
  check(/1 agent, 1 connected/.test(await page.textContent("main")), "the overview counts the agents");
  await waitFor(async () => /refused/.test(await page.textContent("table.matrix tbody")), "the refused cell");
  check(true, "the overview marks the series the agent refused");
  await waitFor(async () => /from (home, plant-genk|plant-genk, home)/.test(await page.textContent("section.alerts")), "the correlated alert", 30000);
  const raised = await page.$$eval("section.alerts li", (l) => l.map((x) => x.textContent));
  check(raised.length === 1 && /closed-both.*down-everywhere/.test(raised[0]), "one alert for both vantages, naming them (" + JSON.stringify(raised) + ")");
  await waitFor(async () => (await page.$$("table.matrix tbody .alerting")).length === 2, "both vantages' cells marked");
  check(true, "the cells of both vantages are marked");
  if (shots) await page.screenshot({ path: join(shots, "agents-overview.png") });

  // The agents page.
  await page.click("table.matrix thead a");
  await page.waitForSelector("table.agents tr[data-agent=plant-genk]");
  await waitFor(
    async () => /connected/.test(await page.textContent("tr[data-agent=plant-genk]")) && /ms/.test(await page.textContent("tr[data-agent=plant-genk] td:nth-child(7)")),
    "the agent's clock offset",
    40000
  );
  const row = await page.textContent("tr[data-agent=plant-genk]");
  check(/tcp/.test(row), "the agents page shows what the agent can measure (" + JSON.stringify(row.slice(0, 160)) + ")");
  await waitFor(async () => /closed-port.*allow list/.test(await page.textContent("table.agents")), "the refused series", 20000);
  check(true, "the series the allow-list refused is listed, with why");

  // An admin makes a token for another agent.
  await page.fill("#agent-name", "plant-gent");
  await page.click("form.enroll button[type=submit]");
  await page.waitForSelector(".token code.secret");
  check(/^rlt1-/.test(await page.textContent(".token code.secret")), "an admin gets an enrollment token");
  await page.waitForSelector("section.tokens li");
  check(/plant-gent/.test(await page.textContent("section.tokens")), "the waiting token is listed");
  if (shots) await page.screenshot({ path: join(shots, "agents-page.png"), fullPage: true });

  // The target view: one graph per vantage, and one shared y-axis. The
  // graphs reload once a minute, so open it once both series have data.
  await waitFor(
    () =>
      page.evaluate(async () => {
        const s = (await (await fetch("/api/v1/series")).json()).series.filter((x) => x.target === "web-ui");
        const n = await Promise.all(s.map(async (x) => (await (await fetch("/api/v1/series/" + x.id + "/data?range=3h")).json()).points.length));
        return n.length === 2 && n.every((k) => k > 0);
      }),
    "rounds from both vantages",
    30000
  );
  await page.goto(base + "/#/target/web-ui");
  await page.waitForSelector("section.graph canvas");
  const heads = await page.$$eval("section.graph .head strong", (h) => h.map((x) => x.textContent));
  check(heads.length === 2 && heads.some((h) => /from home/.test(h)) && heads.some((h) => /from plant-genk/.test(h)), "a graph per vantage (" + heads.join(", ") + ")");
  await waitFor(async () => (await page.$$eval("section.graph canvas", (c) => c.every((x) => Number(x.dataset.points) > 0))), "both graphs to draw");
  await page.check("label.toggle input");
  await page.waitForFunction(() => location.hash.includes("y=shared"));
  await waitFor(async () => {
    const tops = await page.$$eval("section.graph canvas", (c) => c.map((x) => x.dataset.top));
    return tops.length === 2 && tops[0] && tops[0] === tops[1];
  }, "a shared y-axis");
  check(true, "the graphs share one y-axis when asked");
  if (shots) await page.screenshot({ path: join(shots, "agents-target.png"), fullPage: true });

  // Revoke it from the agents page.
  await page.goto(base + "/#/agents");
  await page.waitForSelector("tr[data-agent=plant-genk] button.link");
  await page.click("tr[data-agent=plant-genk] button.link");
  await page.click("tr[data-agent=plant-genk] button.danger");
  await waitFor(async () => /revoked/.test(await page.textContent("tr[data-agent=plant-genk]")), "the agent to show revoked");
  check(true, "revoking from the page marks the agent revoked");
  const api = await page.evaluate(async () => (await fetch("/api/v1/agents")).json());
  const a = api.agents.find((x) => x.name === "plant-genk");
  check(a && a.revoked_ms > 0, "the API agrees");

  check(problems.length === 0, "no script errors or CSP violations" + (problems.length ? ": " + problems.join(" | ") : ""));
} catch (e) {
  failed = true;
  console.error("FAIL: " + e.message);
} finally {
  if (browser) await browser.close();
  for (const p of procs.reverse()) {
    if (p.pid !== undefined && p.exitCode === null && p.signalCode === null) {
      const exited = new Promise((r) => p.once("exit", r));
      p.kill("SIGINT");
      await exited;
    }
  }
  rmSync(dir, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
