// Routelith web UI (architecture doc §20): an overview matrix with the
// alerts raised now, a target view of canvas smoke graphs (one per
// vantage) with the target's events, and the agents page (§21.7 G12),
// read from /api/v1. Plain JavaScript with no
// build step; the server embeds this file. Once the server has users, a
// login form comes first (doc §21.5 F11); the session is a cookie the
// page cannot read, and writes carry its CSRF token.
//
// Every value from the API goes into the page through textContent or an
// attribute, never through innerHTML.
"use strict";

(function () {
  const RANGES = ["3h", "30h", "10d"];
  const RANGE_MS = { "3h": 3 * 3600e3, "30h": 30 * 3600e3, "10d": 240 * 3600e3 };
  // Loss bands of the median line, as in rl-render (§7.1): upper bound of
  // the loss ratio, CSS token, legend label.
  const LOSS = [
    [0.0, "--loss-0", "0 %"],
    [0.05, "--loss-5", "≤5 %"],
    [0.1, "--loss-10", "≤10 %"],
    [0.2, "--loss-20", "≤20 %"],
    [1.0, "--loss-max", ">20 %"],
  ];
  // Same opacity budget as the SVG graph: the middle pair is this dark.
  const SMOKE_OPACITY = 0.6;
  const OVERVIEW_REFRESH_MS = 15e3;
  const GRAPH_REFRESH_MS = 60e3;

  const app = document.getElementById("app");
  const crumbs = document.getElementById("crumbs");
  const status = document.getElementById("status");
  const who = document.getElementById("who");
  let series = null; // from /api/v1/series, loaded once
  let serverVantage = null; // the server's own vantage, from /healthz
  let session = null; // from /api/v1/session: user, role, csrf, ...
  let timer = null;
  let generation = 0; // bumped on navigation; stale fetches are ignored
  const observers = [];

  // ---------- helpers ----------

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children) {
      if (c === null || c === undefined || c === false) continue;
      e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return e;
  }

  function css(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }

  function lossToken(loss) {
    for (const [max, token] of LOSS) if (loss <= max + 1e-9) return token;
    return LOSS[LOSS.length - 1][1];
  }

  // The server wants a login first.
  class LoginNeeded extends Error {
    constructor() {
      super("login required");
    }
  }

  async function getJson(url) {
    const r = await fetch(url, { headers: { Accept: "application/json" } });
    if (r.status === 401) throw new LoginNeeded();
    let body = null;
    try {
      body = await r.json();
    } catch (_) {
      /* not JSON */
    }
    if (!r.ok) throw new Error((body && body.error) || r.status + " " + r.statusText);
    return body;
  }

  // A write with the session's CSRF token; the parsed answer, or an error
  // with the server's reason.
  async function send(method, url, body) {
    const headers = { "X-CSRF-Token": (session && session.csrf) || "" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const r = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (r.status === 401) throw new LoginNeeded();
    let answer = null;
    try {
      answer = await r.json();
    } catch (_) {
      /* 204, or not JSON */
    }
    if (!r.ok) throw new Error((answer && answer.error) || r.status + " " + r.statusText);
    return answer;
  }

  // Only admins who logged in may enroll and revoke agents.
  function isAdmin() {
    return !!(session && session.user && session.role === "admin");
  }

  // Operators and admins who logged in may add and end silences.
  function canSilence() {
    return !!(session && session.user && (session.role === "operator" || session.role === "admin"));
  }

  function fmtMs(us) {
    if (us === undefined || us === null) return "–";
    const ms = us / 1000;
    if (ms < 1) return ms.toFixed(3) + " ms";
    if (ms < 10) return ms.toFixed(2) + " ms";
    if (ms < 100) return ms.toFixed(1) + " ms";
    return Math.round(ms) + " ms";
  }

  function fmtPct(r) {
    if (r === 0) return "0 %";
    if (r < 0.001) return "<0.1 %";
    return (r * 100).toFixed(r < 0.1 ? 1 : 0) + " %";
  }

  function fmtAge(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 90) return s + " s";
    if (s < 5400) return Math.round(s / 60) + " min";
    if (s < 172800) return Math.round(s / 3600) + " h";
    return Math.round(s / 86400) + " d";
  }

  function fmtStep(s) {
    if (s % 3600 === 0) return s / 3600 + " h";
    if (s % 60 === 0) return s / 60 + " min";
    return s + " s";
  }

  function fmtTime(t, withDate) {
    const d = new Date(t);
    const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (!withDate) return hm;
    return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + hm;
  }

  // Median of a point's quantiles (ascending, from the store).
  function medianOf(q) {
    const k = q.length;
    if (k === 0) return null;
    return k % 2 ? q[(k - 1) / 2] : (q[k / 2 - 1] + q[k / 2]) / 2;
  }

  function setStatus(text) {
    status.textContent = text;
  }

  function stop() {
    generation++;
    if (timer) clearTimeout(timer);
    timer = null;
    while (observers.length) observers.pop().disconnect();
  }

  // Refresh the current view now and then every `every` ms, one refresh
  // at a time: the next is scheduled once this one settles (failed or
  // not), so an older response never lands after a newer one, and a
  // failure is retried. Nothing runs or reports once the view is left.
  function poll(gen, refresh, every) {
    const tick = () => {
      if (gen !== generation) return;
      refresh()
        .then(
          () => gen === generation && setStatus("updated " + fmtTime(Date.now())),
          (e) => {
            if (gen !== generation) return;
            // The session ended (logged out elsewhere, or expired).
            if (e instanceof LoginNeeded) {
              session = null;
              route();
            } else setStatus("update failed: " + e.message);
          }
        )
        .finally(() => {
          if (gen === generation) timer = setTimeout(tick, every);
        });
    };
    tick();
  }

  async function loadSeries() {
    if (!series) {
      const [s, h] = await Promise.all([getJson("/api/v1/series"), getJson("/healthz")]);
      series = s.series;
      serverVantage = h.vantage;
      document.getElementById("vantage").textContent =
        "vantage " + h.vantage + " · v" + h.version;
    }
    return series;
  }

  // ---------- login ----------

  async function loadSession() {
    session = await getJson("/api/v1/session");
    showWho();
  }

  // Who is logged in, with a way out; or a way in for a reader without a
  // login. Nothing when the server has no users.
  function showWho() {
    if (!session || !session.users) {
      who.replaceChildren();
      return;
    }
    if (session.user) {
      who.replaceChildren(
        el("span", { class: "muted", text: session.user + " · " + session.role + " " }),
        el("button", { class: "link", type: "button", onclick: logout, text: "Log out" })
      );
    } else if (!session.login_required) {
      who.replaceChildren(el("a", { href: "#/login", text: "Log in" }));
    } else who.replaceChildren();
  }

  async function logout() {
    try {
      await fetch("/api/v1/logout", {
        method: "POST",
        headers: { "X-CSRF-Token": (session && session.csrf) || "" },
      });
    } catch (_) {
      /* the cookie is cleared on the next 401 anyway */
    }
    session = null;
    series = null;
    route();
  }

  function showLogin() {
    crumbs.replaceChildren();
    setStatus("");
    const name = el("input", { id: "login-name", name: "username", autocomplete: "username", required: true });
    const password = el("input", {
      id: "login-password",
      name: "password",
      type: "password",
      autocomplete: "current-password",
      required: true,
    });
    const msg = el("p", { class: "error", role: "alert" });
    const button = el("button", { type: "submit", text: "Log in" });
    const form = el(
      "form",
      { class: "login", onsubmit: submit },
      el("h1", { text: "Log in" }),
      el("label", { for: "login-name", text: "User name" }),
      name,
      el("label", { for: "login-password", text: "Password" }),
      password,
      button,
      msg
    );
    async function submit(ev) {
      ev.preventDefault();
      msg.textContent = "";
      button.disabled = true;
      try {
        const r = await fetch("/api/v1/login", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ name: name.value, password: password.value }),
        });
        const body = await r.json().catch(() => null);
        if (!r.ok) throw new Error((body && body.error) || r.status + " " + r.statusText);
        session = body;
        series = null;
        showWho();
        if (parseHash().view === "login") location.hash = "#/";
        else route();
      } catch (e) {
        msg.textContent = e.message;
        password.value = "";
        password.focus();
      } finally {
        button.disabled = false;
      }
    }
    app.replaceChildren(form);
    name.focus();
  }

  // ---------- routing ----------

  function parseHash() {
    const h = location.hash.replace(/^#/, "") || "/";
    const [path, query] = h.split("?");
    const params = new URLSearchParams(query || "");
    if (path === "/login") return { view: "login" };
    if (path === "/agents") return { view: "agents" };
    const m = path.match(/^\/target\/(.+)$/);
    if (m) {
      let name;
      try {
        name = decodeURIComponent(m[1]);
      } catch (_) {
        name = m[1];
      }
      const range = RANGES.includes(params.get("range")) ? params.get("range") : "3h";
      return { view: "target", name, range, shared: params.get("y") === "shared" };
    }
    return { view: "overview" };
  }

  function targetHref(name, range, shared) {
    const q = new URLSearchParams();
    if (range && range !== "3h") q.set("range", range);
    if (shared) q.set("y", "shared");
    const qs = q.toString();
    return "#/target/" + encodeURIComponent(name) + (qs ? "?" + qs : "");
  }

  async function route() {
    stop();
    const r = parseHash();
    const gen = generation;
    try {
      if (!session) await loadSession();
      if (gen !== generation) return;
      if (r.view === "login" || (session.login_required && !session.user)) return showLogin();
      await loadSeries();
      if (gen !== generation) return;
      if (r.view === "target") await showTarget(r.name, r.range, r.shared, gen);
      else if (r.view === "agents") await showAgents(gen);
      else await showOverview(gen);
    } catch (e) {
      if (gen !== generation) return;
      if (e instanceof LoginNeeded) {
        session = null;
        showWho();
        return showLogin();
      }
      app.replaceChildren(el("p", { class: "note", text: "Could not load: " + e.message }));
    }
  }

  // ---------- overview (§20.1) ----------

  function lossLegend() {
    return el(
      "div",
      { class: "legend" },
      el("span", { text: "Median, coloured by loss:" }),
      ...LOSS.map(([, token, label]) => {
        const i = el("i");
        i.style.background = css(token);
        return el("span", {}, i, label);
      }),
      (() => {
        const i = el("i");
        i.style.background = css("--stale");
        return el("span", {}, i, "no recent round");
      })()
    );
  }

  async function showOverview(gen) {
    crumbs.replaceChildren(el("span", { text: "Overview" }));
    document.title = "Routelith";
    const vantages = [...new Set(series.map((s) => s.vantage))].sort();
    // One row per target and family, one column per vantage.
    const rows = new Map();
    for (const s of series) {
      const key = s.group + "\u0000" + s.target + "\u0000" + s.family;
      if (!rows.has(key)) rows.set(key, { group: s.group, target: s.target, family: s.family, probe: s.probe, cells: {} });
      rows.get(key).cells[s.vantage] = s;
    }
    const sorted = [...rows.values()].sort(
      (a, b) =>
        a.group.localeCompare(b.group) ||
        a.target.localeCompare(b.target) ||
        a.family.localeCompare(b.family)
    );
    const cells = new Map(); // series id -> <span>
    const tbody = el("tbody");
    let group = null;
    for (const r of sorted) {
      if (r.group !== group) {
        group = r.group;
        tbody.append(el("tr", {}, el("th", { class: "group", colspan: vantages.length + 1, text: group })));
      }
      const tr = el(
        "tr",
        {},
        el(
          "th",
          { scope: "row" },
          el("a", { href: targetHref(r.target), text: r.target }),
          el("span", { class: "badge", text: r.family }),
          el("span", { class: "badge", text: r.probe })
        )
      );
      for (const v of vantages) {
        const s = r.cells[v];
        const span = el("span", { class: "v", text: s ? "…" : "" });
        if (s) cells.set(s.id, { span, step_s: s.step_s });
        tr.append(el("td", { class: "cell" }, span));
      }
      tbody.append(tr);
    }
    // An agent's column head says whether it is connected (§21.7 G12).
    const heads = new Map();
    const table = el(
      "table",
      { class: "matrix" },
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          el("th", { text: "Target" }),
          ...vantages.map((v) => {
            const th = el("th", { class: "cell", text: v });
            heads.set(v, th);
            return th;
          })
        )
      ),
      tbody
    );
    const agentLine = el("p", { class: "muted", hidden: true });
    const alertPanel = el("section", { class: "alerts", hidden: true });
    const reports = el("p", { class: "muted reports", hidden: true });
    app.replaceChildren(
      el("h1", { text: "Overview" }),
      el("p", { class: "muted", text: series.length + " series. Each cell is the newest round's median." }),
      agentLine,
      alertPanel,
      lossLegend(),
      el("div", { class: "scroll" }, table),
      reports
    );

    async function refresh() {
      const [data, alerts, agents] = await Promise.all([
        getJson("/api/v1/latest"),
        getJson("/api/v1/alerts"),
        getJson("/api/v1/agents").catch(() => null),
      ]);
      if (gen !== generation) return;
      showAlerts(alertPanel, alerts);
      if (agents) markAgents(heads, agentLine, agents, data.now, cells);
      if (reports.hidden) showReports(reports, alerts.now, alerts.slas && alerts.slas.length > 0);
      const alerting = new Map();
      const mark = (id, rule) => {
        if (!alerting.has(id)) alerting.set(id, []);
        alerting.get(id).push(rule);
      };
      for (const a of alerts.active) {
        if (!a.vantages || !a.vantages.length) {
          mark(a.series, a.rule);
          continue;
        }
        // One alert over several vantages: mark each that matched.
        for (const s of series) {
          if (s.target === a.target && s.family === a.family && a.vantages.includes(s.vantage)) mark(s.id, a.rule);
        }
      }
      const latest = new Map(data.latest.map((l) => [l.series, l]));
      for (const [id, c] of cells) {
        if (c.refused) continue;
        const l = latest.get(id);
        if (!l) {
          c.span.textContent = "–";
          c.span.title = "No round since the server started";
          c.span.classList.toggle("alerting", alerting.has(id));
          c.span.style.borderLeftColor = css("--stale");
          continue;
        }
        const loss = l.sent ? (l.sent - Math.min(l.recv, l.sent)) / l.sent : 0;
        const age = data.now - l.t;
        const stale = age > 3 * c.step_s * 1000 + 60e3;
        c.span.textContent = l.recv ? fmtMs(l.median_us) : "lost";
        c.span.style.borderLeftColor = css(stale ? "--stale" : lossToken(loss));
        const rules = alerting.get(id);
        c.span.classList.toggle("alerting", !!rules);
        c.span.title =
          (rules ? "Alert: " + rules.join(", ") + "\n" : "") +
          "loss " + fmtPct(loss) + " (" + l.recv + "/" + l.sent + ")" +
          (l.errors ? ", " + l.errors + " error(s)" : "") +
          (l.recv ? ", min " + fmtMs(l.min_us) + ", p90 " + fmtMs(l.p90_us) + ", max " + fmtMs(l.max_us) : "") +
          (l.mos !== undefined ? "\nMOS " + l.mos.toFixed(2) : "") +
          "\n" + fmtAge(age) + " ago" + (stale ? " (stale)" : "");
      }
    }
    poll(gen, refresh, OVERVIEW_REFRESH_MS);
  }

  // An agent's state in a few words, and as a class for its dot.
  function agentState(a, now) {
    if (a.revoked_ms) return { cls: "revoked", text: "revoked " + fmtTime(a.revoked_ms, true) };
    if (a.connected) return { cls: "up", text: "connected" + (a.connected_ms ? " for " + fmtAge(now - a.connected_ms) : "") };
    if (a.last_seen_ms) return { cls: "down", text: "disconnected, last seen " + fmtAge(now - a.last_seen_ms) + " ago" };
    return { cls: "down", text: "not connected since the server started" };
  }

  function dot(cls, title) {
    return el("span", { class: "dot " + cls, title, "aria-label": title });
  }

  // Overview: a dot in each agent's column head, and how many are up.
  // A series an agent will not measure says so in its cell, with why.
  function markAgents(heads, line, d, now, cells) {
    for (const c of cells.values()) c.refused = false;
    const agents = d.agents;
    if (!d.enabled) {
      line.hidden = true;
      return;
    }
    if (!agents.length) {
      line.replaceChildren(
        "No agents yet. ",
        el("a", { href: "#/agents", text: isAdmin() ? "Add one on the Agents page" : "Agents page" }),
        "."
      );
      line.hidden = false;
      return;
    }
    let up = 0;
    for (const a of agents) {
      for (const r of a.refused || []) {
        const c = cells.get(r.series);
        if (!c) continue;
        c.refused = true;
        c.span.textContent = "refused";
        c.span.title = a.name + " does not measure this: " + r.reason;
        c.span.classList.remove("alerting");
        c.span.style.borderLeftColor = css("--stale");
      }
      const st = agentState(a, now);
      if (st.cls === "up") up++;
      const th = heads.get(a.name);
      if (!th) continue;
      const title = "Agent " + a.name + ": " + st.text + (a.clock_skewed ? "; clock off by more than 100 ms" : "");
      th.replaceChildren(
        el("a", { href: "#/agents", title }, dot(st.cls + (a.clock_skewed ? " skewed" : ""), title), a.name)
      );
    }
    line.replaceChildren(
      el("a", { href: "#/agents", text: agents.length === 1 ? "1 agent" : agents.length + " agents" }),
      ", " + up + " connected."
    );
    line.hidden = false;
  }

  // Links to the reports (UTC months): the incident timeline of this
  // month, and the SLA reports of last month and this one so far.
  function showReports(p, now, slas) {
    const d = new Date(now);
    const month = (y, m) => {
      const t = new Date(Date.UTC(y, m, 1));
      return t.getUTCFullYear() + "-" + String(t.getUTCMonth() + 1).padStart(2, "0");
    };
    const last = month(d.getUTCFullYear(), d.getUTCMonth() - 1);
    const current = month(d.getUTCFullYear(), d.getUTCMonth());
    const link = (kind, m, format, text) =>
      el("a", { href: "/api/v1/reports/" + kind + "?month=" + m + "&format=" + format, target: "_blank", rel: "noopener", text });
    const parts = [
      "Incidents: ",
      link("incidents", current, "html", current), " (", link("incidents", current, "csv", "CSV"), ", ",
      link("incidents", current, "json", "JSON"), ") · ",
      link("incidents", last, "html", last),
    ];
    if (slas) {
      parts.push(
        " · SLA report: ",
        link("sla", last, "html", last), " (", link("sla", last, "csv", "CSV"), ") · ",
        link("sla", current, "html", current + " so far"), " (", link("sla", current, "csv", "CSV"), ")"
      );
    }
    p.replaceChildren(...parts);
    p.hidden = false;
  }

  // ---------- agents (§21.7 G12) ----------

  const AGENTS_REFRESH_MS = 15e3;

  function fmtBytes(b) {
    if (b === undefined || b === null) return "–";
    if (b < 1024) return b + " B";
    if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
    return (b / 1048576).toFixed(1) + " MB";
  }

  function fmtOffset(ms) {
    if (ms === undefined || ms === null) return "–";
    const a = Math.abs(ms);
    const t = a < 10 ? ms.toFixed(1) : String(Math.round(ms));
    return (ms > 0 ? "+" : "") + t + " ms";
  }

  async function showAgents(gen) {
    crumbs.replaceChildren(el("a", { href: "#/", text: "Overview" }), el("span", { text: "›" }), el("span", { text: "Agents" }));
    document.title = "Agents · Routelith";
    const tbody = el("tbody");
    const tokens = el("section", { class: "tokens", hidden: true });
    const enroll = isAdmin() ? enrollForm() : null;
    const intro = el("p", { class: "muted" });
    app.replaceChildren(
      el("h1", { text: "Agents" }),
      intro,
      el(
        "div",
        { class: "scroll" },
        el(
          "table",
          { class: "agents" },
          el(
            "thead",
            {},
            el(
              "tr",
              {},
              ...["Agent", "Status", "Address", "Version", "Measures", "Timing", "Clock", "Spool", "Lost rounds", "Last seen", ""].map((h) =>
                el("th", { text: h })
              )
            )
          ),
          tbody
        )
      ),
      tokens,
      enroll
    );
    // Revocation asks once more in its row; keep that row as it is
    // while it does.
    let confirming = null;

    async function refresh() {
      const d = await getJson("/api/v1/agents");
      if (gen !== generation) return;
      const now = Date.now();
      const byId = new Map(series.map((s) => [s.id, s]));
      const counts = new Map();
      for (const s of series) counts.set(s.vantage, (counts.get(s.vantage) || 0) + 1);
      intro.textContent = d.agents.length
        ? "Agents measure from other sites and report here. Each one's series are under its name in the overview."
        : "No agents yet. " + (isAdmin() ? "Add one below, or" : "An admin adds one here, or") + " on the server: routelith ctl agent add <name>.";
      if (confirming && d.agents.some((a) => a.name === confirming)) return showTokens(tokens, d.tokens, now);
      confirming = null;
      tbody.replaceChildren();
      for (const a of d.agents) {
        const st = agentState(a, now);
        const n = counts.get(a.name) || 0;
        const clock = el("td", { class: "num" + (a.clock_skewed ? " bad" : ""), text: fmtOffset(a.clock_offset_ms) });
        if (a.clock_offset_ms !== null && a.clock_offset_ms !== undefined) {
          clock.title =
            "Agent clock minus server clock, measured over a " + (a.clock_delay_ms ?? 0).toFixed(1) + " ms round trip" +
            (a.clock_skewed ? ". More than 100 ms off: its rounds' times are off by as much." : "");
        }
        const tr = el(
          "tr",
          { "data-agent": a.name },
          el("th", { scope: "row" }, el("strong", { text: a.name }), el("div", { class: "muted small", text: n === 1 ? "1 series" : n + " series" })),
          el("td", {}, dot(st.cls, st.text), st.text),
          el("td", { text: a.addr || "–" }),
          el("td", {}, a.version || "–", a.os ? el("div", { class: "muted small", text: a.os }) : null),
          el("td", { text: a.capabilities && a.capabilities.length ? a.capabilities.join(", ") : "–" }),
          el("td", { text: a.timing && a.timing.length ? a.timing.join("; ") : "–" }),
          clock,
          el(
            "td",
            { class: "num", title: "Rounds measured and not yet stored here, and the spool's size on the agent" },
            a.spool_backlog === null || a.spool_backlog === undefined ? "–" : a.spool_backlog + " waiting",
            el("div", { class: "muted small", text: fmtBytes(a.spool_bytes) })
          ),
          el("td", { class: "num" + (a.rounds_lost ? " bad" : ""), text: String(a.rounds_lost || 0), title: "Since the server started" }),
          el("td", { text: a.connected ? "now" : a.last_seen_ms ? fmtAge(now - a.last_seen_ms) + " ago" : "–" }),
          el("td", {}, isAdmin() && !a.revoked_ms ? revokeButton(a.name) : null)
        );
        tbody.append(tr);
        if (a.refused && a.refused.length) {
          tbody.append(
            el(
              "tr",
              { class: "refused" },
              el(
                "td",
                { colspan: 11 },
                el("strong", { text: "Not measured by " + a.name + ": " }),
                ...a.refused.flatMap((r, i) => {
                  const s = byId.get(r.series);
                  const what = s ? s.target + " (" + s.family + ")" : "series " + r.series;
                  return [i ? "; " : "", s ? el("a", { href: targetHref(s.target), text: what }) : what, " — " + r.reason];
                })
              )
            )
          );
        }
      }
      showTokens(tokens, d.tokens, now);
    }

    function revokeButton(name) {
      const cell = el("span");
      const ask = el("button", {
        class: "link",
        type: "button",
        text: "Revoke…",
        title: "Refuse this agent's certificate from now on",
        onclick: () => {
          confirming = name;
          const msg = el("span", { class: "error", role: "alert" });
          const yes = el("button", {
            class: "danger",
            type: "button",
            text: "Revoke " + name,
            onclick: async () => {
              yes.disabled = true;
              try {
                await send("DELETE", "/api/v1/agents/" + encodeURIComponent(name));
                confirming = null;
                refresh().catch(() => {});
              } catch (e) {
                if (e instanceof LoginNeeded) return route();
                msg.textContent = " " + e.message;
                yes.disabled = false;
              }
            },
          });
          cell.replaceChildren(
            yes,
            " ",
            el("button", {
              class: "link",
              type: "button",
              text: "Cancel",
              onclick: () => {
                confirming = null;
                refresh().catch(() => {});
              },
            }),
            msg
          );
          yes.focus();
        },
      });
      cell.append(ask);
      return cell;
    }

    function enrollForm() {
      const name = el("input", {
        id: "agent-name",
        "aria-label": "Agent name",
        placeholder: "plant-genk",
        required: true,
        maxlength: 64,
        pattern: "[A-Za-z0-9][A-Za-z0-9._\\-]*",
      });
      const ok = el("button", { type: "submit", text: "Make a token" });
      const msg = el("span", { class: "error", role: "alert" });
      const out = el("div", { class: "token", hidden: true });
      const form = el(
        "form",
        { class: "enroll", onsubmit: submit },
        el("label", { for: "agent-name", text: "Agent name" }),
        name,
        ok,
        msg
      );
      async function submit(ev) {
        ev.preventDefault();
        ok.disabled = true;
        msg.textContent = "";
        try {
          const t = await send("POST", "/api/v1/agents/enroll-token", { name: name.value.trim() });
          const code = el("code", { class: "secret", text: t.token });
          const copy = el("button", {
            class: "link",
            type: "button",
            text: "Copy",
            onclick: async () => {
              try {
                await navigator.clipboard.writeText(t.token);
                copy.textContent = "Copied";
              } catch (_) {
                copy.textContent = "Select the token and copy it";
              }
            },
          });
          out.replaceChildren(
            el("p", {}, "Enrollment token for ", el("strong", { text: t.name }), ", works once, until " + fmtTime(t.expires_ms, true) + ":"),
            el("p", {}, code, " ", copy),
            el("p", { class: "muted", text: "On the agent: routelith agent enroll --config agent.toml --token <token>, then routelith agent run --config agent.toml." }),
            el("p", {
              class: "muted",
              text: "Groups with vantages = [\"*\"] take in the new agent after the server restarts. The token is shown only now.",
            })
          );
          out.hidden = false;
          name.value = "";
          refresh().catch(() => {});
        } catch (e) {
          if (e instanceof LoginNeeded) return route();
          msg.textContent = e.message;
        } finally {
          ok.disabled = false;
        }
      }
      return el("section", { class: "enroll" }, el("h2", { text: "Add an agent" }), form, out);
    }

    poll(gen, refresh, AGENTS_REFRESH_MS);
  }

  function showTokens(panel, tokens, now) {
    panel.hidden = !tokens || !tokens.length;
    if (panel.hidden) return;
    panel.replaceChildren(
      el("h2", { text: "Tokens not used yet" }),
      el(
        "ul",
        {},
        ...tokens.map((t) => el("li", {}, el("strong", { text: t.name }), el("span", { class: "muted", text: " valid until " + fmtTime(t.expires_ms, t.expires_ms - now > 20 * 3600e3) })))
      )
    );
  }

  // ---------- alerts (§12) ----------

  // A rule's value as the API gives it: ms, percent or MOS.
  function fmtValue(rule, v, rules) {
    if (v === undefined || v === null) return "";
    const r = rules.find((x) => x.name === rule);
    const s = r ? r.summary : "";
    if (/^(loss|loss pattern)/.test(s)) return v + " %";
    if (/^mos /.test(s)) return "MOS " + v;
    return v + " ms";
  }

  function showAlerts(panel, data) {
    // Leave an open silence form alone until it is sent or closed.
    if (panel.querySelector("form.silence")) return;
    const list = data.active;
    const silences = silenceList(panel, data);
    panel.hidden = list.length === 0 && silences.length === 0;
    if (panel.hidden) return;
    if (!list.length) {
      panel.replaceChildren(...silences);
      return;
    }
    panel.replaceChildren(
      el("h2", { text: list.length === 1 ? "1 alert raised" : list.length + " alerts raised" }),
      el(
        "ul",
        {},
        ...list.map((a) => {
          const summary = (data.rules.find((r) => r.name === a.rule) || {}).summary;
          const li = el(
            "li",
            {},
            el("a", { href: targetHref(a.target), text: a.target }),
            el("span", { class: "badge", text: a.family }),
            " ",
            el("strong", { text: a.rule, title: summary || "" }),
            el("span", {
              class: "muted",
              text:
                " since " + fmtTime(a.since, data.now - a.since > 20 * 3600e3) +
                " (" + fmtAge(data.now - a.since) + ")" +
                (a.value !== undefined ? ", " + fmtValue(a.rule, a.value, data.rules) : ""),
            }),
            ...(a.vantages && a.vantages.length
              ? [" ", el("span", { class: "badge vantages", text: "from " + a.vantages.join(", "), title: "The vantages that saw it at once" })]
              : []),
            ...(a.silenced_by
              ? [" ", el("span", { class: "badge quiet", text: "silenced: " + a.silenced_by, title: "Logged, not sent" })]
              : []),
            ...(a.suppressed_by
              ? [" ", el("span", { class: "badge quiet", text: "suppressed: parent " + a.suppressed_by + " had an alert", title: "Logged, not sent" })]
              : [])
          );
          if (canSilence() && !a.silenced_by) {
            li.append(
              " ",
              el("button", {
                class: "link",
                type: "button",
                text: "Silence…",
                title: "Stop sending this alert, and its clear, for a while",
                onclick: () => silenceForm(panel, li, a),
              })
            );
          }
          return li;
        })
      ),
      ...silences
    );
  }

  // A form under an alert to silence its rule on its target.
  function silenceForm(panel, li, a) {
    if (panel.querySelector("form.silence")) return;
    const minutes = el(
      "select",
      { "aria-label": "For how long" },
      ...[
        [60, "1 hour"],
        [240, "4 hours"],
        [1440, "24 hours"],
        [10080, "7 days"],
      ].map(([m, label]) => el("option", { value: m, text: label, selected: m === 240 }))
    );
    const comment = el("input", { "aria-label": "Why", placeholder: "Why (kept with the silence)", required: true, maxlength: 500 });
    const msg = el("span", { class: "error", role: "alert" });
    const ok = el("button", { type: "submit", text: "Silence" });
    const form = el(
      "form",
      { class: "silence", onsubmit: submit },
      "Silence " + a.rule + " on " + a.target + " for ",
      minutes,
      " ",
      comment,
      " ",
      ok,
      " ",
      el("button", { class: "link", type: "button", text: "Cancel", onclick: close }),
      " ",
      msg
    );
    li.append(form);
    comment.focus();

    function close() {
      form.remove();
      reload(panel);
    }

    async function submit(ev) {
      ev.preventDefault();
      ok.disabled = true;
      msg.textContent = "";
      try {
        await send("POST", "/api/v1/silences", {
          targets: [a.target],
          alerts: [a.rule],
          minutes: Number(minutes.value),
          comment: comment.value,
        });
        close();
      } catch (e) {
        if (e instanceof LoginNeeded) return route();
        msg.textContent = e.message;
        ok.disabled = false;
      }
    }
  }

  async function reload(panel) {
    try {
      showAlerts(panel, await getJson("/api/v1/alerts"));
    } catch (e) {
      if (e instanceof LoginNeeded) route();
    }
  }

  // The silences in force now, and those added here that are still to
  // come, with a way to end the added ones for an operator.
  function silenceList(panel, data) {
    const shown = (data.silences || []).filter(
      (x) => x.active || (x.source === "ui" && x.start > data.now)
    );
    if (!shown.length) return [];
    return [
      el("h3", { text: "Silences" }),
      el(
        "ul",
        { class: "silences" },
        ...shown.map((x) => {
          const li = el(
            "li",
            {},
            el("strong", { text: x.name }),
            el("span", {
              class: "muted",
              text:
                " " + (x.source === "ui" ? untilText(x, data.now) : x.summary) +
                (x.by ? ", by " + x.by : "") +
                (x.comment ? ": " + x.comment : ""),
            })
          );
          if (x.source === "ui" && canSilence()) {
            const msg = el("span", { class: "error", role: "alert" });
            li.append(
              " ",
              el("button", {
                class: "link",
                type: "button",
                text: "End",
                onclick: async () => {
                  try {
                    await send("DELETE", "/api/v1/silences/" + encodeURIComponent(x.name));
                    reload(panel);
                  } catch (e) {
                    if (e instanceof LoginNeeded) return route();
                    msg.textContent = " " + e.message;
                  }
                },
              }),
              msg
            );
          }
          return li;
        })
      ),
    ];
  }

  function untilText(x, now) {
    const what = (x.targets.concat(x.groups).join(", ") || "all targets") + (x.alerts.length ? " (" + x.alerts.join(", ") + ")" : "");
    if (x.start > now) return what + ", from " + fmtTime(x.start, true) + " until " + fmtTime(x.end, true);
    // With the date when it ends on another day than today.
    const otherDay = new Date(x.end).toDateString() !== new Date(now).toDateString();
    return what + ", until " + fmtTime(x.end, otherDay);
  }

  // Events of one target in the shown range, newest first.
  function showEvents(panel, data, name, from, to) {
    const mine = data.events.filter((e) => e.target === name && e.t >= from && e.t <= to);
    panel.hidden = mine.length === 0;
    if (!mine.length) return;
    panel.replaceChildren(
      el("h2", { text: "Events" }),
      el(
        "ul",
        { class: "changes" },
        ...mine.slice(0, 50).map((e) =>
          el(
            "li",
            { class: "event-" + e.kind },
            el("span", { class: "muted", text: fmtTime(e.t, to - from > 20 * 3600e3) + " " }),
            e.message
          )
        )
      ),
      ...(mine.length > 50 || data.truncated
        ? [
            el(
              "p",
              { class: "muted" },
              "Only the newest 50 events are shown. ",
              el("a", {
                href:
                  "/api/v1/events?target=" + encodeURIComponent(name) +
                  "&from=" + Math.floor(from) + "&to=" + (Math.floor(to) + 1) + "&limit=5000",
                text: "Up to 5000 of this range",
              }),
              " are in the API; for more, ask for a shorter range."
            ),
          ]
        : [])
    );
  }

  // ---------- target view (§20.2) ----------

  async function showTarget(name, range, shared, gen) {
    const list = series
      .filter((s) => s.target === name)
      .sort((a, b) => a.vantage.localeCompare(b.vantage) || a.family.localeCompare(b.family));
    crumbs.replaceChildren(el("a", { href: "#/", text: "Overview" }), el("span", { text: "›" }), el("span", { text: name }));
    document.title = name + " · Routelith";
    if (!list.length) {
      app.replaceChildren(el("p", { class: "note", text: "No target named " + name + "." }));
      return;
    }
    const first = list[0];
    const ranges = el(
      "div",
      { class: "ranges", role: "group", "aria-label": "Time range" },
      ...RANGES.map((r) => el("button", { type: "button", "aria-pressed": r === range ? "true" : "false", text: r, onclick: () => (location.hash = targetHref(name, r, shared)) }))
    );
    // With more than one graph, one y-axis for all of them makes the
    // vantages comparable at a glance (§21.7 G12).
    const vantages = [...new Set(list.map((s) => s.vantage))];
    const yToggle =
      list.length > 1
        ? el(
            "label",
            { class: "toggle" },
            el("input", {
              type: "checkbox",
              checked: shared,
              onchange: (ev) => (location.hash = targetHref(name, range, ev.target.checked)),
            }),
            " Same y-axis for every graph"
          )
        : null;
    // Each vantage's health snapshots (§19; agents send theirs, G10),
    // shared by its graphs.
    const hosts = new Map(vantages.map((v) => [v, { data: null, panel: el("section", { class: "host", hidden: true }) }]));
    async function loadHost() {
      const width = Math.max(200, Math.round(app.clientWidth || 800));
      await Promise.all(
        vantages.map(async (v) => {
          const h = hosts.get(v);
          try {
            const d = await getJson(
              "/api/v1/health?range=" + range + "&points=" + Math.min(5000, width) + "&vantage=" + encodeURIComponent(v)
            );
            if (gen !== generation) return;
            h.data = d;
          } catch (_) {
            h.data = null;
          }
          showHost(h.panel, h.data, list);
        })
      );
    }
    // Which vantages are agents, and whether they are connected.
    async function loadAgents() {
      if (vantages.every((v) => v === serverVantage)) return;
      let d;
      try {
        d = await getJson("/api/v1/agents");
      } catch (_) {
        return;
      }
      if (gen !== generation) return;
      const now = Date.now();
      const by = new Map(d.agents.map((a) => [a.name, a]));
      for (const g of graphs) g.setAgent(by.get(g.vantage), now);
    }
    const graphs = list.map((s) => makeGraph(s, range, gen, hosts.get(s.vantage)));
    const eventPanel = el("section", { class: "events", hidden: true });
    async function loadEvents() {
      const to = Date.now();
      const from = to - RANGE_MS[range];
      try {
        const d = await getJson(
          "/api/v1/events?from=" + Math.floor(from) + "&to=" + (to + 1) + "&limit=500&target=" + encodeURIComponent(name)
        );
        if (gen !== generation) return;
        showEvents(eventPanel, d, name, from, to);
      } catch (_) {
        eventPanel.hidden = true;
      }
    }
    app.replaceChildren(
      el("h1", { text: name }),
      el(
        "p",
        { class: "muted" },
        "group " + first.group + " · " + first.probe + " · " + (first.url || first.host) + " · every " + fmtStep(first.step_s) + ", " + first.pings + " samples per round"
      ),
      el("div", { class: "controls" }, ranges, yToggle),
      lossLegend(),
      ...graphs.map((g) => g.root),
      eventPanel,
      ...vantages.map((v) => hosts.get(v).panel)
    );
    // A graph that fails keeps its last data (or its error) while the
    // others show theirs; the next refresh tries it again.
    async function refresh() {
      await Promise.all([loadHost(), loadEvents(), loadAgents()]);
      if (gen !== generation) return;
      const results = await Promise.allSettled(graphs.map((g) => g.load()));
      if (shared && gen === generation) {
        const top = Math.max(0, ...graphs.map((g) => g.ownTop()));
        for (const g of graphs) g.setTop(top);
      }
      const failed = results.find((r) => r.status === "rejected");
      if (failed) throw failed.reason;
    }
    poll(gen, refresh, GRAPH_REFRESH_MS);
  }

  // Health of a vantage at time t: the bucket holding t and the network
  // state in force then.
  function healthAt(h, t) {
    if (!h) return null;
    let point = null;
    for (const p of h.points) {
      if (t >= p.t && t < p.t + h.width_ms) point = p;
    }
    let net = null;
    for (const n of h.network) {
      if (n.t <= t) net = n;
    }
    if (!net && h.network.length) net = h.network[0];
    return point || net ? { point, net } : null;
  }

  function addrs(list) {
    return list && list.length ? list.join(", ") : "none";
  }

  function showHost(panel, h, list) {
    if (!h || !list.some((s) => s.vantage === h.vantage)) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    let cpu = null;
    let errors = 0;
    let drops = 0;
    for (const p of h.points) {
      if (p.cpu_pct !== undefined) cpu = Math.max(cpu === null ? 0 : cpu, p.cpu_pct);
      errors += p.nic_errors || 0;
      drops += p.nic_drops || 0;
    }
    const now = h.network.length ? h.network[h.network.length - 1] : null;
    const items = [
      el("h2", { text: h.vantage === serverVantage ? "This machine (" + h.vantage + ")" : "Agent " + h.vantage }),
      el(
        "p",
        { class: "host-summary" },
        h.points.length
          ? (cpu === null ? "CPU not measured yet" : "busiest CPU minute " + cpu.toFixed(0) + " %") + " · NIC errors " + errors + " · drops " + drops +
            (errors + drops ? " (red ticks along the bottom of the graphs)" : "")
          : "No health snapshots in this range yet (one is taken each minute)."
      ),
    ];
    if (now) {
      items.push(el("p", { class: "muted", text: "gateway " + addrs(now.gateways) + " · DNS " + addrs(now.dns) }));
    }
    const changes = h.network.slice(1);
    if (changes.length) {
      const ul = el("ul", { class: "changes" });
      let prev = h.network[0];
      for (const c of changes) {
        const what = [];
        if (addrs(prev.gateways) !== addrs(c.gateways)) what.push("gateway " + addrs(prev.gateways) + " → " + addrs(c.gateways));
        if (addrs(prev.dns) !== addrs(c.dns)) what.push("DNS " + addrs(prev.dns) + " → " + addrs(c.dns));
        ul.append(el("li", { text: fmtTime(c.t, true) + ": " + what.join(", ") }));
        prev = c;
      }
      items.push(el("p", { class: "muted", text: "Network changes, marked on the graphs:" }), ul);
    }
    panel.replaceChildren(...items);
  }

  function makeGraph(s, range, gen, host) {
    const canvas = el("canvas", { role: "img", "aria-label": "Smoke graph of " + s.target + " (" + s.family + ") from " + s.vantage });
    const tip = el("div", { class: "tip", hidden: true });
    const summary = el("div", { class: "summary", text: "Loading…" });
    const svg = el("a", { href: "/api/v1/render/" + s.id + ".svg?range=" + range, target: "_blank", rel: "noopener", text: "SVG" });
    // For an agent's graph: a word when it is not connected now.
    const agentNote = el("span", { class: "agent-note", hidden: true });
    // The shared y-axis top (ms), when the view has one.
    let sharedTop = null;
    const root = el(
      "section",
      { class: "graph", "data-series": s.id },
      el("div", { class: "head" }, el("strong", { text: s.family + " from " + s.vantage }), agentNote, el("span", { class: "meta" }, "series " + s.id + " · ", svg)),
      el("div", { class: "plot" }, canvas, tip),
      summary
    );
    let data = null;
    let layout = null;

    async function load() {
      if (gen !== generation) return;
      const width = Math.max(200, Math.round(canvas.clientWidth || 800));
      let d;
      try {
        d = await getJson("/api/v1/series/" + s.id + "/data?range=" + range + "&points=" + Math.min(5000, width));
      } catch (e) {
        if (gen === generation && !data) summary.textContent = "Could not load: " + e.message;
        throw e;
      }
      if (gen !== generation) return;
      data = d;
      draw();
      summarise();
    }

    function summarise() {
      const pts = data.points;
      let sent = 0;
      let recv = 0;
      let rounds = 0;
      const medians = [];
      const scores = [];
      for (const p of pts) {
        if (p.mos !== undefined) scores.push(p.mos);
        sent += p.sent;
        recv += p.recv;
        rounds += p.n;
        const m = medianOf(p.q);
        if (m !== null) medians.push(m);
      }
      medians.sort((a, b) => a - b);
      scores.sort((a, b) => a - b);
      const mos = scores.length ? scores[Math.floor((scores.length - 1) / 2)] : null;
      const med = medians.length ? medians[Math.floor((medians.length - 1) / 2)] : null;
      const res =
        data.resolution !== "raw"
          ? data.resolution === "r1h" ? "hourly" : "daily"
          : pts.some((p) => p.n > 1)
            ? "every round, in " + fmtStep(data.width_ms / 1000) + " columns"
            : "every round";
      summary.textContent = pts.length
        ? "median " + fmtMs(med) + " · loss " + fmtPct(sent ? (sent - recv) / sent : 0) +
          (mos !== null ? " · MOS " + mos.toFixed(2) : "") + " · " + rounds + " rounds · " + res
        : "No data in this range yet.";
      canvas.dataset.points = String(pts.length);
      canvas.dataset.range = range;
    }

    function draw() {
      if (!data) return;
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (!w || !h) return;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      const ctx = canvas.getContext("2d");
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const L = 64, R = 12, T = 8, B = 22;
      const pw = Math.max(10, w - L - R);
      const ph = Math.max(10, h - T - B);
      const from = data.from;
      const to = data.to;
      const x = (t) => L + ((t - from) / (to - from)) * pw;

      const top = sharedTop !== null ? Math.max(sharedTop, ownTop()) : ownTop();
      const tick = niceStep(top, 4);
      const yMax = Math.ceil(top / tick) * tick;
      const y = (ms) => T + ph - (Math.min(ms, yMax) / yMax) * ph;
      // Columns as drawn, for the hover tip.
      const cols = [];
      layout = { L, T, pw, ph, x, from, to, cols };

      ctx.font = "11px system-ui, sans-serif";
      ctx.fillStyle = css("--muted");
      ctx.strokeStyle = css("--grid");
      ctx.lineWidth = 1;
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      for (let v = 0; v <= yMax + tick / 2; v += tick) {
        const yy = Math.round(y(v)) + 0.5;
        ctx.beginPath();
        ctx.moveTo(L, yy);
        ctx.lineTo(L + pw, yy);
        ctx.stroke();
        ctx.fillText(fmtTick(v, tick) + " ms", L - 6, yy);
      }
      const span = to - from;
      const xs = xStep(span, pw);
      const offset = new Date(to).getTimezoneOffset() * 60e3;
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      for (let t = Math.ceil((from - offset) / xs) * xs + offset; t < to; t += xs) {
        const xx = Math.round(x(t)) + 0.5;
        ctx.beginPath();
        ctx.moveTo(xx, T);
        ctx.lineTo(xx, T + ph);
        ctx.stroke();
        ctx.fillText(fmtTime(t, xs >= 86400e3 || span > 86400e3), xx, T + ph + 5);
      }

      // The frame goes under the columns, so a column at the right edge
      // (the newest round) stays visible.
      ctx.strokeStyle = css("--frame");
      ctx.strokeRect(L + 0.5, T + 0.5, pw - 1, ph - 1);

      // Columns: all-lost bars, smoke pairs from the outside in, then the
      // median coloured by loss.
      const wms = data.width_ms;
      const smoke = css("--smoke");
      const lost = css("--lost");
      for (const p of data.points) {
        let x0 = x(Math.max(p.t, from));
        const x1 = x(Math.min(p.t + wms, to));
        const bw = Math.min(pw, Math.max(0.75, x1 - x0));
        x0 = Math.min(x0, L + pw - bw);
        cols.push({ x0, x1: x0 + bw, p });
        const k = p.q.length;
        if (!k) {
          if (p.sent > 0) {
            ctx.fillStyle = lost;
            ctx.fillRect(x0, T, bw, ph);
          }
          continue;
        }
        const pairs = Math.floor(k / 2);
        if (pairs) {
          ctx.fillStyle = smoke;
          ctx.globalAlpha = SMOKE_OPACITY / pairs;
          for (let i = 0; i < pairs; i++) {
            const y0 = y(p.q[k - 1 - i] / 1000);
            const y1 = y(p.q[i] / 1000);
            ctx.fillRect(x0, y0, bw, Math.max(0.5, y1 - y0));
          }
          ctx.globalAlpha = 1;
        }
        const loss = p.sent ? (p.sent - Math.min(p.recv, p.sent)) / p.sent : 0;
        ctx.fillStyle = css(lossToken(loss));
        ctx.fillRect(x0, y(medianOf(p.q) / 1000) - 1, bw, 2);
      }

      // This machine's health: a tick under minutes with NIC errors or
      // drops, a dashed line where the gateway or DNS servers changed.
      const hd = host.data;
      if (hd && hd.vantage === s.vantage) {
        ctx.fillStyle = css("--nic");
        for (const p of hd.points) {
          if (!((p.nic_errors || 0) + (p.nic_drops || 0)) || p.t + hd.width_ms <= from || p.t >= to) continue;
          const x0 = x(Math.max(p.t, from));
          const bw = Math.max(2, x(Math.min(p.t + hd.width_ms, to)) - x0);
          ctx.fillRect(Math.min(x0, L + pw - bw), T + ph - 4, bw, 4);
        }
        ctx.strokeStyle = css("--change");
        ctx.setLineDash([4, 3]);
        for (const c of hd.network.slice(1)) {
          if (c.t < from || c.t >= to) continue;
          const xx = Math.round(x(c.t)) + 0.5;
          ctx.beginPath();
          ctx.moveTo(xx, T);
          ctx.lineTo(xx, T + ph);
          ctx.stroke();
        }
        ctx.setLineDash([]);
      }
    }

    // Y range from the highest p90 (the 18th of 20 quantiles), so a few
    // outliers are clipped instead of flattening the graph; in ms.
    function ownTop() {
      if (!data) return 0;
      let top = 0;
      for (const p of data.points) {
        if (p.q.length) top = Math.max(top, p.q[Math.floor((p.q.length - 1) * 0.9)]);
      }
      return Math.max(top / 1000, 0.1) * 1.1;
    }

    function setTop(t) {
      sharedTop = t;
      canvas.dataset.top = String(t);
      draw();
    }

    function setAgent(a, now) {
      if (!a) {
        agentNote.hidden = true;
        return;
      }
      const st = agentState(a, now);
      agentNote.hidden = st.cls === "up" && !a.clock_skewed;
      agentNote.replaceChildren(
        dot(st.cls, st.text),
        el("a", { href: "#/agents", text: st.cls === "up" ? "clock off by " + fmtOffset(a.clock_offset_ms) : "agent " + st.text })
      );
    }

    function pointAt(px) {
      if (!data || !layout) return null;
      // The drawn column under the pointer, or the nearest within 3 px, so
      // a column narrower than a pixel (the newest) can still be hovered.
      let best = null;
      let dist = 3;
      for (const c of layout.cols) {
        const d = px < c.x0 ? c.x0 - px : px > c.x1 ? px - c.x1 : 0;
        if (d <= dist) {
          best = c.p;
          dist = d;
        }
      }
      return best;
    }

    canvas.addEventListener("mousemove", (ev) => {
      const r = canvas.getBoundingClientRect();
      const px = ev.clientX - r.left;
      const p = pointAt(px);
      if (!p) {
        tip.hidden = true;
        return;
      }
      const loss = p.sent ? (p.sent - Math.min(p.recv, p.sent)) / p.sent : 0;
      const hd = host.data && host.data.vantage === s.vantage ? healthAt(host.data, p.t) : null;
      const healthLines = [];
      if (hd && hd.point) {
        const q = hd.point;
        healthLines.push(
          el("div", {
            class: "tip-host",
            text: (s.vantage === serverVantage ? "this machine" : s.vantage) + ": CPU " + (q.cpu_pct === undefined ? "–" : q.cpu_pct.toFixed(0) + " %") + " · NIC errors " + (q.nic_errors ?? "–") + " · drops " + (q.nic_drops ?? "–"),
          })
        );
      }
      if (hd && hd.net) {
        healthLines.push(el("div", { class: "tip-host", text: "gateway " + addrs(hd.net.gateways) + " · DNS " + addrs(hd.net.dns) }));
      }
      tip.replaceChildren(
        el("div", { text: fmtTime(p.t, true) + (p.n > 1 ? " (" + p.n + " rounds)" : "") }),
        el("div", { text: p.q.length ? "median " + fmtMs(medianOf(p.q)) + " · " + fmtMs(p.q[0]) + " – " + fmtMs(p.q[p.q.length - 1]) : "all lost" }),
        el("div", { text: "loss " + fmtPct(loss) + " (" + p.recv + "/" + p.sent + ")" + (p.mos !== undefined ? " · MOS " + p.mos.toFixed(2) : "") }),
        ...healthLines
      );
      tip.hidden = false;
      const left = Math.min(px + 12, r.width - tip.offsetWidth - 4);
      tip.style.left = Math.max(0, left) + "px";
      tip.style.top = ev.clientY - r.top + 12 + "px";
    });
    canvas.addEventListener("mouseleave", () => (tip.hidden = true));

    if (window.ResizeObserver) {
      let lastWidth = 0;
      const ro = new ResizeObserver(() => {
        if (canvas.clientWidth !== lastWidth) {
          lastWidth = canvas.clientWidth;
          draw();
        }
      });
      ro.observe(canvas);
      observers.push(ro);
    }
    // Removed with the view, so a retired graph is not kept alive.
    const theme = window.matchMedia("(prefers-color-scheme: dark)");
    theme.addEventListener("change", draw);
    observers.push({ disconnect: () => theme.removeEventListener("change", draw) });
    return { root, load, ownTop, setTop, setAgent, vantage: s.vantage };
  }

  function niceStep(max, ticks) {
    const raw = Math.max(max / ticks, 1e-6);
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const n = raw / mag;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * mag;
  }

  function fmtTick(v, tick) {
    const d = tick >= 1 ? 0 : Math.min(3, Math.ceil(-Math.log10(tick) + 1e-9) + (tick * Math.pow(10, Math.ceil(-Math.log10(tick))) % 1 ? 1 : 0));
    return v.toFixed(d);
  }

  // Grid spacing for about one line per 100 px.
  function xStep(span, pw) {
    const steps = [5, 10, 15, 30, 60, 120, 180, 360, 720, 1440, 2880, 10080].map((m) => m * 60e3);
    const want = span / Math.max(2, pw / 100);
    return steps.find((s) => s >= want) || steps[steps.length - 1];
  }

  window.addEventListener("hashchange", route);
  route();
})();
