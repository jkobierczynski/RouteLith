// Routelith web UI (architecture doc §20): an overview matrix and a target
// view of canvas smoke graphs, read from /api/v1. Plain JavaScript with no
// build step; the server embeds this file. Read-only: nothing here writes.
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
  let series = null; // from /api/v1/series, loaded once
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

  async function getJson(url) {
    const r = await fetch(url, { headers: { Accept: "application/json" } });
    let body = null;
    try {
      body = await r.json();
    } catch (_) {
      /* not JSON */
    }
    if (!r.ok) throw new Error((body && body.error) || r.status + " " + r.statusText);
    return body;
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
    if (timer) clearInterval(timer);
    timer = null;
    while (observers.length) observers.pop().disconnect();
  }

  async function loadSeries() {
    if (!series) {
      const [s, h] = await Promise.all([getJson("/api/v1/series"), getJson("/healthz")]);
      series = s.series;
      document.getElementById("vantage").textContent =
        "vantage " + h.vantage + " · v" + h.version;
    }
    return series;
  }

  // ---------- routing ----------

  function parseHash() {
    const h = location.hash.replace(/^#/, "") || "/";
    const [path, query] = h.split("?");
    const params = new URLSearchParams(query || "");
    const m = path.match(/^\/target\/(.+)$/);
    if (m) {
      let name;
      try {
        name = decodeURIComponent(m[1]);
      } catch (_) {
        name = m[1];
      }
      const range = RANGES.includes(params.get("range")) ? params.get("range") : "3h";
      return { view: "target", name, range };
    }
    return { view: "overview" };
  }

  function targetHref(name, range) {
    return "#/target/" + encodeURIComponent(name) + (range && range !== "3h" ? "?range=" + range : "");
  }

  async function route() {
    stop();
    const r = parseHash();
    const gen = generation;
    try {
      await loadSeries();
      if (gen !== generation) return;
      if (r.view === "target") await showTarget(r.name, r.range, gen);
      else await showOverview(gen);
    } catch (e) {
      if (gen !== generation) return;
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
    const table = el(
      "table",
      { class: "matrix" },
      el("thead", {}, el("tr", {}, el("th", { text: "Target" }), ...vantages.map((v) => el("th", { class: "cell", text: v })))),
      tbody
    );
    app.replaceChildren(
      el("h1", { text: "Overview" }),
      el("p", { class: "muted", text: series.length + " series. Each cell is the newest round's median." }),
      lossLegend(),
      el("div", { class: "scroll" }, table)
    );

    async function refresh() {
      const data = await getJson("/api/v1/latest");
      if (gen !== generation) return;
      const latest = new Map(data.latest.map((l) => [l.series, l]));
      for (const [id, c] of cells) {
        const l = latest.get(id);
        if (!l) {
          c.span.textContent = "–";
          c.span.title = "No round since the server started";
          c.span.style.borderLeftColor = css("--stale");
          continue;
        }
        const loss = l.sent ? (l.sent - Math.min(l.recv, l.sent)) / l.sent : 0;
        const age = data.now - l.t;
        const stale = age > 3 * c.step_s * 1000 + 60e3;
        c.span.textContent = l.recv ? fmtMs(l.median_us) : "lost";
        c.span.style.borderLeftColor = css(stale ? "--stale" : lossToken(loss));
        c.span.title =
          "loss " + fmtPct(loss) + " (" + l.recv + "/" + l.sent + ")" +
          (l.errors ? ", " + l.errors + " error(s)" : "") +
          (l.recv ? ", min " + fmtMs(l.min_us) + ", p90 " + fmtMs(l.p90_us) + ", max " + fmtMs(l.max_us) : "") +
          "\n" + fmtAge(age) + " ago" + (stale ? " (stale)" : "");
      }
      setStatus("updated " + fmtTime(Date.now()));
    }
    await refresh();
    timer = setInterval(() => refresh().catch((e) => setStatus("update failed: " + e.message)), OVERVIEW_REFRESH_MS);
  }

  // ---------- target view (§20.2) ----------

  async function showTarget(name, range, gen) {
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
      ...RANGES.map((r) => el("button", { type: "button", "aria-pressed": r === range ? "true" : "false", text: r, onclick: () => (location.hash = targetHref(name, r)) }))
    );
    const graphs = list.map((s) => makeGraph(s, range, gen));
    app.replaceChildren(
      el("h1", { text: name }),
      el(
        "p",
        { class: "muted" },
        "group " + first.group + " · " + first.probe + " · " + (first.url || first.host) + " · every " + fmtStep(first.step_s) + ", " + first.pings + " samples per round"
      ),
      ranges,
      lossLegend(),
      ...graphs.map((g) => g.root)
    );
    await Promise.all(graphs.map((g) => g.load()));
    if (gen !== generation) return;
    setStatus("updated " + fmtTime(Date.now()));
    timer = setInterval(() => {
      Promise.all(graphs.map((g) => g.load()))
        .then(() => setStatus("updated " + fmtTime(Date.now())))
        .catch((e) => setStatus("update failed: " + e.message));
    }, GRAPH_REFRESH_MS);
  }

  function makeGraph(s, range, gen) {
    const canvas = el("canvas", { role: "img", "aria-label": "Smoke graph of " + s.target + " (" + s.family + ") from " + s.vantage });
    const tip = el("div", { class: "tip", hidden: true });
    const summary = el("div", { class: "summary", text: "Loading…" });
    const svg = el("a", { href: "/api/v1/render/" + s.id + ".svg?range=" + range, target: "_blank", rel: "noopener", text: "SVG" });
    const root = el(
      "section",
      { class: "graph", "data-series": s.id },
      el("div", { class: "head" }, el("strong", { text: s.family + " from " + s.vantage }), el("span", { class: "meta" }, "series " + s.id + " · ", svg)),
      el("div", { class: "plot" }, canvas, tip),
      summary
    );
    let data = null;
    let layout = null;

    async function load() {
      const width = Math.max(200, Math.round(canvas.clientWidth || 800));
      const d = await getJson("/api/v1/series/" + s.id + "/data?range=" + range + "&points=" + Math.min(5000, width));
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
      for (const p of pts) {
        sent += p.sent;
        recv += p.recv;
        rounds += p.n;
        const m = medianOf(p.q);
        if (m !== null) medians.push(m);
      }
      medians.sort((a, b) => a - b);
      const med = medians.length ? medians[Math.floor((medians.length - 1) / 2)] : null;
      const res =
        data.resolution !== "raw"
          ? data.resolution === "r1h" ? "hourly" : "daily"
          : pts.some((p) => p.n > 1)
            ? "every round, in " + fmtStep(data.width_ms / 1000) + " columns"
            : "every round";
      summary.textContent = pts.length
        ? "median " + fmtMs(med) + " · loss " + fmtPct(sent ? (sent - recv) / sent : 0) + " · " + rounds + " rounds · " + res
        : "No data in this range yet.";
      canvas.dataset.points = String(pts.length);
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

      // Y range from the highest p90 (the 18th of 20 quantiles), so a few
      // outliers are clipped instead of flattening the graph.
      let top = 0;
      for (const p of data.points) {
        if (p.q.length) top = Math.max(top, p.q[Math.floor((p.q.length - 1) * 0.9)]);
      }
      top = Math.max(top / 1000, 0.1) * 1.1;
      const tick = niceStep(top, 4);
      const yMax = Math.ceil(top / tick) * tick;
      const y = (ms) => T + ph - (Math.min(ms, yMax) / yMax) * ph;
      layout = { L, T, pw, ph, x, from, to };

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
    }

    function pointAt(px) {
      if (!data || !layout) return null;
      const t = layout.from + ((px - layout.L) / layout.pw) * (layout.to - layout.from);
      let best = null;
      for (const p of data.points) {
        if (t >= p.t && t < p.t + data.width_ms) best = p;
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
      tip.replaceChildren(
        el("div", { text: fmtTime(p.t, true) + (p.n > 1 ? " (" + p.n + " rounds)" : "") }),
        el("div", { text: p.q.length ? "median " + fmtMs(medianOf(p.q)) + " · " + fmtMs(p.q[0]) + " – " + fmtMs(p.q[p.q.length - 1]) : "all lost" }),
        el("div", { text: "loss " + fmtPct(loss) + " (" + p.recv + "/" + p.sent + ")" })
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
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", draw);
    return { root, load };
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
