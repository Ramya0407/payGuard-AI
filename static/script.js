const COLORS = { Low: "#22c55e", Medium: "#f59e0b", High: "#ef4444" };
const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function bars(container, items, max, colorFn) {
  container.replaceChildren();
  if (!items.length) { container.append(el("p", "muted sm", "No data yet.")); return; }
  items.forEach((it) => {
    const row = el("div", "brow");
    const lbl = el("div", "lbl");
    lbl.append(el("span", "", it.label), el("span", "", String(it.count)));
    const bar = el("div", "bar");
    const fill = el("div", colorFn(it));
    fill.style.width = (max ? (it.count / max) * 100 : 0) + "%";
    bar.append(fill);
    row.append(lbl, bar);
    container.append(row);
  });
}

function drawTimeline(points) {
  const box = $("timeline");
  box.replaceChildren();
  if (points.length < 2) {
    box.append(el("p", "muted", "Analyze at least 2 transactions to see the timeline."));
    return;
  }
  const NS = "http://www.w3.org/2000/svg", W = 600, H = 200, P = 12;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.style.width = "100%";
  const mk = (t, attrs) => {
    const n = document.createElementNS(NS, t);
    Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
    svg.append(n);
    return n;
  };
  const y = (s) => H - P - (s / 100) * (H - 2 * P);
  [[30, "Medium"], [60, "High"]].forEach(([v, c]) =>
    mk("line", { x1: 0, x2: W, y1: y(v), y2: y(v), stroke: COLORS[c], "stroke-dasharray": "4 4", opacity: 0.4 }));
  const xy = points.map((p, i) => [P + (i * (W - 2 * P)) / (points.length - 1), y(p.score)]);
  mk("polygon", { points: `${xy[0][0]},${H - P} ` + xy.map((q) => q.join(",")).join(" ") + ` ${xy.at(-1)[0]},${H - P}`, fill: "#3b82f6", opacity: 0.15 });
  mk("polyline", { points: xy.map((q) => q.join(",")).join(" "), fill: "none", stroke: "#3b82f6", "stroke-width": 2.5 });
  xy.forEach((q, i) => mk("circle", { cx: q[0], cy: q[1], r: 4.5, fill: COLORS[points[i].category] }));
  box.append(svg);
}

async function loadStats() {
  const s = await (await fetch("/api/stats")).json();
  $("statTotal").textContent = s.total;
  $("statHigh").textContent = s.counts.High;
  $("statMedium").textContent = s.counts.Medium;
  $("statAvg").textContent = s.average_score;
  $("statFlagged").textContent = "₹" + Math.round(s.flagged_amount).toLocaleString("en-IN");

  drawTimeline(s.timeline);

  const alerts = $("alerts");
  alerts.replaceChildren();
  if (!s.alerts.length) alerts.append(el("p", "muted sm", "No medium or high-risk alerts yet."));
  s.alerts.forEach((a) => {
    const row = el("div", "alert");
    const left = el("div");
    left.append(el("b", "", a.receiver_name), el("small", "", "₹" + Number(a.amount).toLocaleString("en-IN") + " · " + a.payment_method));
    row.append(left, el("span", "badge " + a.risk_category, a.risk_score + " " + a.risk_category));
    alerts.append(row);
  });

  const dist = ["High", "Medium", "Low"].map((k) => ({ label: k, count: s.counts[k] }));
  bars($("distBars"), dist, Math.max(1, s.total), (it) => it.label);
  bars($("indBars"), s.indicators, Math.max(1, ...s.indicators.map((i) => i.count)), () => "Blue");
}

async function loadHistory() {
  const rows = await (await fetch("/api/history")).json();
  const body = $("historyBody");
  body.replaceChildren();
  if (!rows.length) {
    const tr = el("tr"); const td = el("td", "muted", "No transactions yet."); td.colSpan = 6;
    tr.append(td); body.append(tr); return;
  }
  rows.forEach((r) => {
    const tr = el("tr"), cell = el("td");
    cell.append(el("span", "badge " + r.risk_category, r.risk_category));
    tr.append(el("td", "", r.created_at), el("td", "", r.receiver_name),
      el("td", "", "₹" + Number(r.amount).toLocaleString("en-IN")),
      el("td", "", r.payment_method), el("td", "", r.risk_score), cell);
    body.append(tr);
  });
}

function showResult(d) {
  const box = $("result");
  box.className = "";
  box.replaceChildren();
  const row = el("div", "score-row");
  row.append(el("span", "score-num", d.risk_score + "/100"), el("span", "badge " + d.risk_category, d.risk_category + " risk"));
  const bar = el("div", "bar"), fill = el("div", d.risk_category);
  fill.style.width = d.risk_score + "%";
  bar.append(fill);
  const list = el("ul");
  d.reasons.forEach((r) => list.append(el("li", "", r)));
  box.append(row, bar, el("p", "", "Why this score:"), list, el("div", "advice", d.advice), el("p", "disclaimer", d.disclaimer));
}

function refreshAll() {
  loadStats().catch(console.error);
  loadHistory().catch(console.error);
}

$("txForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("formError").textContent = "";
  $("submitBtn").disabled = true;
  const payload = {
    amount: $("amount").value,
    receiver_name: $("receiver").value,
    payment_method: $("method").value,
    payment_link: $("payLink").value,
    new_receiver: $("newReceiver").checked,
    urgent: $("urgent").checked,
    asked_otp: $("askedOtp").checked,
  };
  try {
    const res = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const data = await res.json();
    if (!res.ok) $("formError").textContent = data.error || "Something went wrong.";
    else { showResult(data); refreshAll(); }
  } catch (err) {
    $("formError").textContent = "Cannot reach the server. Is app.py running?";
  } finally {
    $("submitBtn").disabled = false;
  }
});

refreshAll();