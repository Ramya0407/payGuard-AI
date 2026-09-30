
const COLORS = {
  Low: "#22c55e",
  Medium: "#f59e0b",
  High: "#ef4444"
};

const $ = (id) => document.getElementById(id);


// =====================================================
// ELEMENT CREATOR
// =====================================================

function el(tag, cls, text) {
  const n = document.createElement(tag);

  if (cls) {
    n.className = cls;
  }

  if (text !== undefined) {
    n.textContent = text;
  }

  return n;
}


// =====================================================
// BAR CHARTS
// =====================================================

function bars(container, items, max, colorFn) {

  container.replaceChildren();

  if (!items.length) {
    container.append(
      el("p", "muted sm", "No data yet.")
    );
    return;
  }

  items.forEach((it) => {

    const row = el("div", "brow");

    const lbl = el("div", "lbl");

    lbl.append(
      el("span", "", it.label),
      el("span", "", String(it.count))
    );

    const bar = el("div", "bar");

    const fill = el(
      "div",
      colorFn(it)
    );

    fill.style.width =
      (max ? (it.count / max) * 100 : 0) + "%";

    bar.append(fill);

    row.append(
      lbl,
      bar
    );

    container.append(row);

  });
}


// =====================================================
// RISK SCORE TIMELINE
// =====================================================

function drawTimeline(points) {

  const box = $("timeline");

  box.replaceChildren();

  if (points.length < 2) {

    box.append(
      el(
        "p",
        "muted",
        "Analyze at least 2 transactions to see the timeline."
      )
    );

    return;
  }

  const NS =
    "http://www.w3.org/2000/svg";

  const W = 600;
  const H = 200;
  const P = 12;

  const svg =
    document.createElementNS(
      NS,
      "svg"
    );

  svg.setAttribute(
    "viewBox",
    `0 0 ${W} ${H}`
  );

  svg.style.width = "100%";


  function mk(type, attrs) {

    const n =
      document.createElementNS(
        NS,
        type
      );

    Object.entries(attrs).forEach(
      ([key, value]) => {
        n.setAttribute(
          key,
          value
        );
      }
    );

    svg.append(n);

    return n;
  }


  function y(score) {

    return (
      H -
      P -
      (score / 100) *
      (H - 2 * P)
    );

  }


  // Medium and High threshold lines

  [
    [30, "Medium"],
    [60, "High"]
  ].forEach(([value, category]) => {

    mk(
      "line",
      {
        x1: 0,
        x2: W,
        y1: y(value),
        y2: y(value),
        stroke: COLORS[category],
        "stroke-dasharray": "4 4",
        opacity: 0.4
      }
    );

  });


  const xy =
    points.map(
      (point, index) => [

        P +
        (
          index *
          (W - 2 * P)
        ) /
        (points.length - 1),

        y(point.score)

      ]
    );


  // Area below line

  mk(
    "polygon",
    {
      points:
        `${xy[0][0]},${H - P} ` +
        xy
          .map((q) => q.join(","))
          .join(" ") +
        ` ${xy[xy.length - 1][0]},${H - P}`,

      fill: "#3b82f6",

      opacity: 0.15
    }
  );


  // Main line

  mk(
    "polyline",
    {
      points:
        xy
          .map((q) => q.join(","))
          .join(" "),

      fill: "none",

      stroke: "#3b82f6",

      "stroke-width": 2.5
    }
  );


  // Points

  xy.forEach(
    (point, index) => {

      mk(
        "circle",
        {
          cx: point[0],
          cy: point[1],
          r: 4.5,
          fill:
            COLORS[
              points[index].category
            ]
        }
      );

    }
  );


  box.append(svg);

}


// =====================================================
// DASHBOARD STATS
// =====================================================

async function loadStats() {

  const response =
    await fetch("/api/stats");

  const s =
    await response.json();


  $("statTotal").textContent =
    s.total;

  $("statHigh").textContent =
    s.counts.High;

  $("statMedium").textContent =
    s.counts.Medium;

  $("statAvg").textContent =
    s.average_score;

  $("statFlagged").textContent =
    "₹" +
    Math.round(
      s.flagged_amount
    ).toLocaleString("en-IN");


  // Timeline

  drawTimeline(
    s.timeline
  );


  // ===================================================
  // RECENT ALERTS
  // ===================================================

  const alerts =
    $("alerts");

  alerts.replaceChildren();


  if (!s.alerts.length) {

    alerts.append(
      el(
        "p",
        "muted sm",
        "No medium or high-risk alerts yet."
      )
    );

  }


  s.alerts.forEach((a) => {

    const row =
      el("div", "alert");

    const left =
      el("div");


    left.append(

      el(
        "b",
        "",
        a.receiver_name
      ),

      el(
        "small",
        "",
        "₹" +
        Number(a.amount)
          .toLocaleString("en-IN") +
        " · " +
        a.payment_method
      )

    );


    row.append(

      left,

      el(
        "span",
        "badge " +
        a.risk_category,

        a.risk_score +
        " " +
        a.risk_category
      )

    );


    alerts.append(row);

  });


  // ===================================================
  // RISK DISTRIBUTION
  // ===================================================

  const dist = [

    {
      label: "High",
      count: s.counts.High
    },

    {
      label: "Medium",
      count: s.counts.Medium
    },

    {
      label: "Low",
      count: s.counts.Low
    }

  ];


  bars(
    $("distBars"),

    dist,

    Math.max(
      1,
      s.total
    ),

    (it) =>
      it.label
  );


  // ===================================================
  // TOP RISK INDICATORS
  // ===================================================

  bars(

    $("indBars"),

    s.indicators,

    Math.max(
      1,
      ...s.indicators.map(
        (i) => i.count
      )
    ),

    () => "Blue"

  );

}


// =====================================================
// HISTORY
// =====================================================

async function loadHistory() {

  const response =
    await fetch("/api/history");

  const rows =
    await response.json();


  const body =
    $("historyBody");

  body.replaceChildren();


  if (!rows.length) {

    const tr =
      el("tr");

    const td =
      el(
        "td",
        "muted",
        "No transactions yet."
      );

    td.colSpan = 6;

    tr.append(td);

    body.append(tr);

    return;
  }


  rows.forEach((r) => {

    const tr =
      el("tr");

    const riskCell =
      el("td");


    riskCell.append(

      el(
        "span",
        "badge " +
        r.risk_category,

        r.risk_category
      )

    );


    tr.append(

      el(
        "td",
        "",
        r.created_at
      ),

      el(
        "td",
        "",
        r.receiver_name
      ),

      el(
        "td",
        "",
        "₹" +
        Number(r.amount)
          .toLocaleString("en-IN")
      ),

      el(
        "td",
        "",
        r.payment_method
      ),

      el(
        "td",
        "",
        r.risk_score
      ),

      riskCell

    );


    body.append(tr);

  });

}


// =====================================================
// SHOW RESULT
// =====================================================

function showResult(d) {

  const box =
    $("result");

  box.className = "";

  box.replaceChildren();


  // ===================================================
  // SCORE HEADER
  // ===================================================

  const row =
    el("div", "score-row");


  row.append(

    el(
      "span",
      "score-num",
      d.risk_score + "/100"
    ),

    el(
      "span",
      "badge " +
      d.risk_category,

      d.risk_category +
      " risk"
    )

  );


  // ===================================================
  // SCORE BAR
  // ===================================================

  const bar =
    el("div", "bar");

  const fill =
    el(
      "div",
      d.risk_category
    );

  fill.style.width =
    d.risk_score + "%";

  bar.append(fill);


  // ===================================================
  // REASONS
  // ===================================================

  const heading =
    el(
      "p",
      "",
      "Why this score:"
    );


  const list =
    el("ul");


  d.reasons.forEach(
    (reason) => {

      list.append(
        el(
          "li",
          "",
          reason
        )
      );

    }
  );


  // ===================================================
  // ADVICE
  // ===================================================

  const advice =
    el(
      "div",
      "advice",
      d.advice
    );


  // ===================================================
  // DISCLAIMER
  // ===================================================

  const disclaimer =
    el(
      "p",
      "disclaimer",
      d.disclaimer
    );


  box.append(

    row,

    bar,

    heading,

    list,

    advice,

    disclaimer

  );

}


// =====================================================
// REFRESH DASHBOARD
// =====================================================

function refreshAll() {

  loadStats()
    .catch(console.error);

  loadHistory()
    .catch(console.error);

}


// =====================================================
// MAIN ANALYSIS FORM
// =====================================================

$("txForm").addEventListener(
  "submit",
  async (e) => {

    e.preventDefault();


    $("formError").textContent =
      "";


    const button =
      $("submitBtn");


    button.disabled = true;

    button.textContent =
      "🔄 Analyzing...";


    // =================================================
    // COLLECT ALL DATA
    // =================================================

    const payload = {

      amount:
        $("amount").value,

      receiver_name:
        $("receiver").value,

      payment_method:
        $("method").value,

      payment_link:
        $("payLink").value,

      // NEW: SMS MESSAGE
      sms_message:
        $("smsMessage").value,

      new_receiver:
        $("newReceiver").checked,

      urgent:
        $("urgent").checked,

      asked_otp:
        $("askedOtp").checked

    };


    // =================================================
    // SEND TO FLASK
    // =================================================

    try {

      const response =
        await fetch(
          "/api/analyze",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json"
            },

            body:
              JSON.stringify(payload)
          }
        );


      const data =
        await response.json();


      if (!response.ok) {

        $("formError").textContent =
          data.error ||
          "Something went wrong.";

        return;

      }


      // =================================================
      // SHOW RESULT
      // =================================================

      showResult(data);


      // =================================================
      // REFRESH DASHBOARD
      // =================================================

      refreshAll();


    } catch (error) {

      console.error(error);

      $("formError").textContent =
        "Cannot reach the server. Is app.py running?";

    } finally {

      button.disabled = false;

      button.textContent =
        "🛡️ Analyze Everything";

    }

  }
);


// =====================================================
// INITIAL LOAD
// =====================================================

refreshAll();
