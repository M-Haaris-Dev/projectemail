/* mailMeta dashboard — clean, plain-language UI */
(function () {
  "use strict";

  const state = { page: 0, pageSize: 50, level: "all", search: "", sort: "date_ts" };
  const $ = (id) => document.getElementById(id);

  const PLAIN = {
    risk: {
      safe: "Likely legitimate",
      low: "Most likely legitimate",
      medium: "Caution advised",
      high: "Suspicious / possible phishing",
    },
    riskSummary: {
      safe: "All authentication checks passed. This email very likely came from the sender it claims.",
      low: "Minor inconsistencies only. The email is probably legitimate, but keep standard caution.",
      medium: "One or more checks did not fully pass. Treat links and attachments with care.",
      high: "Strong indicators of spoofing or phishing. Do not trust links, attachments, or any instructions in this email.",
    },
    spf: {
      pass: "Sending server was authorised by the sender's domain.",
      fail: "Not authorised by the sender's domain - the domain may be impersonated.",
      softfail: "Not confirmed by the sender's domain - typical of spoofed mail.",
      neutral: "Domain gives no clear verdict for this server.",
      none: "Sender's domain publishes no SPF policy.",
      temperror: "Temporary DNS error - could not check.",
      permerror: "Sender's SPF policy is malformed.",
      unknown: "Could not verify SPF.",
    },
    dkim: {
      pass: "Valid digital signature from the claimed domain.",
      fail: "Digital signature could not be validated - content or sender may be forged.",
      error: "Signature could not be checked due to an error.",
      none: "No digital signature present.",
      unknown: "Could not check digital signature.",
    },
    dmarc: {
      pass: "Domain policy satisfied - sender identity aligns.",
      fail: "Domain policy says senders must authenticate; this one did not.",
      none: "No DMARC policy published for this domain.",
      unknown: "Could not evaluate DMARC.",
    },
  };

  const VERDICT_LABEL = { safe: "SAFE", low: "LOW RISK", medium: "MEDIUM RISK", high: "HIGH RISK" };

  /* ---------- helpers ---------- */
  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) throw new Error((await r.text()) || r.statusText);
    return r.json();
  }
  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }
  function flagFor(cc) { return cc ? (cc.toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)))) : ""; }
  function dt(ts) { return ts ? new Date(ts * 1000).toLocaleString() : "—"; }
  function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

  function authText(kind, status) {
    return (PLAIN[kind] && PLAIN[kind][status]) || "No data.";
  }
  function chip(status) {
    const cls = ["pass", "fail", "softfail", "permerror", "none", "neutral", "error", "temperror"].includes(status) ? status : "none";
    return `<span class="chip ${cls}">${esc(status || "—")}</span>`;
  }
  function geoLabel(geo) {
    if (!geo) return "";
    if (geo.status === "private") return "Private / local network";
    if (geo.status === "success") {
      const parts = [];
      if (geo.city) parts.push(geo.city);
      if (geo.countryCode) parts.push(geo.countryCode);
      return parts.join(", ");
    }
    return "Location unknown";
  }

  const ctx = { page: 0, pageSize: 50, level: "all", search: "", account: "" };

  /* ========================= list ========================= */
  async function loadAll() {
    await Promise.allSettled([loadStats(), loadMonitors(), loadEmails(), loadAccounts()]);
  }

  async function loadStats() {
    const s = await api("/api/stats");
    $("statTotal").textContent = s.total;
    $("statSafe").textContent = s.by_level?.safe || 0;
    $("statLow").textContent = s.by_level?.low || 0;
    $("statMedium").textContent = s.by_level?.medium || 0;
    $("statHigh").textContent = s.by_level?.high || 0;
  }

  async function loadMonitors() {
    let mons = [];
    try { mons = await api("/api/monitors"); } catch (e) { mons = []; }
    const dot = $("monitorDot"), text = $("monitorText");
    if (!mons.length) { dot.className = "dot off"; text.textContent = "No mailbox connected"; return; }
    const ok = mons.filter((m) => !m.status?.startsWith("error") && m.status && m.status !== "stopped");
    if (ok.length) { dot.className = "dot on"; text.textContent = `${ok.length}/${mons.length} mailbox${mons.length > 1 ? "es" : ""} connected`; }
    else { dot.className = "dot off"; text.textContent = "Mailbox disconnected"; }
  }

  async function loadAccounts() {
    const s = await api("/api/stats");
    const sel = $("filterAccount");
    const accts = Object.keys(s.by_account || {});
    sel.innerHTML = '<option value="">All mailboxes</option>';
    accts.forEach((a) => {
      const o = document.createElement("option");
      o.value = a; o.textContent = a;
      if (a === ctx.account) o.selected = true;
      sel.appendChild(o);
    });
  }

  async function loadEmails() {
    const q = new URLSearchParams({
      limit: ctx.pageSize, offset: ctx.page * ctx.pageSize,
      risk_level: ctx.level, search: ctx.search, account: ctx.account, sort: ctx.sort,
    });
    const data = await api(`/api/emails?${q}`);
    renderRows(data.rows);
    const pages = Math.max(1, Math.ceil(data.total / ctx.pageSize));
    $("pageInfo").textContent = `Page ${ctx.page + 1} of ${pages} · ${data.total} emails`;
    $("prevPage").disabled = ctx.page === 0;
    $("nextPage").disabled = ctx.page + 1 >= pages;
  }

  function renderRows(rows) {
    const tb = $("emailRows");
    if (!rows || !rows.length) {
      tb.innerHTML = '<tr><td colspan="9" class="empty">No emails match the current filter.</td></tr>';
      return;
    }
    tb.innerHTML = rows.map((r) => {
      const name = r.from_name ? `${r.from_name} <${r.from_addr || ""}>` : r.from_addr || "—";
      const geo = r.geo;
      const origin = geo
        ? `${esc(r.ip_address || "—")} <span class="flag">${geo.countryCode ? flagFor(geo.countryCode) : ""}</span>${esc(geoLabel(geo))}`
        : esc(r.ip_address || "—");
      return `<tr data-id="${r.id}">
        <td><span class="pill ${r.risk_level}">${VERDICT_LABEL[r.risk_level] || r.risk_level}</span></td>
        <td class="time-cell">${dt(r.date_ts)}</td>
        <td class="from-cell" title="${esc(name)}">${esc(name)}</td>
        <td class="subj-cell" title="${esc(r.subject)}">${esc(r.subject)}</td>
        <td>${chip(r.spf_status)}</td>
        <td>${chip(r.dkim_status)}</td>
        <td>${chip(r.dmarc_status)}</td>
        <td class="origin-cell" title="${esc(origin)}">${origin}</td>
        <td class="num"><span class="score-num">${r.risk_score}</span></td>
      </tr>`;
    }).join("");
  }

  /* ========================= report ========================= */
  async function openReport(id) {
    const m = await api(`/api/emails/${id}`);
    const d = m.data || {};
    const lvl = m.risk_level || "unknown";
    const geo = d.geo || {};
    const rp = d.reply_to, frm = d.from_addr || "—";

    const geoHtml = geo.status === "success"
      ? `            <div class="kv">
              <span class="k">IP address</span><span class="v">${esc(d.ip_address || "—")}</span>
              ${d.ptr ? `<span class="k">Reverse DNS</span><span class="v">${esc(d.ptr)}</span>` : ""}
              <span class="k">Location</span><span class="v"><span class="flag-lg">${flagFor(geo.countryCode)}</span> ${esc([geo.city, geo.regionName, geo.country].filter(Boolean).join(", ") || "Unknown")}</span>
              <span class="k">Internet provider</span><span class="v">${esc(geo.isp || "Unknown")}${geo.org && geo.org !== geo.isp ? ` · ${esc(geo.org)}` : ""}</span>
              <span class="k">Coordinates</span><span class="v">${geo.lat}° ${geo.lon}°</span>
              <span class="k">Timezone</span><span class="v">${esc(geo.timezone || "—")}</span>
            </div>`
      : `            <div class="kv">
              <span class="k">IP address</span><span class="v">${esc(d.ip_address || "—")}</span>
              <span class="k">Location</span><span class="v">${esc(geo.note || "Could not determine location")}</span>
            </div>`;

    const authRow = (kind, label, st) => `
      <div class="auth-row">
        <div class="auth-name">${label}</div>
        <div class="auth-status">${chip(st)}</div>
        <div class="auth-explain">${esc(authText(kind, st))}
          ${d[kind]?.explanation || d[kind]?.detail ? `<div class="auth-detail">${esc(d[kind]?.explanation || d[kind]?.detail)}</div>` : ""}
        </div>
      </div>`;

    const findings = (d.findings || []).map((f) => `<div class="finding">${esc(f)}</div>`).join("")
      || '<div class="finding">No notable anomalies detected.</div>';

    const hops = (d.received_chain || []).length
      ? `            <details class="hop">
                <summary>View full delivery path (${d.received_chain.length} hop${d.received_chain.length > 1 ? "s" : ""})</summary>
                <table class="hop-tbl">
                  <thead><tr><th>#</th><th>Server / details</th></tr></thead>
                  <tbody>${d.received_chain.map((h, i) => `<tr><td>${i + 1}</td><td>${esc(h)}</td></tr>`).join("")}</tbody>
                </table>
              </details>`
      : "";

    $("drawerBody").innerHTML = `
    <div class="report">
      <div class="verdict ${lvl}">
        <div class="v-title">${VERDICT_LABEL[lvl] || lvl.toUpperCase()}<span class="score">Risk score ${m.risk_score}/100</span></div>
        <div class="v-summary">${PLAIN.riskSummary[lvl]}</div>
      </div>

      <div class="card">
        <h3>1 · Who sent it</h3>
          <div class="kv">
            <span class="k">From</span><span class="v">${esc(d.from_name || "")} &lt;${esc(frm)}&gt;</span>
            ${rp ? `<span class="k">Reply-To</span><span class="v">${esc(rp)}</span>` : ""}
            ${d.sender_addr ? `<span class="k">Sender</span><span class="v">${esc(d.sender_addr)}</span>` : ""}
            ${d.return_path ? `<span class="k">Return-Path</span><span class="v">${esc(d.return_path)}</span>` : ""}
            <span class="k">Date</span><span class="v">${esc(d.date || "—")}</span>
            ${d.message_id ? `<span class="k">Message-ID</span><span class="v">${esc(d.message_id)}</span>` : ""}
          </div>
      </div>

      <div class="card">
        <h3>2 · Where it came from</h3>
        ${geoHtml}
      </div>

      <div class="card">
        <h3>3 · Is the sender verified?</h3>
        ${authRow("spf", "SPF", d.spf?.status)}
        ${authRow("dkim", "DKIM", d.dkim?.status)}
        ${authRow("dmarc", "DMARC", d.dmarc?.status)}
        ${d.spf?.record ? `<p style="margin-top:10px;font-size:12px;color:var(--muted)">SPF record: <span style="font-family:ui-monospace,Menlo,monospace">${esc(d.spf.record)}</span></p>` : ""}
      </div>

      <div class="card">
        <h3>4 · Checks &amp; findings</h3>
        ${findings}
        ${hops}
      </div>

      <div class="card">
        <h3>5 · Raw email</h3>
        <pre class="raw" id="rawBox">Click below to load the raw message.</pre>
        <button class="btn ghost" style="margin-top:10px" id="loadRawBtn">Load raw message</button>
      </div>
    </div>`;

    $("loadRawBtn").addEventListener("click", async () => {
      const r = await api(`/api/emails/${id}/raw`);
      $("rawBox").textContent = r.raw;
      $("loadRawBtn").remove();
    });
    openDrawer();
  }

  function openDrawer() { $("drawer").classList.add("open"); $("drawer").setAttribute("aria-hidden", "false"); $("drawerBackdrop").hidden = false; }
  function closeDrawer() { $("drawer").classList.remove("open"); $("drawer").setAttribute("aria-hidden", "true"); $("drawerBackdrop").hidden = true; }

  /* ========================= csv ========================= */
  async function exportCSV() {
    const q = new URLSearchParams({ limit: 5000, offset: 0, risk_level: ctx.level, search: ctx.search });
    const data = await api(`/api/emails?${q}`);
    if (!data.rows.length) return;
    const cols = ["date_ts", "risk_level", "risk_score", "from_addr", "from_name", "reply_to", "ip_address", "subject", "spf_status", "dkim_status", "dmarc_status", "message_id"];
    const head = cols.join(",");
    const body = data.rows.map((r) => cols.map((c) => `"${String(r[c] ?? "").replace(/"/g, '""')}"`).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([head + "\n" + body], { type: "text/csv" }));
    a.download = "mailmeta-report.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  /* ========================= events ========================= */
  $("refreshBtn").addEventListener("click", loadAll);
  $("filterLevel").addEventListener("change", (e) => { ctx.level = e.target.value; ctx.page = 0; loadEmails(); });
  $("filterSearch").addEventListener("input", debounce((e) => { ctx.search = e.target.value.trim(); ctx.page = 0; loadEmails(); }, 400));
  $("prevPage").addEventListener("click", () => { ctx.page = Math.max(0, ctx.page - 1); loadEmails(); });
  $("nextPage").addEventListener("click", () => { ctx.page += 1; loadEmails(); });
  $("exportBtn").addEventListener("click", exportCSV);
  $("drawerClose").addEventListener("click", closeDrawer);
  $("drawerBackdrop").addEventListener("click", closeDrawer);
  $("emailRows").addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (tr) openReport(tr.dataset.id);
  });

  loadAll();
  setInterval(loadStats, 30000);
})();