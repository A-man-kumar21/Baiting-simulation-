/* Shared UI helpers: auth guard, nav, toasts, formatting, safety banner. */
const App = (() => {
  let me = null;

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function badge(text) {
    return `<span class="badge b-${esc(text)}">${esc(text.replace(/_/g, " "))}</span>`;
  }

  function toast(msg, type = "") {
    const wrap = document.getElementById("toasts") || (() => {
      const w = document.createElement("div");
      w.id = "toasts"; w.className = "toast-wrap";
      document.body.appendChild(w); return w;
    })();
    const el = document.createElement("div");
    el.className = "toast " + type;
    el.textContent = msg;
    wrap.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    return new Date(iso).toLocaleString();
  }

  function fmtDur(sec) {
    if (sec == null) return "—";
    sec = Math.round(sec);
    const m = Math.floor(sec / 60), s = sec % 60;
    return m > 0 ? `${m}m ${s}s` : `${s}s`;
  }

  const NAV = [
    { section: "Operate" },
    { href: "/dashboard.html", label: "Dashboard", icon: "◈" },
    { href: "/scenarios.html", label: "Scenarios", icon: "◉" },
    { href: "/alerts.html", label: "Alerts", icon: "⚠" },
    { href: "/incidents.html", label: "Incidents", icon: "⬢" },
    { section: "Analyze" },
    { href: "/analytics.html", label: "Analytics", icon: "▤" },
    { href: "/mitre.html", label: "MITRE ATT&CK", icon: "⊞" },
    { href: "/reports.html", label: "Reports", icon: "▦" },
    { section: "Account" },
    { href: "/profile.html", label: "Profile", icon: "☺" },
  ];

  function renderNav() {
    const path = location.pathname;
    const links = NAV.map((n) => n.section
      ? `<div class="section">${n.section}</div>`
      : `<a href="${n.href}" class="${path === n.href ? "active" : ""}"><span>${n.icon}</span>${n.label}</a>`).join("");
    const mobile = NAV.filter((n) => !n.section)
      .map((n) => `<a href="${n.href}" class="${path === n.href ? "active" : ""}">${n.label}</a>`).join("");
    document.querySelectorAll(".sidebar .nav").forEach((el) => { el.innerHTML = links; });
    document.querySelectorAll(".mobile-nav").forEach((el) => { el.innerHTML = mobile; });
  }

  function safetyBanner() {
    return `<div class="safety">🛡️ <span><b>Simulation only.</b>
      Every attack, log entry, IP address, user and file in this console is fictional training data.
      Response actions change simulated records only — nothing here touches real systems.</span></div>`;
  }

  async function currentUser(force = false) {
    if (me && !force) return me;
    me = await API.get("/auth/me");
    return me;
  }

  /** Guard for app pages: redirects to login when unauthenticated, fills user chip. */
  async function guard({ adminOnly = false } = {}) {
    if (!API.token()) { location.href = "/login.html"; return null; }
    try {
      const u = await currentUser(true);
      if (adminOnly && u.role !== "ADMIN") {
        location.href = "/dashboard.html";
        return null;
      }
      document.querySelectorAll("[data-user-name]").forEach((el) => { el.textContent = u.name; });
      document.querySelectorAll("[data-user-role]").forEach((el) => { el.innerHTML = badge(u.role); });
      document.querySelectorAll("[data-user-initial]").forEach((el) => { el.textContent = u.name[0].toUpperCase(); });
      return u;
    } catch (e) {
      location.href = "/login.html";
      return null;
    }
  }

  function shell({ title, subtitle = "", actions = "" }) {
    return `
    <div class="app">
      <aside class="sidebar">
        <div class="brand"><div class="logo">S</div><div><b>CyberSOC</b><small>Security Operations</small></div></div>
        <nav class="nav"></nav>
      </aside>
      <div class="main">
        <div class="topbar">
          <div class="user"><span class="avatar" data-user-initial>?</span>
            <span><b data-user-name>…</b><br><span data-user-role></span></span></div>
          <button class="btn small" onclick="API.logout()">Log out</button>
        </div>
        <div class="mobile-nav"></div>
        <div class="content">
          ${safetyBanner()}
          <div class="page-head"><div><h1>${esc(title)}</h1>${subtitle ? `<p>${subtitle}</p>` : ""}</div>
          <div class="btn-row">${actions}</div></div>
          <div id="page"></div>
        </div>
      </div>
    </div>`;
  }

  /** Simple canvas bar chart. data: [{label, value, color}] */
  function barChart(canvas, data, { height = 220 } = {}) {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 600;
    canvas.width = w * dpr; canvas.height = height * dpr;
    canvas.style.height = height + "px";
    const ctx = canvas.getContext("2d"); ctx.scale(dpr, dpr);
    const max = Math.max(1, ...data.map((d) => d.value));
    const bw = Math.min(56, (w - 40) / data.length - 12);
    data.forEach((d, i) => {
      const h = (height - 60) * (d.value / max);
      const x = 20 + i * ((w - 40) / data.length) + ((w - 40) / data.length - bw) / 2;
      const y = height - 34 - h;
      ctx.fillStyle = d.color || "#38bdf8";
      ctx.beginPath(); ctx.roundRect(x, y, bw, h, 4); ctx.fill();
      ctx.fillStyle = "#dbe4f3"; ctx.font = "12px sans-serif"; ctx.textAlign = "center";
      ctx.fillText(String(d.value), x + bw / 2, y - 6);
      ctx.fillStyle = "#8b98b3";
      ctx.fillText(d.label.slice(0, 12), x + bw / 2, height - 14);
    });
  }

  /** Simple canvas line chart. points: [numbers], labels: [strings] */
  function lineChart(canvas, points, labels, { height = 220 } = {}) {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 600;
    canvas.width = w * dpr; canvas.height = height * dpr;
    canvas.style.height = height + "px";
    const ctx = canvas.getContext("2d"); ctx.scale(dpr, dpr);
    const max = Math.max(1, ...points), min = Math.min(0, ...points);
    const px = (i) => 30 + (i * (w - 50)) / Math.max(1, points.length - 1);
    const py = (v) => height - 34 - ((v - min) / (max - min || 1)) * (height - 60);
    ctx.strokeStyle = "#22304a"; ctx.beginPath();
    ctx.moveTo(30, 10); ctx.lineTo(30, height - 30); ctx.lineTo(w - 10, height - 30); ctx.stroke();
    if (points.length > 1) {
      ctx.strokeStyle = "#38bdf8"; ctx.lineWidth = 2; ctx.beginPath();
      points.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
      ctx.stroke();
    }
    ctx.fillStyle = "#38bdf8";
    points.forEach((v, i) => { ctx.beginPath(); ctx.arc(px(i), py(v), 4, 0, 7); ctx.fill(); });
    ctx.fillStyle = "#8b98b3"; ctx.font = "11px sans-serif"; ctx.textAlign = "center";
    labels.forEach((l, i) => { if (i % Math.ceil(labels.length / 8) === 0) ctx.fillText(l, px(i), height - 12); });
  }

  function paginate(el, total, skip, limit, onPage) {
    const pages = Math.ceil(total / limit);
    const cur = Math.floor(skip / limit);
    if (pages <= 1) { el.innerHTML = ""; return; }
    let html = `<div class="btn-row" style="margin-top:12px">`;
    for (let i = 0; i < pages; i++) {
      html += `<button class="btn small ${i === cur ? "primary" : ""}" data-p="${i}">${i + 1}</button>`;
    }
    el.innerHTML = html + `</div><p style="color:var(--muted);font-size:12px">${total} total</p>`;
    el.querySelectorAll("button").forEach((b) =>
      b.addEventListener("click", () => onPage(parseInt(b.dataset.p, 10) * limit)));
  }

  return { esc, badge, toast, fmtDate, fmtDur, renderNav, guard, shell, barChart, lineChart, paginate, currentUser };
})();
