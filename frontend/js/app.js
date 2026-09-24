/* Shared UI helpers: auth guard, nav, toasts, formatting, safety banner. */
const App = (() => {
  let me = null;

  const P = (inner) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
  const ICONS = {
    shield: P(`<path d="M12 3l7.5 3v5.5c0 4.6-3.2 7.9-7.5 9.5-4.3-1.6-7.5-4.9-7.5-9.5V6L12 3z"/><path d="M9.5 12l2 2 3.5-4"/>`),
    dash: P(`<rect x="3.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.6"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.6"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.6"/>`),
    scenarios: P(`<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 12.5l9 5 9-5"/><path d="M3 17l9 5 9-5"/>`),
    alert: P(`<path d="M12 4a6 6 0 0 0-6 6v3.5L4 16h16l-2-2.5V10a6 6 0 0 0-6-6z"/><path d="M10 19a2 2 0 0 0 4 0"/>`),
    incident: P(`<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/><path d="M12 8v4.5"/><circle cx="12" cy="16" r="0.6" fill="currentColor"/>`),
    chart: P(`<path d="M4 20V10"/><path d="M10 20V4"/><path d="M16 20v-8"/><path d="M21 20H3"/>`),
    mitre: P(`<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1" fill="currentColor"/><path d="M12 1.5v4M12 18.5v4M1.5 12h4M18.5 12h4"/>`),
    report: P(`<path d="M6 2.5h8L19 7.5V21.5H6V2.5z"/><path d="M14 2.5v5h5"/><path d="M9 12.5h6M9 16h6"/>`),
    user: P(`<circle cx="12" cy="8" r="4"/><path d="M4.5 20.5a7.5 7.5 0 0 1 15 0"/>`),
    admin: P(`<circle cx="12" cy="12" r="3.2"/><path d="M19 12a7 7 0 0 0-.14-1.4l2-1.55-2-3.46-2.36.95A7 7 0 0 0 14 5.1L13.7 2.6h-3.4L10 5.1a7 7 0 0 0-2.5 1.44l-2.36-.95-2 3.46 2 1.55a7 7 0 0 0 0 2.8l-2 1.55 2 3.46 2.36-.95a7 7 0 0 0 2.5 1.44l.3 2.5h3.4l.3-2.5a7 7 0 0 0 2.5-1.44l2.36.95 2-3.46-2-1.55c.1-.46.14-.93.14-1.4z"/>`),
    play: P(`<circle cx="12" cy="12" r="8.5"/><path d="M10 8.5l6 3.5-6 3.5v-7z"/>`),
    check: P(`<path d="M4.5 12.5l5 5L19.5 7"/>`),
    lock: P(`<rect x="5" y="10.5" width="14" height="10" rx="2.2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>`),
    zap: P(`<path d="M13 2.5L4.5 13.5H11l-1 8 8.5-11H12l1-8z"/>`),
    x: P(`<path d="M6 6l12 12M18 6L6 18"/>`),
  };

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
    setTimeout(() => { el.style.opacity = "0"; el.style.transform = "translateX(30px)"; setTimeout(() => el.remove(), 250); }, 4200);
  }

  /** Skeleton placeholder while a region loads. */
  function skel(lines = 3) {
    return `<div style="display:flex;flex-direction:column;gap:10px;padding:4px 0">` +
      Array.from({ length: lines }, (_, i) =>
        `<div class="skel" style="height:14px;width:${92 - i * 14}%"></div>`).join("") + `</div>`;
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
    { href: "/dashboard.html", label: "Dashboard", icon: "dash" },
    { href: "/scenarios.html", label: "Scenarios", icon: "scenarios" },
    { href: "/alerts.html", label: "Alerts", icon: "alert" },
    { href: "/incidents.html", label: "Incidents", icon: "incident" },
    { section: "Analyze" },
    { href: "/analytics.html", label: "Analytics", icon: "chart" },
    { href: "/mitre.html", label: "MITRE ATT&CK", icon: "mitre" },
    { href: "/reports.html", label: "Reports", icon: "report" },
    { section: "Account" },
    { href: "/profile.html", label: "Profile", icon: "user" },
  ];
  const ADMIN_NAV = { href: "/admin.html", label: "Administration", icon: "admin" };

  function renderNav(isAdmin) {
    const path = location.pathname;
    const items = isAdmin ? [...NAV, { section: "System" }, ADMIN_NAV] : NAV;
    const links = items.map((n) => n.section
      ? `<div class="section">${n.section}</div>`
      : `<a href="${n.href}" class="${path === n.href ? "active" : ""}">${ICONS[n.icon] || ""}<span>${n.label}</span></a>`).join("");
    const mobile = items.filter((n) => !n.section)
      .map((n) => `<a href="${n.href}" class="${path === n.href ? "active" : ""}">${n.label}</a>`).join("");
    document.querySelectorAll(".sidebar .nav").forEach((el) => { el.innerHTML = links; });
    document.querySelectorAll(".mobile-nav").forEach((el) => { el.innerHTML = mobile; });
  }

  function dismissSafety() {
    try { sessionStorage.setItem("cybersoc_safety_dismissed", "1"); } catch (e) {}
    document.querySelectorAll(".safety").forEach((el) => el.remove());
  }

  function safetyBanner() {
    try { if (sessionStorage.getItem("cybersoc_safety_dismissed")) return ""; } catch (e) {}
    return `<div class="safety">${ICONS.shield}<span><b>Simulation only.</b>
      Every attack, log entry, IP address, user and file in this console is fictional training data.
      Response actions change simulated records only — nothing here touches real systems.</span>
      <button class="x" onclick="App.dismissSafety()" aria-label="Dismiss">✕</button></div>`;
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
      renderNav(u.role === "ADMIN");
      document.querySelectorAll("[data-user-name]").forEach((el) => { el.textContent = u.name; });
      document.querySelectorAll("[data-user-role]").forEach((el) => { el.innerHTML = badge(u.role); });
      document.querySelectorAll("[data-user-initial]").forEach((el) => { el.textContent = u.name[0].toUpperCase(); });
      const crumb = document.querySelector("[data-crumb]");
      if (crumb && document.title.includes("—")) crumb.textContent = document.title.split("—")[1].trim();
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
        <div class="brand"><div class="logo">${ICONS.shield}</div><div><b>CyberSOC</b><small>Security Operations</small></div></div>
        <nav class="nav"></nav>
        <div class="side-foot"><span class="live-dot"></span><span>Training environment · v1.0</span></div>
      </aside>
      <div class="main">
        <div class="topbar">
          <div class="crumb"><span>CyberSOC</span><span style="opacity:.5">/</span><b data-crumb>${esc(title)}</b><span class="env-pill"><span class="live-dot" style="background:var(--yellow);box-shadow:0 0 8px var(--yellow)"></span>SIMULATION</span></div>
          <div class="user">
            <div class="user-chip">
              <div class="who"><b data-user-name>…</b><span data-user-role></span></div>
              <span class="avatar" data-user-initial>?</span>
            </div>
            <button class="btn small ghost" onclick="API.logout()">Log out</button>
          </div>
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
    const slot = (w - 40) / Math.max(1, data.length);
    const bw = Math.min(54, slot - 14);
    ctx.strokeStyle = "rgba(148,163,184,.12)"; ctx.lineWidth = 1;
    for (let g = 0; g <= 4; g++) {
      const y = 14 + (g * (height - 60)) / 4;
      ctx.beginPath(); ctx.moveTo(30, y); ctx.lineTo(w - 10, y); ctx.stroke();
    }
    data.forEach((d, i) => {
      const h = Math.max(3, (height - 60) * (d.value / max));
      const x = 20 + i * slot + (slot - bw) / 2;
      const y = height - 34 - h;
      const grad = ctx.createLinearGradient(0, y, 0, y + h);
      grad.addColorStop(0, d.color || "#5b8cff");
      grad.addColorStop(1, (d.color || "#5b8cff") + "55");
      ctx.fillStyle = grad;
      ctx.beginPath(); ctx.roundRect(x, y, bw, h, [5, 5, 0, 0]); ctx.fill();
      ctx.fillStyle = "#c3cede"; ctx.font = "600 12px Inter, sans-serif"; ctx.textAlign = "center";
      ctx.fillText(String(d.value), x + bw / 2, y - 7);
      ctx.fillStyle = "#5d6a85"; ctx.font = "11px Inter, sans-serif";
      ctx.fillText(d.label.slice(0, 14), x + bw / 2, height - 14);
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
    const px = (i) => 34 + (i * (w - 54)) / Math.max(1, points.length - 1);
    const py = (v) => height - 36 - ((v - min) / (max - min || 1)) * (height - 66);
    ctx.strokeStyle = "rgba(148,163,184,.12)"; ctx.lineWidth = 1;
    for (let g = 0; g <= 4; g++) {
      const y = 12 + (g * (height - 60)) / 4;
      ctx.beginPath(); ctx.moveTo(34, y); ctx.lineTo(w - 12, y); ctx.stroke();
    }
    if (points.length > 1) {
      const grad = ctx.createLinearGradient(0, 12, 0, height - 30);
      grad.addColorStop(0, "rgba(91,140,255,.30)"); grad.addColorStop(1, "rgba(91,140,255,0)");
      ctx.beginPath();
      points.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
      ctx.lineTo(px(points.length - 1), height - 30); ctx.lineTo(px(0), height - 30); ctx.closePath();
      ctx.fillStyle = grad; ctx.fill();
      ctx.beginPath();
      points.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
      ctx.strokeStyle = "#5b8cff"; ctx.lineWidth = 2.2; ctx.lineJoin = "round"; ctx.stroke();
    }
    ctx.fillStyle = "#8fb0ff";
    points.forEach((v, i) => { ctx.beginPath(); ctx.arc(px(i), py(v), 3.5, 0, 7); ctx.fill(); });
    ctx.fillStyle = "#5d6a85"; ctx.font = "11px Inter, sans-serif"; ctx.textAlign = "center";
    labels.forEach((l, i) => { if (i % Math.ceil(labels.length / 8) === 0) ctx.fillText(l, px(i), height - 12); });
  }

  function paginate(el, total, skip, limit, onPage) {
    const pages = Math.ceil(total / limit);
    const cur = Math.floor(skip / limit);
    if (pages <= 1) { el.innerHTML = ""; return; }
    let html = `<div class="btn-row" style="margin-top:14px">`;
    for (let i = 0; i < pages; i++) {
      html += `<button class="btn small ${i === cur ? "primary" : ""}" data-p="${i}">${i + 1}</button>`;
    }
    el.innerHTML = html + `</div><p style="color:var(--muted);font-size:12px;margin:8px 0 0">${total} total</p>`;
    el.querySelectorAll("button").forEach((b) =>
      b.addEventListener("click", () => onPage(parseInt(b.dataset.p, 10) * limit)));
  }

  return { esc, badge, toast, skel, fmtDate, fmtDur, renderNav, guard, shell, barChart, lineChart, paginate, currentUser, dismissSafety, ICONS };
})();
