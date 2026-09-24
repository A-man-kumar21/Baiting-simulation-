/* CyberSOC API client — every UI action goes through here. */
const API = (() => {
  const TOKEN_KEY = "cybersoc_token";
  const base = "/api";

  function token() { return localStorage.getItem(TOKEN_KEY); }
  function setToken(t) { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY); }

  async function req(method, path, body) {
    const headers = { "Content-Type": "application/json" };
    const t = token();
    if (t) headers["Authorization"] = "Bearer " + t;
    const opts = { method, headers };
    if (body !== undefined) opts.body = JSON.stringify(body);
    let res;
    try {
      res = await fetch(base + path, opts);
    } catch (e) {
      throw new Error("Cannot reach the API server. Is the backend running?");
    }
    if (res.status === 401 && token()) {
      setToken(null);
      location.href = "/login.html";
      throw new Error("Session expired — please log in again.");
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* empty body */ }
    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || `Request failed (${res.status})`;
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    return data;
  }

  return {
    token, setToken,
    get: (p) => req("GET", p),
    post: (p, b) => req("POST", p, b),
    patch: (p, b) => req("PATCH", p, b),
    put: (p, b) => req("PUT", p, b),
    del: (p) => req("DELETE", p),
    logout() { setToken(null); location.href = "/login.html"; },
  };
})();
