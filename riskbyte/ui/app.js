(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var token = sessionStorage.getItem("rb_token") || "", cur = null, timer = null;

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function api(path, method) {
    return fetch(path, { method: method || "GET", headers: { Authorization: "Bearer " + token } }).then(function (r) {
      if (r.status === 401 || r.status === 403) { signOut(); throw new Error("auth"); }
      return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || r.status); return j; });
    });
  }
  function when(ts) { return new Date(ts * 1000).toLocaleString(); }
  function signOut() { sessionStorage.removeItem("rb_token"); token = ""; clearInterval(timer); $("app").hidden = true; $("login").hidden = false; $("out").hidden = true; }

  function renderList(alerts) {
    var box = $("list"); box.replaceChildren();
    if (!alerts.length) box.appendChild(el("p", "mu", "No alerts yet."));
    alerts.forEach(function (a) {
      var b = el("button", "row" + (cur === a.id ? " on" : ""));
      b.type = "button";
      b.appendChild(el("span", "dot s-" + a.severity));
      var t = el("span"); t.appendChild(document.createTextNode(a.title));
      t.appendChild(el("small", null, (a.host || a.user || a.src_ip || "") + " · " + when(a.ts)));
      b.appendChild(t); b.appendChild(el("span", "tag", a.status));
      b.addEventListener("click", function () { cur = a.id; loadDetail(); refresh(); });
      box.appendChild(b);
    });
  }

  function loadDetail() {
    if (!cur) return;
    api("/api/alerts/" + cur).then(function (a) {
      var d = $("det"); d.replaceChildren();
      d.appendChild(el("h2", null, a.title));
      d.appendChild(el("div", "mu", a.severity + " · " + a.status + " · rule " + a.rule_id));
      var t = a.triage;
      if (t) {
        d.appendChild(el("p", null, t.summary));
        d.appendChild(el("div", "mu", "Verdict: " + t.verdict.replace("_", " ") + " (" + Math.round(t.confidence * 100) + "%) · " + t.engine));
        var ul = el("ul"); t.steps.forEach(function (s) { ul.appendChild(el("li", null, s)); }); d.appendChild(ul);
      } else { d.appendChild(el("p", "mu", "Waiting for triage.")); }
      if (a.proposed_action) d.appendChild(el("div", "box", "Proposed action: " + a.proposed_action.kind.replace("_", " ") + " → " + a.proposed_action.target));
      var open = a.status === "triaged" || a.status === "failed";
      var acts = el("div", "acts"), ok = el("button", "btn", "Approve action"), no = el("button", "btn o", "Dismiss");
      ok.disabled = !(a.status === "triaged" && a.proposed_action); no.disabled = !open;
      ok.addEventListener("click", function () { act("approve"); }); no.addEventListener("click", function () { act("dismiss"); });
      acts.appendChild(ok); acts.appendChild(no); d.appendChild(acts);
      var m = el("div", "msg"); m.id = "msg"; d.appendChild(m);
      d.appendChild(el("h2", null, "Events")); var pre = el("pre");
      pre.textContent = a.events.map(function (e) { return when(e.ts) + "  " + [e.host, e.user, e.src_ip, e.process, e.cmdline || e.message].filter(Boolean).join(" | "); }).join("\n");
      d.appendChild(pre);
    });
  }
  function act(kind) {
    api("/api/alerts/" + cur + "/" + kind, "POST").then(function (r) { loadDetail(); refresh(); setTimeout(function () { var m = $("msg"); if (m) m.textContent = r.result || r.status; }, 150); })
      .catch(function (e) { var m = $("msg"); if (m) { m.textContent = e.message; m.style.color = "var(--da)"; } });
  }
  function table(id, head, rows) {
    var t = $(id); t.replaceChildren();
    var tr = el("tr"); head.forEach(function (h) { tr.appendChild(el("th", null, h)); }); t.appendChild(tr);
    rows.forEach(function (r) { var x = el("tr"); r.forEach(function (c) { x.appendChild(el("td", null, c)); }); t.appendChild(x); });
  }
  function refresh() {
    api("/api/alerts").then(renderList);
    api("/api/license").then(function (l) {
      $("lic").textContent = l.state + (l.plan ? " · " + l.plan : "") + (l.days_left != null ? " · " + l.days_left + "d left" : "");
      var b = $("banner"); b.hidden = l.state === "active" || l.state === "dev"; b.textContent = l.message;
    });
    api("/api/stats").then(function (s) { $("stats").textContent = s.events + " events · " + s.open_alerts + " open alerts · audit " + (s.audit_intact ? "intact" : "TAMPERED") + " · model " + (s.llm === "none" ? "heuristic only" : s.llm + (s.llm_redaction ? " (redacted)" : "")); });
    api("/api/cases").then(function (c) { table("ct", ["Case", "Entity", "Severity", "Status", "Opened"], c.map(function (x) { return [String(x.id), x.entity, x.severity, x.status, when(x.ts)]; })); });
    api("/api/audit").then(function (a) { table("at", ["Time", "Actor", "Event", "Alert", "Detail"], a.map(function (x) { return [when(x.ts), x.actor, x.kind, x.alert_id == null ? "" : String(x.alert_id), x.detail]; })); });
  }
  function start() { $("login").hidden = true; $("app").hidden = false; $("out").hidden = false; refresh(); timer = setInterval(refresh, 5000); }

  $("lf").addEventListener("submit", function (e) {
    e.preventDefault(); token = $("tok").value.trim();
    api("/api/stats").then(function () { sessionStorage.setItem("rb_token", token); $("lerr").textContent = ""; start(); })
      .catch(function () { $("lerr").textContent = "That token was not accepted."; });
  });
  $("out").addEventListener("click", signOut);
  document.querySelectorAll(".tabs button").forEach(function (b) {
    b.addEventListener("click", function () {
      document.querySelectorAll(".tabs button").forEach(function (x) { x.classList.toggle("on", x === b); });
      ["alerts", "cases", "audit"].forEach(function (n) { $("v-" + n).hidden = n !== b.dataset.t; });
    });
  });
  if (token) api("/api/stats").then(start).catch(function () {});
})();
