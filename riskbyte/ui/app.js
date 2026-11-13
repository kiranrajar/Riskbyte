(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var token = sessionStorage.getItem("rb_token") || "dev-analyst";
  var cur = null, timer = null;

  /* ---- Helpers ---- */
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function api(path, method) {
    return fetch(path, {
      method: method || "GET",
      headers: { Authorization: "Bearer " + token }
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(j.error || r.status);
        return j;
      });
    });
  }

  function when(ts) { return new Date(ts * 1000).toLocaleString(); }

  /* ---- Severity helpers ---- */
  var SEV_LABEL = {
    critical: "Critical", high: "High",
    medium: "Medium", low: "Low", info: "Info"
  };

  function sevClass(s) {
    if (!s) return "";
    return "s-" + s.toLowerCase();
  }

  /* ---- Alert List ---- */
  function renderList(alerts) {
    var box = $("list");
    box.replaceChildren();
    if (!alerts.length) {
      var p = el("p", "mu");
      p.style.cssText = "padding:24px 20px;font-size:13px;";
      p.textContent = "No alerts ingested yet.";
      box.appendChild(p);
      return;
    }
    alerts.forEach(function (a) {
      var sev = (a.severity || "info").toLowerCase();
      var row = el("button", "row " + sevClass(sev) + (cur === a.id ? " on" : ""));
      row.type = "button";

      /* Severity bar */
      row.appendChild(el("span", "sev-bar"));

      /* Body */
      var body = el("div", "row-body");
      var title = el("div", "row-title");
      title.textContent = a.title;
      var meta = el("div", "row-meta");
      meta.textContent = (a.host || a.user || a.src_ip || "") + " · " + when(a.ts);
      body.appendChild(title);
      body.appendChild(meta);
      row.appendChild(body);

      /* Badge */
      var badgeWrap = el("div", "row-badge");
      var badge = el("span", "sev-tag");
      badge.textContent = SEV_LABEL[sev] || sev;
      badgeWrap.appendChild(badge);
      row.appendChild(badgeWrap);

      row.addEventListener("click", function () { cur = a.id; loadDetail(); refresh(); });
      box.appendChild(row);
    });
  }

  /* ---- Detail Panel ---- */
  function loadDetail() {
    if (!cur) return;
    api("/api/alerts/" + cur).then(function (a) {
      var d = $("det");
      d.replaceChildren();

      /* Title */
      d.appendChild(el("h2", null, a.title));

      /* Meta row */
      var meta = el("div", "det-meta");
      var sev = (a.severity || "info").toLowerCase();

      var sevSpan = el("span", "sev-tag " + sevClass(sev));
      sevSpan.textContent = SEV_LABEL[sev] || sev;
      meta.appendChild(sevSpan);

      meta.appendChild(el("span", "det-sep mu", "·"));

      var statusSpan = el("span", "mu");
      statusSpan.style.fontSize = "12px";
      statusSpan.textContent = a.status.replace(/_/g, " ").toUpperCase();
      meta.appendChild(statusSpan);

      meta.appendChild(el("span", "det-sep mu", "·"));

      var ruleSpan = el("span", "mu");
      ruleSpan.style.fontSize = "12px";
      ruleSpan.textContent = "Rule " + a.rule_id;
      meta.appendChild(ruleSpan);

      var t = a.triage;
      if (t && t.verdict) {
        meta.appendChild(el("span", "det-sep mu", "·"));
        var vb = el("span", "verdict-badge " + t.verdict.toLowerCase().replace(/_/g, "_"));
        vb.textContent = t.verdict.replace(/_/g, " ");
        meta.appendChild(vb);

        var conf = el("span", "mu");
        conf.style.fontSize = "11px";
        conf.textContent = Math.round(t.confidence * 100) + "% confidence";
        meta.appendChild(conf);
      }

      d.appendChild(meta);

      /* Triage Section */
      if (t) {
        d.appendChild(el("div", "det-section-title", "AI Analysis"));

        var summary = el("p", "triage-summary");
        summary.textContent = t.summary;
        d.appendChild(summary);

        if (t.engine) {
          var eng = el("div", "mu");
          eng.style.cssText = "font-size:11px;margin-bottom:16px;";
          eng.textContent = "Engine: " + t.engine;
          d.appendChild(eng);
        }

        if (t.steps && t.steps.length) {
          d.appendChild(el("div", "det-section-title", "Reasoning Steps"));
          var ul = el("ul", "triage-steps");
          t.steps.forEach(function (s) {
            var li = el("li");
            /* Extract MITRE technique references like T1059, T1490 etc */
            var text = s;
            var mitre = s.match(/\bT\d{4}(?:\.\d{3})?\b/g);
            li.appendChild(document.createTextNode(text));
            if (mitre) {
              mitre.forEach(function (tid) {
                var tag = el("span", "mitre-tag");
                tag.textContent = tid;
                li.appendChild(tag);
              });
            }
            ul.appendChild(li);
          });
          d.appendChild(ul);
        }
      } else {
        var wait = el("p", "triage-summary mu");
        wait.textContent = "Triage pending — AI engine processing.";
        d.appendChild(wait);
      }

      /* Proposed Action */
      if (a.proposed_action) {
        d.appendChild(el("div", "det-section-title", "Proposed Response"));
        var box = el("div", "proposed-action-box");
        var lbl = el("strong");
        lbl.textContent = a.proposed_action.kind.replace(/_/g, " ");
        box.appendChild(lbl);
        box.appendChild(document.createTextNode(a.proposed_action.target));
        d.appendChild(box);
      }

      /* Actions */
      var open = a.status === "triaged" || a.status === "failed";
      var acts = el("div", "acts");
      var okBtn = el("button", "btn", "Approve Action");
      var noBtn = el("button", "btn o", "Dismiss");
      okBtn.disabled = !(a.status === "triaged" && a.proposed_action);
      noBtn.disabled = !open;
      okBtn.addEventListener("click", function () { act("approve"); });
      noBtn.addEventListener("click", function () { act("dismiss"); });
      acts.appendChild(okBtn);
      acts.appendChild(noBtn);
      d.appendChild(acts);

      var msg = el("div", "msg"); msg.id = "msg"; d.appendChild(msg);

      /* Events */
      d.appendChild(el("div", "det-section-title", "Raw Events"));
      var pre = el("pre", "events-log");
      pre.textContent = a.events.map(function (e) {
        return when(e.ts) + "  " +
          [e.host, e.user, e.src_ip, e.process, e.cmdline || e.message]
            .filter(Boolean).join(" | ");
      }).join("\n");
      d.appendChild(pre);
    });
  }

  function act(kind) {
    api("/api/alerts/" + cur + "/" + kind, "POST")
      .then(function (r) {
        loadDetail(); refresh();
        setTimeout(function () {
          var m = $("msg"); if (m) m.textContent = r.result || r.status;
        }, 150);
      })
      .catch(function (e) {
        var m = $("msg");
        if (m) { m.textContent = e.message; m.style.color = "var(--burgundy)"; }
      });
  }

  /* ---- Tables ---- */
  function table(id, head, rows) {
    var t = $(id);
    t.replaceChildren();
    var tr = el("tr");
    head.forEach(function (h) { tr.appendChild(el("th", null, h)); });
    t.appendChild(tr);
    rows.forEach(function (r) {
      var x = el("tr");
      r.forEach(function (c, i) {
        x.appendChild(el("td", null, c));
      });
      t.appendChild(x);
    });
  }

  /* ---- Metric Cards ---- */
  function updateMetrics(s) {
    var ev = $("m-events");
    if (ev) ev.textContent = s.events != null ? s.events.toLocaleString() : "—";

    var al = $("m-alerts");
    if (al) al.textContent = s.open_alerts != null ? s.open_alerts : "—";

    var cs = $("m-cases");
    /* Cases count comes separately — set placeholder here, updated in refresh */
    if (cs && s.open_cases != null) cs.textContent = s.open_cases;

    var md = $("m-model");
    if (md) {
      md.textContent = s.llm === "none" ? "Heuristic" : (s.llm || "—");
    }

    var au = $("m-audit");
    if (au) {
      au.textContent = s.audit_intact ? "Audit intact" : "⚠ AUDIT TAMPERED";
      au.style.color = s.audit_intact ? "" : "var(--burgundy)";
    }
  }

  /* ---- Refresh ---- */
  function refresh() {
    api("/api/alerts").then(renderList).catch(function () {});

    api("/api/license").then(function (l) {
      var lic = $("lic");
      if (lic) {
        lic.textContent = l.state.toUpperCase() +
          (l.plan ? " · " + l.plan : "") +
          (l.days_left != null ? " · " + l.days_left + "d" : "");
      }
      var b = $("banner");
      if (b) { b.hidden = l.state === "active" || l.state === "dev"; b.textContent = l.message; }
    }).catch(function () {});

    api("/api/stats").then(function (s) {
      updateMetrics(s);
      var st = $("stats");
      if (st) {
        st.textContent = (s.events || 0).toLocaleString() + " events · " +
          (s.open_alerts || 0) + " open · " +
          (s.audit_intact ? "audit intact" : "audit TAMPERED");
      }
    }).catch(function () {});

    api("/api/cases").then(function (c) {
      /* Update cases metric */
      var cs = $("m-cases");
      if (cs) cs.textContent = c.length;
      table("ct",
        ["Case", "Entity", "Severity", "Status", "Opened"],
        c.map(function (x) { return [String(x.id), x.entity, x.severity, x.status, when(x.ts)]; })
      );
    }).catch(function () {});

    api("/api/audit").then(function (a) {
      table("at",
        ["Time", "Actor", "Event", "Alert", "Detail"],
        a.map(function (x) {
          return [when(x.ts), x.actor, x.kind, x.alert_id == null ? "" : String(x.alert_id), x.detail];
        })
      );
    }).catch(function () {});
  }

  /* ---- Tab switching ---- */
  document.querySelectorAll(".tabs button").forEach(function (b) {
    b.addEventListener("click", function () {
      document.querySelectorAll(".tabs button").forEach(function (x) {
        x.classList.toggle("on", x === b);
      });
      ["alerts", "cases", "audit"].forEach(function (n) {
        var sec = $("v-" + n); if (sec) sec.hidden = n !== b.dataset.t;
      });
    });
  });

  /* ---- Start ---- */
  function start() {
    refresh();
    timer = setInterval(refresh, 5000);
  }

  start();
})();
