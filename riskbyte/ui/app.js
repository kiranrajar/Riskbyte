(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var token = sessionStorage.getItem("rb_token") || "dev-analyst";
  var currentAlertId = null;
  var currentFilter = "";
  var chatHistory = [];
  var isGenerating = false;
  var investigationLog = [];
  var refreshTimer = null;

  /* ============================================================
     API CLIENT
     ============================================================ */
  function api(path, method, body) {
    var opts = {
      method: method || "GET",
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json"
      }
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
        return j;
      });
    });
  }

  function when(ts) {
    if (!ts) return "—";
    var d = new Date(ts * 1000);
    return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  /* ============================================================
     MARKDOWN RENDERER
     ============================================================ */
  function renderMarkdown(src) {
    if (!src) return "";
    var text = String(src);

    // Escape raw HTML entities
    text = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

    // Code blocks ```lang ... ```
    text = text.replace(/```([a-z0-9_-]*)\n([\s\S]*?)```/gi, function (_, lang, code) {
      return "<pre><code>" + code.trim() + "</code></pre>";
    });

    // Inline code `...`
    text = text.replace(/`([^`\n]+)`/g, "<code>$1</code>");

    // Headers
    text = text.replace(/^### (.*$)/gim, "<h3>$1</h3>");
    text = text.replace(/^## (.*$)/gim, "<h2>$1</h2>");
    text = text.replace(/^# (.*$)/gim, "<h1>$1</h1>");

    // Bold & italic
    text = text.replace(/\*\*\*([^*]+)\*\*\*/g, "<strong><em>$1</em></strong>");
    text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    text = text.replace(/\*([^*]+)\*/g, "<em>$1</em>");

    // Blockquotes
    text = text.replace(/^> (.*$)/gim, "<blockquote>$1</blockquote>");

    // Unordered lists
    text = text.replace(/^(?:[-*]|\+)\s+(.*)$/gim, "<li>$1</li>");
    text = text.replace(/(<li>.*<\/li>(\n|$)(\s*))+/g, "<ul>$&</ul>");

    // Numbered lists
    text = text.replace(/^\d+\.\s+(.*)$/gim, "<li>$1</li>");

    // Tables
    text = text.replace(/((?:\|[^\n]+\|\r?\n)+)/g, function (tableText) {
      var lines = tableText.trim().split("\n");
      if (lines.length < 2) return tableText;
      var html = "<table>";
      lines.forEach(function (line, idx) {
        var clean = line.replace(/^\||\|$/g, "");
        var cells = clean.split("|");
        if (idx === 0) {
          html += "<thead><tr>";
          cells.forEach(function (c) { html += "<th>" + c.trim() + "</th>"; });
          html += "</tr></thead><tbody>";
        } else if (idx === 1 && line.indexOf("---") !== -1) {
          // delimiter row
        } else {
          html += "<tr>";
          cells.forEach(function (c) { html += "<td>" + c.trim() + "</td>"; });
          html += "</tr>";
        }
      });
      return html + "</tbody></table>";
    });

    // Paragraphs
    var paragraphs = text.split(/\n{2,}/);
    var formatted = paragraphs.map(function (p) {
      p = p.trim();
      if (!p) return "";
      if (/^<(h[1-3]|ul|ol|pre|table|blockquote)/i.test(p)) return p;
      return "<p>" + p.replace(/\n/g, "<br>") + "</p>";
    }).join("\n");

    return formatted;
  }

  /* ============================================================
     NAVIGATION & VIEW SWITCHING
     ============================================================ */
  function switchView(viewName) {
    document.querySelectorAll(".nav-item").forEach(function (b) {
      b.classList.toggle("active", b.dataset.view === viewName);
    });
    document.querySelectorAll(".view").forEach(function (v) {
      v.classList.toggle("active", v.id === "v-" + viewName);
    });

    var titles = {
      agent: "AI Analyst",
      alerts: "Alerts & Incidents",
      cases: "Investigation Cases",
      audit: "Tamper-Evident Audit Trail"
    };
    var t = $("topbarTitle");
    if (t) t.textContent = titles[viewName] || "RiskByte SOC";

    if (viewName === "alerts") refreshAlerts();
    if (viewName === "cases") refreshCases();
    if (viewName === "audit") refreshAudit();
  }

  document.querySelectorAll(".nav-item").forEach(function (btn) {
    btn.addEventListener("click", function () {
      switchView(btn.dataset.view);
      var sb = $("sidebar");
      if (window.innerWidth < 820 && sb) sb.classList.remove("mobile-open");
    });
  });

  // Sidebar toggle
  var sidebarToggle = $("sidebarToggle");
  if (sidebarToggle) {
    sidebarToggle.addEventListener("click", function () {
      var sb = $("sidebar");
      var mw = $("mainWrap");
      var isCol = sb.classList.toggle("collapsed");
      if (mw) mw.classList.toggle("sidebar-collapsed", isCol);
      sessionStorage.setItem("rb_sb_collapsed", isCol ? "1" : "0");
    });
  }

  var menuBtn = $("menuBtn");
  if (menuBtn) {
    menuBtn.addEventListener("click", function () {
      var sb = $("sidebar");
      if (sb) sb.classList.toggle("mobile-open");
    });
  }

  if (sessionStorage.getItem("rb_sb_collapsed") === "1") {
    var sb = $("sidebar");
    var mw = $("mainWrap");
    if (sb) sb.classList.add("collapsed");
    if (mw) mw.classList.add("sidebar-collapsed");
  }

  /* ============================================================
     AI ANALYST CHAT
     ============================================================ */
  var STAGES = [
    "Understanding request & parsing intent…",
    "Selecting authorized investigation tools…",
    "Querying telemetry & threat indicators…",
    "Correlating evidence & MITRE ATT&CK…",
    "Synthesizing forensic findings…"
  ];

  function addChatMessage(role, content, toolsUsed) {
    var messagesBox = $("chatMessages");
    var welcome = $("chatWelcome");
    if (welcome) welcome.style.display = "none";

    var row = document.createElement("div");
    row.className = "msg-row " + role;

    var meta = document.createElement("div");
    meta.className = "msg-meta";
    meta.textContent = role === "user" ? "You" : "RiskByte AI";
    row.appendChild(meta);

    // If tools were used, render tool execution card
    if (toolsUsed && toolsUsed.length) {
      toolsUsed.forEach(function (tool) {
        var tb = document.createElement("div");
        tb.className = "tool-block";
        var trow = document.createElement("div");
        trow.className = "tool-row";
        var tname = document.createElement("span");
        tname.className = "tool-name";
        tname.textContent = "⚙ Tool: " + (tool.tool || "investigation");
        var tstat = document.createElement("span");
        tstat.className = "tool-status " + (tool.status || "completed");
        tstat.textContent = tool.status || "completed";
        trow.appendChild(tname);
        trow.appendChild(tstat);
        tb.appendChild(trow);
        if (tool.alert_id) {
          var tdetail = document.createElement("div");
          tdetail.style.cssText = "font-size:11px;color:var(--txt3);margin-top:2px;";
          tdetail.textContent = "Extracted forensic telemetry for Alert #" + tool.alert_id;
          tb.appendChild(tdetail);
        }
        row.appendChild(tb);
      });
    }

    var bubble = document.createElement("div");
    bubble.className = "msg-bubble";

    if (role === "assistant") {
      bubble.innerHTML = renderMarkdown(content);
    } else {
      bubble.textContent = content;
    }
    row.appendChild(bubble);

    // Copy button for assistant responses
    if (role === "assistant") {
      var actWrap = document.createElement("div");
      actWrap.className = "msg-actions";
      var cpBtn = document.createElement("button");
      cpBtn.className = "msg-action-btn";
      cpBtn.textContent = "Copy";
      cpBtn.addEventListener("click", function () {
        navigator.clipboard.writeText(content).then(function () {
          cpBtn.textContent = "Copied!";
          setTimeout(function () { cpBtn.textContent = "Copy"; }, 1500);
        });
      });
      actWrap.appendChild(cpBtn);
      row.appendChild(actWrap);
    }

    messagesBox.appendChild(row);
    messagesBox.scrollTop = messagesBox.scrollHeight;
  }

  function showThinking() {
    var messagesBox = $("chatMessages");
    var row = document.createElement("div");
    row.id = "thinkingRow";
    row.className = "msg-row assistant";

    var wrap = document.createElement("div");
    wrap.className = "thinking-indicator";

    var dots = document.createElement("div");
    dots.className = "thinking-dots";
    dots.innerHTML = "<span></span><span></span><span></span>";
    wrap.appendChild(dots);

    var label = document.createElement("span");
    label.id = "thinkingStage";
    label.textContent = STAGES[0];
    wrap.appendChild(label);

    row.appendChild(wrap);
    messagesBox.appendChild(row);
    messagesBox.scrollTop = messagesBox.scrollHeight;

    // Cycle through stages
    var stageIdx = 0;
    var stageTimer = setInterval(function () {
      if (!isGenerating) {
        clearInterval(stageTimer);
        return;
      }
      stageIdx = (stageIdx + 1) % STAGES.length;
      var el = $("thinkingStage");
      if (el) el.textContent = STAGES[stageIdx];
    }, 1800);
  }

  function hideThinking() {
    var row = $("thinkingRow");
    if (row) row.remove();
  }

  function sendChatMessage(text) {
    if (!text || !text.trim() || isGenerating) return;
    text = text.trim();

    var input = $("composerInput");
    if (input) {
      input.value = "";
      input.style.height = "auto";
    }
    var sendBtn = $("sendBtn");
    if (sendBtn) sendBtn.disabled = true;

    // Add user message to UI and history
    addChatMessage("user", text);
    chatHistory.push({ role: "user", content: text });

    // Track investigation in session
    investigationLog.unshift({ prompt: text, time: Math.floor(Date.now() / 1000) });
    renderInvestigationHistory();

    isGenerating = true;
    var statusText = $("agentStatusText");
    if (statusText) {
      statusText.textContent = "Investigating…";
      statusText.className = "agent-status-text working";
    }

    showThinking();

    api("/api/agent/chat", "POST", { messages: chatHistory })
      .then(function (res) {
        hideThinking();
        isGenerating = false;
        if (statusText) {
          statusText.textContent = "Ready to investigate";
          statusText.className = "agent-status-text";
        }
        var reply = res.reply || "No response received.";
        chatHistory.push({ role: "assistant", content: reply });
        addChatMessage("assistant", reply, res.tools_used);
      })
      .catch(function (err) {
        hideThinking();
        isGenerating = false;
        if (statusText) {
          statusText.textContent = "Ready";
          statusText.className = "agent-status-text";
        }
        addChatMessage("assistant", "⚠️ **Investigation Error**: " + err.message + "\n\nPlease ensure the backend has a configured LLM provider and try again.");
      });
  }

  // Auto-resize composer
  var composerInput = $("composerInput");
  if (composerInput) {
    composerInput.addEventListener("input", function () {
      this.style.height = "auto";
      this.style.height = Math.min(this.scrollHeight, 160) + "px";
      var sendBtn = $("sendBtn");
      if (sendBtn) sendBtn.disabled = !this.value.trim() || isGenerating;
    });

    composerInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage(this.value);
      }
    });
  }

  var sendBtn = $("sendBtn");
  if (sendBtn) {
    sendBtn.addEventListener("click", function () {
      if (composerInput) sendChatMessage(composerInput.value);
    });
  }

  // Suggestion buttons
  var suggestionGrid = $("suggestionGrid");
  if (suggestionGrid) {
    suggestionGrid.querySelectorAll(".suggestion-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var prompt = btn.dataset.prompt;
        if (prompt) sendChatMessage(prompt);
      });
    });
  }

  // New chat button
  var newChatBtn = $("newChatBtn");
  if (newChatBtn) {
    newChatBtn.addEventListener("click", function () {
      chatHistory = [];
      var messagesBox = $("chatMessages");
      if (messagesBox) {
        messagesBox.replaceChildren();
        var welcome = $("chatWelcome");
        if (welcome) {
          welcome.style.display = "flex";
          messagesBox.appendChild(welcome);
        }
      }
      var statusText = $("agentStatusText");
      if (statusText) {
        statusText.textContent = "Ready to investigate";
        statusText.className = "agent-status-text";
      }
    });
  }

  // Render investigation history in context panel
  function renderInvestigationHistory() {
    var box = $("ctx-history");
    if (!box) return;
    box.replaceChildren();
    if (!investigationLog.length) {
      var emp = document.createElement("div");
      emp.className = "ctx-empty";
      emp.textContent = "No investigations this session";
      box.appendChild(emp);
      return;
    }
    investigationLog.slice(0, 5).forEach(function (item) {
      var div = document.createElement("div");
      div.className = "ctx-history-item";
      div.textContent = item.prompt;
      div.title = item.prompt;
      div.addEventListener("click", function () {
        switchView("agent");
        sendChatMessage(item.prompt);
      });
      box.appendChild(div);
    });
  }

  /* ============================================================
     ALERTS MODULE
     ============================================================ */
  function renderAlertList(alerts) {
    var list = $("alertList");
    if (!list) return;
    list.replaceChildren();

    var filtered = alerts;
    if (currentFilter) {
      filtered = alerts.filter(function (a) { return a.status === currentFilter; });
    }

    if (!filtered.length) {
      var p = document.createElement("p");
      p.style.cssText = "padding:24px 16px;font-size:12px;color:var(--txt3);text-align:center;";
      p.textContent = currentFilter ? "No alerts matching '" + currentFilter + "'" : "No alerts recorded yet";
      list.appendChild(p);
      return;
    }

    filtered.forEach(function (a) {
      var sev = (a.severity || "info").toLowerCase();
      var row = document.createElement("button");
      row.type = "button";
      row.className = "alert-row" + (currentAlertId === a.id ? " active" : "");

      // Severity bar
      var sevBar = document.createElement("span");
      sevBar.className = "alert-row-sev c-" + sev;
      row.appendChild(sevBar);

      // Body
      var body = document.createElement("div");
      body.className = "alert-row-body";
      var title = document.createElement("div");
      title.className = "alert-row-title";
      title.textContent = a.title;
      var meta = document.createElement("div");
      meta.className = "alert-row-meta";
      meta.textContent = (a.host || a.user || a.src_ip || "telemetry") + " · " + when(a.ts);
      body.appendChild(title);
      body.appendChild(meta);
      row.appendChild(body);

      // Status chip
      var stWrap = document.createElement("div");
      stWrap.className = "alert-row-status";
      var chip = document.createElement("span");
      chip.className = "status-chip sc-" + a.status;
      chip.textContent = a.status.replace("_", " ");
      stWrap.appendChild(chip);
      row.appendChild(stWrap);

      row.addEventListener("click", function () {
        currentAlertId = a.id;
        loadAlertDetail(a.id);
        renderAlertList(alerts);
      });

      list.appendChild(row);
    });
  }

  function loadAlertDetail(aid) {
    var col = $("alertDetailCol");
    if (!col) return;

    api("/api/alerts/" + aid)
      .then(function (a) {
        col.replaceChildren();

        var pane = document.createElement("div");
        pane.className = "detail-pane";

        // Title
        var h2 = document.createElement("h2");
        h2.className = "detail-title";
        h2.textContent = a.title;
        pane.appendChild(h2);

        // Meta row
        var meta = document.createElement("div");
        meta.className = "detail-meta-row";

        var sev = (a.severity || "info").toLowerCase();
        var sevBadge = document.createElement("span");
        sevBadge.className = "sev-badge sev-" + sev;
        sevBadge.textContent = a.severity;
        meta.appendChild(sevBadge);

        meta.appendChild(document.createTextNode(" "));

        var stBadge = document.createElement("span");
        stBadge.className = "status-chip sc-" + a.status;
        stBadge.textContent = a.status.replace("_", " ");
        meta.appendChild(stBadge);

        var ruleSpan = document.createElement("span");
        ruleSpan.className = "detail-muted";
        ruleSpan.textContent = "Rule " + a.rule_id + " · Case #" + a.case_id;
        meta.appendChild(ruleSpan);

        var t = a.triage;
        if (t && t.verdict) {
          var vBadge = document.createElement("span");
          vBadge.className = "verdict-badge vb-" + t.verdict.toLowerCase();
          vBadge.textContent = t.verdict.replace("_", " ");
          meta.appendChild(vBadge);

          if (t.confidence) {
            var conf = document.createElement("span");
            conf.className = "detail-muted";
            conf.textContent = Math.round(t.confidence * 100) + "% confidence";
            meta.appendChild(conf);
          }
        }
        pane.appendChild(meta);

        // One-click AI Investigation button
        var aiInvestBtn = document.createElement("button");
        aiInvestBtn.className = "investigate-btn";
        aiInvestBtn.innerHTML = "<svg width='14' height='14' viewBox='0 0 16 16' fill='none'><circle cx='8' cy='8' r='6.5' stroke='currentColor' stroke-width='1.3'/><path d='M5.5 7.5C5.5 6.4 6.4 5.5 7.5 5.5h1C9.6 5.5 10.5 6.4 10.5 7.5c0 .8-.5 1.5-1.2 1.8L9 10H7l-.3-.7C6 9 5.5 8.3 5.5 7.5z' stroke='currentColor' stroke-width='1.2' stroke-linejoin='round'/><path d='M7.5 11.5h1' stroke='currentColor' stroke-width='1.5' stroke-linecap='round'/></svg> Investigate with RiskByte AI";
        aiInvestBtn.addEventListener("click", function () {
          switchView("agent");
          sendChatMessage("Investigate alert #" + a.id + " ('" + a.title + "'). What is the root cause, attacker intent, blast radius, and recommended remediation?");
        });
        pane.appendChild(aiInvestBtn);

        // AI Triage findings
        if (t) {
          var triageLabel = document.createElement("div");
          triageLabel.className = "section-label";
          triageLabel.textContent = "AI Analysis & Evidence";
          pane.appendChild(triageLabel);

          var summary = document.createElement("p");
          summary.className = "triage-summary";
          summary.textContent = t.summary;
          pane.appendChild(summary);

          if (t.engine) {
            var eng = document.createElement("div");
            eng.className = "detail-muted";
            eng.style.marginBottom = "10px";
            eng.textContent = "Engine: " + t.engine;
            pane.appendChild(eng);
          }

          if (t.steps && t.steps.length) {
            var ul = document.createElement("ul");
            ul.className = "triage-steps";
            t.steps.forEach(function (s) {
              var li = document.createElement("li");
              li.appendChild(document.createTextNode(s));
              var mitre = s.match(/\bT\d{4}(?:\.\d{3})?\b/g);
              if (mitre) {
                mitre.forEach(function (tid) {
                  var tag = document.createElement("span");
                  tag.className = "mitre-tag";
                  tag.textContent = tid;
                  li.appendChild(tag);
                });
              }
              ul.appendChild(li);
            });
            pane.appendChild(ul);
          }
        }

        // Proposed Response Action
        if (a.proposed_action) {
          var actLabel = document.createElement("div");
          actLabel.className = "section-label";
          actLabel.textContent = "Automated Response Gate";
          pane.appendChild(actLabel);

          var actBox = document.createElement("div");
          actBox.className = "action-box";
          var abLabel = document.createElement("div");
          abLabel.className = "action-box-label";
          abLabel.textContent = "Proposed Action: " + a.proposed_action.kind.replace("_", " ");
          actBox.appendChild(abLabel);
          actBox.appendChild(document.createTextNode("Target: " + a.proposed_action.target));
          pane.appendChild(actBox);
        }

        // Approve / Dismiss actions
        var canAct = a.status === "triaged" || a.status === "failed";
        var btnRow = document.createElement("div");
        btnRow.className = "btn-row";

        var okBtn = document.createElement("button");
        okBtn.className = "btn btn-primary";
        okBtn.textContent = "Approve Action";
        okBtn.disabled = !(a.status === "triaged" && a.proposed_action);

        var noBtn = document.createElement("button");
        noBtn.className = "btn btn-secondary";
        noBtn.textContent = "Dismiss";
        noBtn.disabled = !canAct;

        var actMsg = document.createElement("div");
        actMsg.className = "action-msg";

        okBtn.addEventListener("click", function () {
          api("/api/alerts/" + a.id + "/approve", "POST")
            .then(function (r) {
              actMsg.textContent = "Action executed: " + (r.result || r.status);
              loadAlertDetail(a.id);
              refreshAlerts();
            })
            .catch(function (e) {
              actMsg.textContent = "Error: " + e.message;
              actMsg.style.color = "var(--critical)";
            });
        });

        noBtn.addEventListener("click", function () {
          api("/api/alerts/" + a.id + "/dismiss", "POST")
            .then(function () {
              actMsg.textContent = "Alert dismissed.";
              loadAlertDetail(a.id);
              refreshAlerts();
            })
            .catch(function (e) {
              actMsg.textContent = "Error: " + e.message;
              actMsg.style.color = "var(--critical)";
            });
        });

        btnRow.appendChild(okBtn);
        btnRow.appendChild(noBtn);
        pane.appendChild(btnRow);
        pane.appendChild(actMsg);

        // Raw Events
        var evLabel = document.createElement("div");
        evLabel.className = "section-label";
        evLabel.textContent = "Raw Telemetry (" + (a.events ? a.events.length : 0) + " events)";
        pane.appendChild(evLabel);

        var pre = document.createElement("pre");
        pre.className = "events-log";
        pre.textContent = (a.events || []).map(function (e) {
          return when(e.ts) + "  " + [e.host, e.user, e.src_ip, e.process, e.cmdline || e.message].filter(Boolean).join(" | ");
        }).join("\n");
        pane.appendChild(pre);

        col.appendChild(pane);
      })
      .catch(function (err) {
        col.innerHTML = "<div class='detail-empty'><p>Failed to load alert: " + err.message + "</p></div>";
      });
  }

  // Filter buttons in Alerts view
  document.querySelectorAll(".filter-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll(".filter-btn").forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");
      currentFilter = btn.dataset.status;
      refreshAlerts();
    });
  });

  /* ============================================================
     CASES MODULE
     ============================================================ */
  function refreshCases() {
    api("/api/cases")
      .then(function (cases) {
        var tbody = document.querySelector("#caseTable tbody");
        if (!tbody) return;
        tbody.replaceChildren();

        if (!cases.length) {
          var tr = document.createElement("tr");
          tr.innerHTML = "<td colspan='5' style='text-align:center;color:var(--txt3);padding:24px;'>No investigation cases found</td>";
          tbody.appendChild(tr);
          return;
        }

        cases.forEach(function (c) {
          var tr = document.createElement("tr");
          tr.style.cursor = "pointer";
          tr.innerHTML =
            "<td><strong>#" + c.id + "</strong></td>" +
            "<td>" + (c.entity || "—") + "</td>" +
            "<td><span class='sev-badge sev-" + (c.severity || "info").toLowerCase() + "'>" + c.severity + "</span></td>" +
            "<td><span class='status-chip sc-" + c.status + "'>" + c.status + "</span></td>" +
            "<td>" + when(c.ts) + "</td>";

          tr.addEventListener("click", function () {
            switchView("agent");
            sendChatMessage("Investigate Case #" + c.id + " for entity '" + c.entity + "'. What alerts are associated with it and what is the current threat assessment?");
          });
          tbody.appendChild(tr);
        });
      })
      .catch(function () {});
  }

  /* ============================================================
     AUDIT TRAIL MODULE
     ============================================================ */
  function refreshAudit() {
    api("/api/audit")
      .then(function (entries) {
        var tbody = document.querySelector("#auditTable tbody");
        if (!tbody) return;
        tbody.replaceChildren();

        if (!entries.length) {
          var tr = document.createElement("tr");
          tr.innerHTML = "<td colspan='5' style='text-align:center;color:var(--txt3);padding:24px;'>No audit records yet</td>";
          tbody.appendChild(tr);
          return;
        }

        entries.forEach(function (a) {
          var tr = document.createElement("tr");
          var detailStr = "";
          try {
            var d = typeof a.detail === "string" ? JSON.parse(a.detail) : a.detail;
            detailStr = Object.keys(d || {}).map(function (k) { return k + "=" + d[k]; }).join(", ");
          } catch (_) {
            detailStr = String(a.detail || "");
          }
          tr.innerHTML =
            "<td>" + when(a.ts) + "</td>" +
            "<td><code>" + a.actor + "</code></td>" +
            "<td><strong>" + a.kind + "</strong></td>" +
            "<td>" + (a.alert_id ? "#" + a.alert_id : "—") + "</td>" +
            "<td style='font-size:11.5px;color:var(--txt3);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>" + (detailStr || "—") + "</td>";
          tbody.appendChild(tr);
        });
      })
      .catch(function () {});
  }

  /* ============================================================
     GLOBAL DATA REFRESH (STATS, ALERTS, HEALTH)
     ============================================================ */
  function refreshAlerts() {
    api("/api/alerts")
      .then(function (alerts) {
        renderAlertList(alerts);
        renderContextAlerts(alerts);
      })
      .catch(function () {});
  }

  function renderContextAlerts(alerts) {
    var box = $("ctx-alert-list");
    if (!box) return;
    box.replaceChildren();

    if (!alerts.length) {
      var emp = document.createElement("div");
      emp.className = "ctx-empty";
      emp.textContent = "No alerts yet";
      box.appendChild(emp);
      return;
    }

    alerts.slice(0, 5).forEach(function (a) {
      var item = document.createElement("div");
      item.className = "ctx-alert-item";

      var dot = document.createElement("span");
      dot.className = "ctx-sev-dot c-" + (a.severity || "info").toLowerCase();
      item.appendChild(dot);

      var body = document.createElement("div");
      body.style.minWidth = "0";
      var t = document.createElement("div");
      t.className = "ctx-alert-title";
      t.textContent = a.title;
      var m = document.createElement("div");
      m.className = "ctx-alert-meta";
      m.textContent = (a.host || a.src_ip || "host") + " · " + a.status;
      body.appendChild(t);
      body.appendChild(m);
      item.appendChild(body);

      item.addEventListener("click", function () {
        switchView("alerts");
        currentAlertId = a.id;
        loadAlertDetail(a.id);
      });

      box.appendChild(item);
    });
  }

  function refreshStats() {
    api("/api/stats")
      .then(function (s) {
        // Topbar
        var me = $("m-events"); if (me) me.textContent = (s.events || 0).toLocaleString();
        var ma = $("m-alerts"); if (ma) ma.textContent = s.open_alerts != null ? s.open_alerts : "—";
        var mc = $("m-cases"); if (mc) mc.textContent = s.open_cases != null ? s.open_cases : "—";

        // Badges
        var nba = $("nb-alerts");
        if (nba) {
          nba.textContent = s.open_alerts > 0 ? s.open_alerts : "";
          nba.style.display = s.open_alerts > 0 ? "flex" : "none";
        }
        var nbc = $("nb-cases");
        if (nbc) {
          nbc.textContent = s.open_cases > 0 ? s.open_cases : "";
          nbc.style.display = s.open_cases > 0 ? "flex" : "none";
        }

        // Context panel
        var cse = $("cs-events"); if (cse) cse.textContent = (s.events || 0).toLocaleString();
        var csa = $("cs-alerts"); if (csa) csa.textContent = s.open_alerts != null ? s.open_alerts : "—";
        var csc = $("cs-cases"); if (csc) csc.textContent = s.open_cases != null ? s.open_cases : "—";
        var csm = $("cs-model");
        if (csm) {
          csm.textContent = s.llm === "none" ? "Heuristic" : s.llm;
          csm.title = "Engine: " + s.llm + (s.llm_redaction ? " (redacted)" : "");
        }

        // Health dot
        var hdot = $("health-dot");
        var htext = $("health-text");
        if (hdot) hdot.className = "status-dot ok";
        if (htext) htext.textContent = s.audit_intact ? "Audit intact" : "Audit tampered";
      })
      .catch(function () {
        var hdot = $("health-dot");
        var htext = $("health-text");
        if (hdot) hdot.className = "status-dot err";
        if (htext) htext.textContent = "Offline";
      });

    api("/api/license")
      .then(function (l) {
        var lic = $("lic");
        if (lic) lic.textContent = l.state.toUpperCase() + (l.plan ? " · " + l.plan : "");
        var b = $("banner");
        if (b) {
          b.hidden = l.state === "active" || l.state === "dev";
          b.textContent = l.message || "";
        }
      })
      .catch(function () {});
  }

  function refreshAll() {
    refreshStats();
    refreshAlerts();
  }

  /* ============================================================
     INIT
     ============================================================ */
  function init() {
    refreshAll();
    refreshTimer = setInterval(refreshAll, 6000);
  }

  init();
})();
