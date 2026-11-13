"""AI Analyst Investigation Service: Auto-triage, Evidence Correlation & Report Synthesis."""
from __future__ import annotations
import json, logging, re, time
from typing import Dict, Any, List, Optional, Tuple

from .llm import SelfHostedLLMClient
from .tools import ToolExecutor, TOOL_REGISTRY
from ..normalization.mitre import extract_mitre_techniques

log = logging.getLogger("riskbyte.agent.analyst")

VERDICTS = ("true_positive", "false_positive", "suspicious_needs_review", "insufficient_data")


class AIAnalystService:
    """Enterprise AI Analyst orchestrator enforcing zero fabrication and evidence citations."""

    def __init__(self, db, llm_client: Optional[SelfHostedLLMClient] = None, connector_manager=None):
        self.db = db
        self.llm = llm_client
        self.tools = ToolExecutor(db, connector_manager)

    def triage_alert(self, alert_data: Dict[str, Any], raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute automated triage on a newly ingested alert with evidence citations."""
        evidence_citations = [f"Alert #{alert_data.get('id')}", f"Rule {alert_data.get('rule_id')}"]
        if alert_data.get("host"):
            evidence_citations.append(f"Host: {alert_data.get('host')}")
        if alert_data.get("src_ip"):
            evidence_citations.append(f"Src IP: {alert_data.get('src_ip')}")

        # Scan for MITRE techniques in title, command lines, messages
        all_text = f"{alert_data.get('title','')} " + " ".join(
            f"{e.get('cmdline','')} {e.get('message','')}" for e in raw_events
        )
        mitre_hits = extract_mitre_techniques(all_text)

        # Fallback heuristic if local LLM is unconfigured / offline
        heuristic_verdict = "suspicious_needs_review"
        sev = str(alert_data.get("severity", "medium")).lower()
        if sev == "critical":
            heuristic_verdict = "true_positive"
        elif sev == "low" and not mitre_hits:
            heuristic_verdict = "insufficient_data"

        fallback_result = {
            "verdict": heuristic_verdict,
            "confidence": 0.85 if heuristic_verdict == "true_positive" else 0.50,
            "mitre_techniques": [f"{m['id']} — {m['name']}" for m in mitre_hits],
            "evidence_citations": evidence_citations,
            "summary": f"Alert '{alert_data.get('title')}' triggered at {sev.upper()} severity across {len(raw_events)} event(s).",
            "recommended_action": alert_data.get("proposed_action"),
            "engine": "heuristic:fallback",
            "timestamp": time.time()
        }

        if not self.llm or not self.llm.is_available():
            return fallback_result

        # Assemble strictly fenced prompt for local LLM
        system_prompt = (
            "You are RiskByte AI, a principal SOC investigation analyst. "
            "Analyze the alert and raw telemetry. Determine if this is a true_positive, false_positive, "
            "suspicious_needs_review, or insufficient_data. "
            "You must cite primary evidence for every claim. If evidence is lacking, state 'insufficient_data'. "
            "Reply strictly with a valid JSON object matching this schema:\n"
            '{"verdict": "true_positive|false_positive|suspicious_needs_review|insufficient_data", '
            '"confidence": 0.0-1.0, "summary": "...", "mitre_techniques": ["T1059.001 - PowerShell"], '
            '"evidence_citations": ["Alert #1", "Event log #12"], "recommended_action": {"kind": "isolate_host", "target": "..."}}'
        )

        prompt_data = {
            "alert": {
                "id": alert_data.get("id"),
                "title": alert_data.get("title"),
                "severity": alert_data.get("severity"),
                "host": alert_data.get("host"),
                "user": alert_data.get("user"),
                "src_ip": alert_data.get("src_ip")
            },
            "events_sample": [
                {"ts": e.get("ts"), "proc": e.get("process"), "cmd": e.get("cmdline")} for e in raw_events[:5]
            ]
        }

        user_content = f"<untrusted_evidence>{json.dumps(prompt_data, default=str)}</untrusted_evidence>"

        try:
            raw_llm = self.llm.generate(system_prompt, user_content, json_format=True)
            parsed = json.loads(raw_llm)
            v = parsed.get("verdict")
            if v in VERDICTS:
                return {
                    "verdict": v,
                    "confidence": float(parsed.get("confidence", 0.7)),
                    "mitre_techniques": parsed.get("mitre_techniques", [f"{m['id']} — {m['name']}" for m in mitre_hits]),
                    "evidence_citations": parsed.get("evidence_citations", evidence_citations),
                    "summary": str(parsed.get("summary", ""))[:600],
                    "recommended_action": parsed.get("recommended_action") or alert_data.get("proposed_action"),
                    "engine": f"llm:{self.llm.model_name}",
                    "timestamp": time.time()
                }
        except Exception as exc:
            log.warning("Local LLM triage inference failed: %s; using deterministic baseline", exc)

        return fallback_result

    def chat_investigate(self, messages: List[Dict[str, str]], actor: str) -> Dict[str, Any]:
        """Interactive analyst investigation conversation with tool invocation and live context."""
        last_msg = messages[-1].get("content", "") if messages else ""
        tools_executed = []

        # Tool detection: detect entity references in user query
        alert_matches = re.findall(r"\b(?:alert\s*#?|id\s*[:=]?)\s*(\d+)", last_msg, re.IGNORECASE)
        extra_evidence = ""
        for aid_str in alert_matches[:2]:
            aid = int(aid_str)
            try:
                forensics = self.tools.execute_tool("get_alert_forensics", {"alert_id": aid})
                extra_evidence += f"\n<untrusted_evidence>ALERT FORENSICS #{aid}:\n{json.dumps(forensics, default=str)}</untrusted_evidence>\n"
                tools_executed.append({"tool": "get_alert_forensics", "target": f"#{aid}", "status": "completed"})
            except Exception as e:
                tools_executed.append({"tool": "get_alert_forensics", "target": f"#{aid}", "status": "failed", "error": str(e)})

        # Tool detection: IP addresses or hostnames
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", last_msg)
        for ip in ip_matches[:2]:
            try:
                ioc = self.tools.execute_tool("lookup_local_misp_ioc", {"observable": ip})
                extra_evidence += f"\n<untrusted_evidence>IOC CHECK FOR {ip}:\n{json.dumps(ioc, default=str)}</untrusted_evidence>\n"
                tools_executed.append({"tool": "lookup_local_misp_ioc", "target": ip, "status": "completed"})
            except Exception:
                pass

        # Build prompt
        system_instruction = (
            "You are RiskByte AI, a senior incident responder. "
            "You assist analysts in investigating alerts, tracing attack chains, mapping MITRE ATT&CK techniques, "
            "and recommending remediation. All claims must cite real evidence records. "
            "Use clear markdown formatting with headers, lists, and bold text. "
            "If evidence is insufficient to reach a conclusion, state 'insufficient data' rather than guessing."
        )

        history_text = "\n".join(f"{m.get('role').capitalize()}: {m.get('content')}" for m in messages[:-1])
        full_prompt = f"{history_text}\nAnalyst: {last_msg}\n{extra_evidence}"

        if not self.llm or not self.llm.is_available():
            reply = (
                "⚠️ **Local AI Engine Unreachable**\n\n"
                "The configured self-hosted inference container (Ollama / vLLM) is currently offline or unreachable. "
                "Per RiskByte's enterprise security policy, no external cloud AI endpoints will be called. "
                "Please verify the Ollama service status on your cluster."
            )
            return {"reply": reply, "tools_used": tools_executed}

        try:
            reply = self.llm.generate(system_instruction, full_prompt, json_format=False)
            self.db.audit("default", actor, "ai_investigation_query", details={"query": last_msg[:120], "tools": len(tools_executed)})
            return {"reply": reply, "tools_used": tools_executed}
        except Exception as exc:
            return {
                "reply": f"⚠️ **Inference Error**: {exc}. Please verify the self-hosted LLM container.",
                "tools_used": tools_executed
            }

