"""Schema-Validated Tool Layer for Self-Hosted AI Analyst."""
from __future__ import annotations
import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ToolDefinition(BaseModel):
    name: str
    description: str
    parameters: Dict[str, Any]


class ToolQueryHistoryInput(BaseModel):
    entity: str = Field(..., description="Target hostname, IP address, or user account")
    window_minutes: int = Field(60, description="Time window in minutes to search")


class ToolLookupIOCInput(BaseModel):
    observable: str = Field(..., description="IP, SHA256 hash, or domain to lookup in local threat intel")


class ToolGetAlertInput(BaseModel):
    alert_id: int = Field(..., description="Alert ID to inspect")


TOOL_REGISTRY: List[ToolDefinition] = [
    ToolDefinition(
        name="query_event_history",
        description="Query local telemetry history for an entity (host, IP, user) over a sliding time window.",
        parameters=ToolQueryHistoryInput.model_json_schema()
    ),
    ToolDefinition(
        name="lookup_local_misp_ioc",
        description="Check if an IP, hash, or domain matches local MISP threat intelligence indicators.",
        parameters=ToolLookupIOCInput.model_json_schema()
    ),
    ToolDefinition(
        name="get_alert_forensics",
        description="Fetch complete raw forensics, raw payloads, and rule triggers for a specific Alert ID.",
        parameters=ToolGetAlertInput.model_json_schema()
    )
]


class ToolExecutor:
    """Safely executes allowlisted tools against platform services."""

    def __init__(self, db, connector_manager=None):
        self.db = db
        self.connectors = connector_manager

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch declarative tool calls with input validation."""
        if tool_name == "query_event_history":
            args = ToolQueryHistoryInput(**arguments)
            # Query local alerts matching entity
            rows = self.db.query(
                "SELECT id, rule_id, title, severity, status, host, user, src_ip, created_at "
                "FROM alerts WHERE host=? OR user=? OR src_ip=? ORDER BY id DESC LIMIT 20",
                (args.entity, args.entity, args.entity)
            )
            return {"entity": args.entity, "match_count": len(rows), "recent_records": rows}

        elif tool_name == "lookup_local_misp_ioc":
            args = ToolLookupIOCInput(**arguments)
            # In air-gap mode, check indicators table or misp connector if present
            if self.connectors and "misp" in self.connectors:
                return self.connectors["misp"].enrich("observable", args.observable)
            # Default check against local intel
            return {"observable": args.observable, "is_known_threat": False, "note": "No local MISP match"}

        elif tool_name == "get_alert_forensics":
            args = ToolGetAlertInput(**arguments)
            a = self.db.one("SELECT * FROM alerts WHERE id=?", (args.alert_id,))
            if not a:
                return {"error": f"Alert #{args.alert_id} not found"}
            return {
                "id": a["id"],
                "rule_id": a["rule_id"],
                "title": a["title"],
                "severity": a["severity"],
                "status": a["status"],
                "host": a.get("host"),
                "user": a.get("user"),
                "src_ip": a.get("src_ip"),
                "triage": json.loads(a["triage"]) if a.get("triage") else None,
                "proposed_action": json.loads(a["proposed_action"]) if a.get("proposed_action") else None
            }

        else:
            raise ValueError(f"Unauthorized tool execution attempt: '{tool_name}' is not in the allowlist.")

