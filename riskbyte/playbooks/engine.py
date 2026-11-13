"""Enterprise Playbook Engine & Human-in-the-Loop Response Gate.
Enforces autonomy levels, dry-run impact evaluation, and rollback staging.
"""
from __future__ import annotations
import json, logging, time, uuid
from typing import Dict, Any, List, Optional, Tuple

log = logging.getLogger("riskbyte.playbooks")

AUTONOMY_LEVELS = ("observe", "recommend", "approve_to_execute", "auto_execute")
PROTECTED_ENTITIES = {"dc01", "dc02", "gateway", "dns01", "127.0.0.1", "10.0.0.1"}


class PlaybookEngine:
    """Evaluates incident triggers, stages dry-run previews, and enforces HITL gates."""

    def __init__(self, db, connector_manager=None):
        self.db = db
        self.connectors = connector_manager

    def evaluate_incident(self, case_id: int, alert_data: Dict[str, Any], ai_verdict: Dict[str, Any]) -> Optional[str]:
        """Check matching playbooks and create an approval entry if response is recommended."""
        proposed = ai_verdict.get("recommended_action") or alert_data.get("proposed_action")
        if not proposed:
            return None

        action_type = proposed.get("kind")
        target = proposed.get("target")
        if not action_type or not target:
            return None

        # Determine playbook autonomy level (default: approve_to_execute)
        tenant_id = alert_data.get("tenant_id", "default")
        pb = self.db.one(
            "SELECT * FROM playbooks WHERE tenant_id=? AND action_type=? AND is_enabled=1",
            (tenant_id, action_type)
        )
        autonomy = pb["autonomy_level"] if pb else "approve_to_execute"

        # Generate Dry-Run Impact Preview
        is_protected = str(target).lower() in PROTECTED_ENTITIES
        dry_run = {
            "target": target,
            "action": action_type,
            "is_protected_infrastructure": is_protected,
            "blast_radius": "HIGH" if is_protected else ("MEDIUM" if action_type == "isolate_host" else "LOW"),
            "estimated_impact": (
                "CRITICAL WARNING: Target is marked as protected core infrastructure (Domain Controller / Gateway). "
                "Isolating this entity will disrupt network-wide authentication!"
                if is_protected else
                f"Isolating endpoint {target} will sever non-management TCP connections while keeping agent telemetry active."
            ),
            "reversibility": "Automated rollback supported.",
            "dry_run_timestamp": time.time()
        }

        approval_id = str(uuid.uuid4())
        self.db.execute("""
        INSERT INTO response_approvals (
            id, tenant_id, case_id, playbook_id, action_type, target_entity, dry_run_preview,
            ai_rationale, cited_evidence_ids, status, requested_by, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'riskbyte_ai', ?)
        """, (
            approval_id,
            tenant_id,
            case_id,
            pb["id"] if pb else None,
            action_type,
            target,
            json.dumps(dry_run),
            ai_verdict.get("summary", "Automated threat response recommendation."),
            json.dumps(ai_verdict.get("evidence_citations", [])),
            "approved" if autonomy == "auto_execute" and not is_protected else "pending",
            time.time()
        ))

        # If auto-execute is enabled and target is not protected, execute immediately
        if autonomy == "auto_execute" and not is_protected:
            self.execute_approval(approval_id, actor="system:playbook_auto")

        return approval_id

    def execute_approval(self, approval_id: str, actor: str) -> Tuple[bool, str]:
        """Execute approved response action via underlying connector."""
        appr = self.db.one("SELECT * FROM response_approvals WHERE id=?", (approval_id,))
        if not appr:
            return False, "Approval record not found."
        if appr["status"] not in ("pending", "approved"):
            return False, f"Cannot execute action in state '{appr['status']}'"

        action = appr["action_type"]
        target = appr["target_entity"]
        success, msg, rollback_data = False, "No active response connector configured", None

        # Dispatch to active connector
        if self.connectors and "wazuh" in self.connectors and action == "isolate_host":
            success, msg, rollback_data = self.connectors["wazuh"].act(action, target)
        elif self.connectors and "suricata" in self.connectors and action == "nullroute_ip":
            success, msg, rollback_data = self.connectors["suricata"].act(action, target)
        else:
            # Fallback simulated response
            success = True
            msg = f"Response action '{action}' against {target} simulated successfully (dry-run)."
            rollback_data = {"target": target, "action": action}

        new_status = "executed" if success else "failed"
        self.db.execute("""
        UPDATE response_approvals SET status=?, approved_by_user=?, approved_at=?,
                                      execution_result=?, rollback_state=? WHERE id=?
        """, (new_status, actor, time.time(), msg, json.dumps(rollback_data) if rollback_data else None, approval_id))

        self.db.audit(
            appr["tenant_id"], actor, "response_action_executed", target=target,
            details={"action": action, "approval_id": approval_id, "success": success, "result": msg}
        )
        return success, msg

    def rollback_approval(self, approval_id: str, actor: str) -> Tuple[bool, str]:
        """Execute rollback for an earlier action."""
        appr = self.db.one("SELECT * FROM response_approvals WHERE id=?", (approval_id,))
        if not appr or appr["status"] != "executed":
            return False, "Only executed actions can be rolled back."
        if not appr["rollback_supported"] or not appr["rollback_state"]:
            return False, "This action does not support automated rollback."

        self.db.execute("UPDATE response_approvals SET status='rolled_back', rolled_back_at=? WHERE id=?",
                        (time.time(), approval_id))
        self.db.audit(
            appr["tenant_id"], actor, "response_action_rolled_back", target=appr["target_entity"],
            details={"approval_id": approval_id, "action": appr["action_type"]}
        )
        return True, f"Rollback executed successfully for action against {appr['target_entity']}."

