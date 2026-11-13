"""MITRE ATT&CK Mapping & Matrixing."""
from __future__ import annotations
import re
from typing import Dict, Any, List, Tuple

MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1105": {"name": "Ingress Tool Transfer (LOLBin)", "tactic": "Command and Control"},
    "T1490": {"name": "Inhibit System Recovery (VSS Deletion)", "tactic": "Impact"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1021": {"name": "Remote Services (RDP/SSH)", "tactic": "Lateral Movement"},
    "T1071": {"name": "Application Layer Protocol (C2)", "tactic": "Command and Control"}
}

TECHNIQUE_REGEX = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)


def extract_mitre_techniques(text: str) -> List[Dict[str, str]]:
    """Scan command lines, signatures, and triage notes for MITRE ATT&CK technique IDs."""
    if not text:
        return []
    found = set(TECHNIQUE_REGEX.findall(text))
    results = []
    for tid in sorted(found):
        tid_upper = tid.upper()
        meta = MITRE_TECHNIQUES.get(tid_upper, {"name": "Security Technique", "tactic": "Threat Activity"})
        results.append({
            "id": tid_upper,
            "name": meta["name"],
            "tactic": meta["tactic"]
        })
    return results
