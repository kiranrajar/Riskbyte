"""Event Normalization into OCSF v1.1.0 & ECS Formats."""
from __future__ import annotations
import base64, hashlib, json, time, struct, socket
from typing import Dict, Any, Optional


def compute_community_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int = 6) -> str:
    """Generate standard Community ID v1 flow hash for network event correlation."""
    try:
        sip = socket.inet_aton(src_ip)
        dip = socket.inet_aton(dst_ip)
    except OSError:
        # Return fallback hash for non-IPv4 or unparsable addresses
        feed = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{proto}".encode("utf-8")
        return "1:" + base64.b64encode(hashlib.sha1(feed).digest()).decode("ascii")

    # Order lowest endpoint first to ensure flow bidirectionality
    is_ordered = (sip < dip) or (sip == dip and src_port <= dst_port)
    if is_ordered:
        pack_data = struct.pack(">H4s4sBBHH", 0, sip, dip, proto, 0, src_port, dst_port)
    else:
        pack_data = struct.pack(">H4s4sBBHH", 0, dip, sip, proto, 0, dst_port, src_port)

    digest = hashlib.sha1(pack_data).digest()
    return "1:" + base64.b64encode(digest).decode("ascii")


def normalize_event(raw: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Map heterogeneous telemetry into normalized OCSF Security Finding structure."""
    ts = raw.get("timestamp") or raw.get("ts") or time.time()
    if isinstance(ts, (int, float)):
        iso_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    else:
        iso_ts = str(ts)

    # Extract source-specific fields
    host = raw.get("host") or raw.get("agent", {}).get("name") or raw.get("device", {}).get("hostname")
    user = raw.get("user") or raw.get("data", {}).get("srcuser") or raw.get("user", {}).get("name")
    src_ip = raw.get("src_ip") or raw.get("id.orig_h") or raw.get("data", {}).get("srcip")
    dst_ip = raw.get("dst_ip") or raw.get("id.resp_h") or raw.get("data", {}).get("dstip")
    src_port = int(raw.get("src_port") or raw.get("id.orig_p") or 0)
    dst_port = int(raw.get("dst_port") or raw.get("id.resp_p") or 0)
    process = raw.get("process") or raw.get("process", {}).get("name")
    cmdline = raw.get("cmdline") or raw.get("process", {}).get("cmdline") or raw.get("message")

    # Community ID
    community_id = raw.get("community_id")
    if not community_id and src_ip and dst_ip and src_port and dst_port:
        community_id = compute_community_id(src_ip, dst_ip, src_port, dst_port)

    # Severity mapping
    sev_raw = str(raw.get("severity") or raw.get("alert", {}).get("severity") or "info").lower()
    if sev_raw in ("critical", "4", "high_critical"):
        severity = "critical"
        severity_id = 4
    elif sev_raw in ("high", "3"):
        severity = "high"
        severity_id = 3
    elif sev_raw in ("medium", "2"):
        severity = "medium"
        severity_id = 2
    else:
        severity = "low"
        severity_id = 1

    return {
        "timestamp": iso_ts,
        "collector": {"source": source, "ingest_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        "severity": severity,
        "severity_id": severity_id,
        "device": {"hostname": host, "ip": src_ip},
        "user": {"name": user},
        "src_endpoint": {"ip": src_ip, "port": src_port},
        "dst_endpoint": {"ip": dst_ip, "port": dst_port},
        "network": {"community_id": community_id},
        "process": {"name": process, "cmdline": cmdline},
        "raw_payload": json.dumps(raw, default=str)
    }

