"""Zeek Connector: JSON Log Stream Consumer & Community_ID Correlator."""
from __future__ import annotations
import glob, json, logging, os, time
from typing import Dict, Any, List, Optional, Tuple

from .base import BaseConnector, HealthCheckResult

log = logging.getLogger("riskbyte.connectors.zeek")


class ZeekConnector(BaseConnector):
    """Consumes Zeek JSON logs and provides Community_ID flow correlation."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logs_dir = config.get("logs_dir", "/var/log/zeek/current")

    def health(self) -> HealthCheckResult:
        t0 = time.time()
        if not os.path.isdir(self.logs_dir):
            return HealthCheckResult(
                is_healthy=False,
                status="disconnected",
                latency_ms=int((time.time() - t0) * 1000),
                message=f"Zeek logs directory '{self.logs_dir}' not found on host.",
                last_error="Directory not found"
            )

        log_files = glob.glob(os.path.join(self.logs_dir, "*.log"))
        latency = int((time.time() - t0) * 1000)
        if not log_files:
            return HealthCheckResult(
                is_healthy=True,
                status="degraded",
                latency_ms=latency,
                message=f"Zeek log directory exists but contains no active log streams.",
                last_sync=self.last_sync_time
            )

        newest_mtime = max(os.path.getmtime(p) for p in log_files)
        age = int(time.time() - newest_mtime)
        status = "connected" if age < 300 else "degraded"
        return HealthCheckResult(
            is_healthy=True,
            status=status,
            latency_ms=latency,
            message=f"Connected to Zeek streams ({len(log_files)} logs, newest modified {age}s ago)",
            last_sync=newest_mtime
        )

    def pull(self, since: float, limit: int = 100) -> List[Dict[str, Any]]:
        """Scan active notice.log and conn.log for security events."""
        events = []
        target_logs = ["notice.log", "conn.log", "dns.log", "intel.log"]
        for name in target_logs:
            p = os.path.join(self.logs_dir, name)
            if not os.path.exists(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 32768))
                    for line in reversed(f.readlines()):
                        line = line.strip()
                        if line and line.startswith("{"):
                            try:
                                d = json.loads(line)
                                d["_zeek_stream"] = name
                                events.append(d)
                                if len(events) >= limit:
                                    break
                            except json.JSONDecodeError:
                                pass
            except Exception as e:
                log.warning("Error reading Zeek log %s: %s", name, e)
        self.last_sync_time = time.time()
        return events

    def enrich(self, entity_type: str, observable: str) -> Dict[str, Any]:
        """Correlate IP or Community ID against recent Zeek connection history."""
        if entity_type not in ("ip", "community_id"):
            return {}

        matches = []
        conn_log = os.path.join(self.logs_dir, "conn.log")
        if os.path.exists(conn_log):
            try:
                with open(conn_log, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 65536))
                    for line in f.readlines():
                        if observable in line and line.strip().startswith("{"):
                            try:
                                matches.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
            except Exception:
                pass
        return {"zeek_matches": len(matches), "recent_flows": matches[:5]}

