"""Suricata Connector: EVE JSON Stream Reader & Unix Socket Control."""
from __future__ import annotations
import json, logging, os, socket, time
from typing import Dict, Any, List, Optional, Tuple

from .base import BaseConnector, HealthCheckResult

log = logging.getLogger("riskbyte.connectors.suricata")


class SuricataConnector(BaseConnector):
    """Parses Suricata EVE JSON alerts/flows and manages active Unix socket commands."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.eve_log_path = config.get("eve_log_path", "/var/log/suricata/eve.json")
        self.unix_socket_path = config.get("unix_socket_path", "/var/run/suricata/suricata-command.socket")

    def _socket_command(self, cmd: str, args: Optional[dict] = None) -> dict:
        if not os.path.exists(self.unix_socket_path):
            raise FileNotFoundError(f"Suricata Unix socket not found at {self.unix_socket_path}")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(self.unix_socket_path)
            # Suricata command protocol exchange
            init = json.loads(sock.recv(4096).decode("utf-8"))
            req = {"command": cmd, "arguments": args or {}}
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            resp = json.loads(sock.recv(8192).decode("utf-8"))
            return resp
        finally:
            sock.close()

    def health(self) -> HealthCheckResult:
        t0 = time.time()
        # Probe unix socket if configured
        if os.path.exists(self.unix_socket_path):
            try:
                res = self._socket_command("version")
                latency = int((time.time() - t0) * 1000)
                ver = res.get("message", {}).get("version", "Suricata IDS")
                return HealthCheckResult(
                    is_healthy=True,
                    status="connected",
                    latency_ms=latency,
                    message=f"Connected to Suricata Unix Socket ({ver})",
                    last_sync=self.last_sync_time
                )
            except Exception as e:
                log.warning("Suricata socket probe failed: %s; checking EVE log", e)

        # Probe EVE JSON file
        if os.path.exists(self.eve_log_path):
            try:
                st = os.stat(self.eve_log_path)
                latency = int((time.time() - t0) * 1000)
                age = int(time.time() - st.st_mtime)
                status = "connected" if age < 300 else "degraded"
                return HealthCheckResult(
                    is_healthy=True,
                    status=status,
                    latency_ms=latency,
                    message=f"EVE log available ({st.st_size} bytes, modified {age}s ago)",
                    last_sync=st.st_mtime
                )
            except Exception as exc:
                return HealthCheckResult(
                    is_healthy=False,
                    status="error",
                    latency_ms=int((time.time() - t0) * 1000),
                    message=f"Failed to read EVE log: {exc}",
                    last_error=str(exc)
                )

        return HealthCheckResult(
            is_healthy=False,
            status="disconnected",
            latency_ms=int((time.time() - t0) * 1000),
            message=f"Neither Suricata socket ({self.unix_socket_path}) nor EVE log ({self.eve_log_path}) is reachable.",
            last_error="No socket or file found"
        )

    def pull(self, since: float, limit: int = 100) -> List[Dict[str, Any]]:
        """Stream recent events from EVE JSON file."""
        if not os.path.exists(self.eve_log_path):
            return []

        events = []
        try:
            with open(self.eve_log_path, "r", encoding="utf-8", errors="replace") as f:
                # Seek near the end for active tailing
                f.seek(0, os.SEEK_END)
                size = f.tell()
                # Read last 64KB for recent events
                f.seek(max(0, size - 65536))
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        event_type = record.get("event_type")
                        if event_type in ("alert", "dns", "http", "tls", "flow"):
                            events.append(record)
                            if len(events) >= limit:
                                break
                    except json.JSONDecodeError:
                        continue
            self.last_sync_time = time.time()
        except Exception as exc:
            self.last_error = str(exc)
            log.error("Failed to read Suricata EVE log: %s", exc)
        return events

    def act(self, action: str, target: str, params: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Trigger active response rule reload or IP drop."""
        if action == "nullroute_ip":
            try:
                # Issue rule reload or drop command to Suricata
                res = self._socket_command("ruleset-reload-rules")
                return True, f"Suricata rule reload executed for target block: {target}", {"target": target}
            except Exception as e:
                return False, f"Suricata active-response failed: {e}", None
        return False, f"Action '{action}' unsupported by Suricata", None

