"""Cortex Connector: Security Analyzers and Active Responders."""
from __future__ import annotations
import json, logging, time, urllib.error, urllib.request, ssl
from typing import Dict, Any, List, Optional, Tuple

from .base import BaseConnector, HealthCheckResult

log = logging.getLogger("riskbyte.connectors.cortex")


class CortexConnector(BaseConnector):
    """Executes on-premises Cortex analyzers and active response jobs."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get("api_key", "")
        self.verify_ssl = bool(config.get("verify_ssl", True))

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def health(self) -> HealthCheckResult:
        t0 = time.time()
        url = f"{self.endpoint_url.rstrip('/')}/api/status"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ssl_context(), timeout=10) as r:
                res = json.loads(r.read())
                latency = int((time.time() - t0) * 1000)
                return HealthCheckResult(
                    is_healthy=True,
                    status="connected",
                    latency_ms=latency,
                    message="Connected to Cortex Engine",
                    last_sync=self.last_sync_time
                )
        except Exception as exc:
            return HealthCheckResult(
                is_healthy=False,
                status="error",
                latency_ms=int((time.time() - t0) * 1000),
                message=f"Cortex connection failed: {exc}",
                last_error=str(exc)
            )

    def pull(self, since: float, limit: int = 100) -> List[Dict[str, Any]]:
        return []

    def run_analyzer(self, analyzer_id: str, data_type: str, data: str) -> Optional[dict]:
        """Run a local Cortex analyzer against an observable."""
        url = f"{self.endpoint_url.rstrip('/')}/api/analyzer/{analyzer_id}/run"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {"data": data, "dataType": data_type, "tlp": 2}
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=self._ssl_context(), timeout=30) as r:
                return json.loads(r.read())
        except Exception as e:
            log.error("Cortex analyzer %s failed: %s", analyzer_id, e)
            return None
