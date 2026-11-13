"""Splunk Connector: REST Search Jobs (:8089) & HEC Ingestion."""
from __future__ import annotations
import json, logging, time, urllib.error, urllib.request, urllib.parse, ssl
from typing import Dict, Any, List, Optional, Tuple

from .base import BaseConnector, HealthCheckResult, CircuitBreakerOpenException

log = logging.getLogger("riskbyte.connectors.splunk")


class SplunkConnector(BaseConnector):
    """Integrates with Splunk Enterprise REST API and HTTP Event Collector (HEC)."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_token = config.get("api_token", "")
        self.hec_url = config.get("hec_url", "").rstrip("/")
        self.hec_token = config.get("hec_token", "")
        self.verify_ssl = bool(config.get("verify_ssl", True))

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def health(self) -> HealthCheckResult:
        t0 = time.time()
        url = f"{self.endpoint_url.rstrip('/')}/services/server/info?output_mode=json"
        headers = {"Authorization": f"Bearer {self.api_token}"}
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ssl_context(), timeout=10) as r:
                res = json.loads(r.read())
                latency = int((time.time() - t0) * 1000)
                ver = res.get("generator", {}).get("version", "Splunk")
                return HealthCheckResult(
                    is_healthy=True,
                    status="connected",
                    latency_ms=latency,
                    message=f"Connected to Splunk Enterprise ({ver})",
                    last_sync=self.last_sync_time
                )
        except Exception as exc:
            return HealthCheckResult(
                is_healthy=False,
                status="error",
                latency_ms=int((time.time() - t0) * 1000),
                message=f"Splunk connection failed: {exc}",
                last_error=str(exc)
            )

    def pull(self, since: float, limit: int = 100) -> List[Dict[str, Any]]:
        """Query notable events or security alerts via Splunk search job."""
        events = []
        search_query = f"search index=riskbyte OR tag=notable earliest={int(since)} | head {limit}"
        url = f"{self.endpoint_url.rstrip('/')}/services/search/jobs"
        data = urllib.parse.urlencode({"search": search_query, "output_mode": "json", "exec_mode": "oneshot"}).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.api_token}"}
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, context=self._ssl_context(), timeout=30) as r:
                res = json.loads(r.read())
                results = res.get("results", [])
                for it in results:
                    events.append(it)
            self.last_sync_time = time.time()
        except Exception as exc:
            self.last_error = str(exc)
            log.warning("Splunk search job failed: %s", exc)
        return events

    def send_hec_event(self, event_data: dict, sourcetype: str = "riskbyte:soc:agent") -> bool:
        """Send event to Splunk HTTP Event Collector."""
        if not self.hec_url or not self.hec_token:
            return False
        payload = {
            "time": time.time(),
            "sourcetype": sourcetype,
            "event": event_data
        }
        url = f"{self.hec_url}/services/collector/event"
        headers = {"Authorization": f"Splunk {self.hec_token}", "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=self._ssl_context(), timeout=10) as r:
                return r.status == 200
        except Exception:
            return False
