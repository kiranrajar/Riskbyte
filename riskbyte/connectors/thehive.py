"""TheHive 5 Connector: Bidirectional Incident & Case Sync."""
from __future__ import annotations
import json, logging, time, urllib.error, urllib.request, ssl
from typing import Dict, Any, List, Optional, Tuple

from .base import BaseConnector, HealthCheckResult, CircuitBreakerOpenException

log = logging.getLogger("riskbyte.connectors.thehive")


class TheHiveConnector(BaseConnector):
    """Bidirectional integration with TheHive 5 Case Management Platform."""

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

    def _api_call(self, endpoint: str, method: str = "GET", body: Optional[dict] = None) -> dict:
        if not self.circuit_breaker.can_execute():
            raise CircuitBreakerOpenException(f"Circuit breaker is OPEN for {self.name}")
        if not self.rate_limiter.acquire():
            raise RuntimeError(f"Rate limit exceeded on connector {self.name}")

        url = f"{self.endpoint_url.rstrip('/')}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, context=self._ssl_context(), timeout=15) as r:
                res = json.loads(r.read())
                self.circuit_breaker.record_success()
                return res
        except Exception as exc:
            self.circuit_breaker.record_failure()
            self.last_error = str(exc)
            raise

    def health(self) -> HealthCheckResult:
        t0 = time.time()
        try:
            # Query status
            res = self._api_call("/api/v1/status")
            latency = int((time.time() - t0) * 1000)
            return HealthCheckResult(
                is_healthy=True,
                status="connected",
                latency_ms=latency,
                message=f"Connected to TheHive 5 ({res.get('version', 'v5.x')})",
                last_sync=self.last_sync_time
            )
        except Exception as exc:
            return HealthCheckResult(
                is_healthy=False,
                status="error",
                latency_ms=int((time.time() - t0) * 1000),
                message=f"TheHive connection failed: {exc}",
                last_error=str(exc)
            )

    def pull(self, since: float, limit: int = 100) -> List[Dict[str, Any]]:
        """Pull open cases or alerts from TheHive."""
        try:
            query = {
                "query": [
                    {"_name": "listCase"},
                    {"_name": "filter", "_and": [{"_field": "status", "_value": "Open"}]},
                    {"_name": "sort", "_fields": [{"_field": "createdAt", "_order": "desc"}]},
                    {"_name": "page", "from": 0, "to": limit}
                ]
            }
            res = self._api_call("/api/v1/query", method="POST", body=query)
            cases = res if isinstance(res, list) else []
            self.last_sync_time = time.time()
            return cases
        except Exception as e:
            log.warning("TheHive pull failed: %s", e)
            return []

    def create_case(self, title: str, description: str, severity: int = 2, tags: Optional[List[str]] = None) -> Optional[str]:
        """Push a RiskByte incident into TheHive 5."""
        body = {
            "title": title,
            "description": description,
            "severity": severity,
            "startDate": int(time.time() * 1000),
            "tags": tags or ["RiskByte-SOC-Agent"],
            "flag": False
        }
        try:
            res = self._api_call("/api/v1/case", method="POST", body=body)
            return res.get("_id") or res.get("id")
        except Exception as exc:
            log.error("Failed to create TheHive case: %s", exc)
            return None

    def add_observable(self, case_id: str, data_type: str, value: str, message: str = "") -> bool:
        """Add observable to an existing TheHive case."""
        body = {
            "dataType": data_type,
            "data": value,
            "message": message,
            "tags": ["RiskByte-Enriched"]
        }
        try:
            self._api_call(f"/api/v1/case/{case_id}/observable", method="POST", body=body)
            return True
        except Exception:
            return False

