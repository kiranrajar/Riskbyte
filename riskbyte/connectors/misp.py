"""MISP Threat Intelligence Connector: Local/Self-Hosted Indicator Query."""
from __future__ import annotations
import json, logging, time, urllib.error, urllib.request, ssl
from typing import Dict, Any, List, Optional, Tuple

from .base import BaseConnector, HealthCheckResult

log = logging.getLogger("riskbyte.connectors.misp")


class MISPConnector(BaseConnector):
    """Queries self-hosted MISP instance for IOC matches without external egress."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.auth_key = config.get("auth_key", "")
        self.verify_ssl = bool(config.get("verify_ssl", True))
        self._local_cache: Dict[str, Tuple[float, dict]] = {}

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def health(self) -> HealthCheckResult:
        t0 = time.time()
        url = f"{self.endpoint_url.rstrip('/')}/servers/getVersion.json"
        headers = {"Authorization": self.auth_key, "Accept": "application/json"}
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ssl_context(), timeout=10) as r:
                res = json.loads(r.read())
                latency = int((time.time() - t0) * 1000)
                ver = res.get("version", "MISP")
                return HealthCheckResult(
                    is_healthy=True,
                    status="connected",
                    latency_ms=latency,
                    message=f"Connected to self-hosted MISP ({ver})",
                    last_sync=self.last_sync_time
                )
        except Exception as exc:
            return HealthCheckResult(
                is_healthy=False,
                status="error",
                latency_ms=int((time.time() - t0) * 1000),
                message=f"MISP connection failed: {exc}",
                last_error=str(exc)
            )

    def pull(self, since: float, limit: int = 100) -> List[Dict[str, Any]]:
        """Pull recent warning lists or attributes."""
        return []

    def enrich(self, entity_type: str, observable: str) -> Dict[str, Any]:
        """Search observable in MISP with 1-hour local cache."""
        now = time.time()
        if observable in self._local_cache:
            cached_time, cached_val = self._local_cache[observable]
            if now - cached_time < 3600:
                return cached_val

        url = f"{self.endpoint_url.rstrip('/')}/attributes/restSearch"
        headers = {
            "Authorization": self.auth_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        body = {"value": observable, "limit": 10}
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, context=self._ssl_context(), timeout=10) as r:
                res = json.loads(r.read())
                attributes = res.get("response", {}).get("Attribute", [])
                hit = len(attributes) > 0
                data = {
                    "is_known_threat": hit,
                    "misp_hits": len(attributes),
                    "tags": [t.get("name") for a in attributes for t in a.get("Tag", [])][:5]
                }
                self._local_cache[observable] = (now, data)
                return data
        except Exception as exc:
            log.warning("MISP enrichment query failed for %s: %s", observable, exc)
            return {"is_known_threat": False, "error": str(exc)}
