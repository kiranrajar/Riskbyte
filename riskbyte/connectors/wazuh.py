"""Wazuh Connector: Manager REST API (:55000) & Wazuh Indexer OpenSearch (:9200)."""
from __future__ import annotations
import base64, json, logging, time, urllib.error, urllib.request, ssl
from typing import Dict, Any, List, Optional, Tuple

from .base import BaseConnector, HealthCheckResult, CircuitBreakerOpenException

log = logging.getLogger("riskbyte.connectors.wazuh")


class WazuhConnector(BaseConnector):
    """Integrates with Wazuh Manager REST API and Wazuh Indexer."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.username = config.get("username", "wazuh-wui")
        self.password = config.get("password", "")
        self.indexer_url = config.get("indexer_url", "").rstrip("/")
        self.verify_ssl = bool(config.get("verify_ssl", True))
        self._jwt_token: Optional[str] = None
        self._jwt_expires: float = 0.0

    def _ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get_token(self) -> str:
        now = time.time()
        if self._jwt_token and now < self._jwt_expires - 60:
            return self._jwt_token

        url = f"{self.endpoint_url.rstrip('/')}/security/user/authenticate"
        auth_hdr = "Basic " + base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        req = urllib.request.Request(url, headers={"Authorization": auth_hdr}, method="POST")

        with urllib.request.urlopen(req, context=self._ssl_context(), timeout=10) as r:
            payload = json.loads(r.read())
            self._jwt_token = payload["data"]["token"]
            self._jwt_expires = now + 900  # Wazuh tokens default to 15m
            return self._jwt_token

    def _api_call(self, endpoint: str, method: str = "GET", body: Optional[dict] = None) -> dict:
        if not self.circuit_breaker.can_execute():
            raise CircuitBreakerOpenException(f"Circuit breaker is OPEN for {self.name}")
        if not self.rate_limiter.acquire():
            raise RuntimeError(f"Rate limit exceeded on connector {self.name}")

        token = self._get_token()
        url = f"{self.endpoint_url.rstrip('/')}{endpoint}"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        data = json.dumps(body).encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        t0 = time.time()
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
            res = self._api_call("/")
            latency = int((time.time() - t0) * 1000)
            version = res.get("data", {}).get("title", "Wazuh API")
            return HealthCheckResult(
                is_healthy=True,
                status="connected",
                latency_ms=latency,
                message=f"Connected to Wazuh Manager ({version})",
                last_sync=self.last_sync_time
            )
        except Exception as exc:
            latency = int((time.time() - t0) * 1000)
            return HealthCheckResult(
                is_healthy=False,
                status="error",
                latency_ms=latency,
                message=f"Wazuh connection failed: {exc}",
                last_error=str(exc)
            )

    def pull(self, since: float, limit: int = 100) -> List[Dict[str, Any]]:
        """Pull recent security alerts from Wazuh Indexer OpenSearch or Manager."""
        events = []
        if self.indexer_url:
            query = {
                "size": limit,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since))
                        }
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            req = urllib.request.Request(
                f"{self.indexer_url}/wazuh-alerts-*/_search",
                data=json.dumps(query).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, context=self._ssl_context(), timeout=15) as r:
                    hits = json.loads(r.read()).get("hits", {}).get("hits", [])
                    for h in hits:
                        events.append(h["_source"])
            except Exception as e:
                log.warning("Wazuh Indexer query failed: %s; falling back to agent status", e)

        # Fallback to fetching agents status from Manager API
        if not events:
            try:
                res = self._api_call(f"/agents?limit={limit}&select=id,name,ip,status,os")
                items = res.get("data", {}).get("affected_items", [])
                self.last_sync_time = time.time()
                for it in items:
                    events.append({
                        "source": "wazuh_agent",
                        "agent_id": it.get("id"),
                        "host": it.get("name"),
                        "ip": it.get("ip"),
                        "status": it.get("status"),
                        "os": it.get("os", {}).get("name", "")
                    })
            except Exception as exc:
                self.last_error = str(exc)
        return events

    def act(self, action: str, target: str, params: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Execute active response (e.g. host isolation)."""
        if action == "isolate_host":
            # Call Wazuh Active Response API
            body = {
                "command": "firewall-drop",
                "custom": True,
                "alert": {"data": {"srcip": target}}
            }
            try:
                res = self._api_call("/active-response", method="PUT", body=body)
                return True, f"Wazuh active-response firewall-drop executed against {target}", {"rollback_action": "unblock", "target": target}
            except Exception as e:
                return False, f"Failed to execute Wazuh active-response: {e}", None
        return False, f"Action '{action}' unsupported by Wazuh connector", None
