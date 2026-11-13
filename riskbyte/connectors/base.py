"""Enterprise Modular Connector Framework.
Base plugin interface, Circuit Breaker, Rate Limiter, and SSRF Guard.
"""
from __future__ import annotations
import abc, ipaddress, logging, time, urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass

log = logging.getLogger("riskbyte.connectors")


@dataclass
class HealthCheckResult:
    is_healthy: bool
    status: str              # "connected", "degraded", "disconnected", "error"
    latency_ms: int
    message: str
    last_sync: Optional[float] = None
    last_error: Optional[str] = None


class CircuitBreakerOpenException(Exception):
    pass


class CircuitBreaker:
    """Three-state circuit breaker: CLOSED -> OPEN -> HALF-OPEN."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self.failure_count = 0
        self.last_failure_time = 0.0

    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
            log.warning("Circuit breaker OPEN (threshold of %d failures reached)", self.failure_threshold)

    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF_OPEN"
                log.info("Circuit breaker entering HALF_OPEN recovery test")
                return True
            return False
        if self.state == "HALF_OPEN":
            return True
        return False


class RateLimiter:
    """Token-bucket rate limiter per integration instance."""

    def __init__(self, rate_per_minute: int = 300):
        self.capacity = float(rate_per_minute)
        self.tokens = self.capacity
        self.fill_rate = self.capacity / 60.0
        self.last_update = time.time()

    def acquire(self, tokens: int = 1) -> bool:
        now = time.time()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.fill_rate)
        self.last_update = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


def validate_connector_endpoint(url: str, allow_private: bool = True) -> str:
    """Validate connector URL scheme and prevent cloud-metadata SSRF attacks."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https", "unix"):
        raise ValueError(f"Invalid connector scheme '{parsed.scheme}'; only http, https, and unix sockets permitted.")
    if parsed.scheme in ("http", "https"):
        hostname = parsed.hostname or ""
        # Block cloud metadata addresses (AWS/GCP/Azure 169.254.169.254)
        if hostname == "169.254.169.254" or hostname == "metadata.google.internal":
            raise ValueError(f"SSRF violation: connection to cloud metadata endpoint blocked.")
    return url


class BaseConnector(abc.ABC):
    """Abstract base connector plugin interface."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.id = config.get("id", "connector-anon")
        self.name = config.get("name", "Unnamed Connector")
        self.endpoint_url = validate_connector_endpoint(config.get("endpoint_url", ""))
        self.rate_limiter = RateLimiter(int(config.get("rate_limit_per_min", 300)))
        self.circuit_breaker = CircuitBreaker()
        self.last_sync_time: Optional[float] = None
        self.last_error: Optional[str] = None

    @abc.abstractmethod
    def health(self) -> HealthCheckResult:
        """Execute live endpoint probe, measuring latency and certifying connectivity."""
        pass

    @abc.abstractmethod
    def pull(self, since: float, limit: int = 100) -> List[Dict[str, Any]]:
        """Poll telemetry/alerts from upstream sensor."""
        pass

    def enrich(self, entity_type: str, observable: str) -> Dict[str, Any]:
        """Optional enrichment for observables (IP, domain, hash, user). Defaults to empty dict."""
        return {}

    def act(self, action: str, target: str, params: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """Optional active response action. Returns (success, message, rollback_metadata)."""
        return False, f"Action '{action}' is not supported by connector {self.name}", None
