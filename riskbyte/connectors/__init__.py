"""Modular Connector Registry & Dispatcher."""
from .base import BaseConnector, HealthCheckResult, CircuitBreakerOpenException
from .wazuh import WazuhConnector
from .suricata import SuricataConnector
from .zeek import ZeekConnector
from .thehive import TheHiveConnector
from .splunk import SplunkConnector
from .misp import MISPConnector
from .cortex import CortexConnector

CONNECTOR_REGISTRY = {
    "wazuh": WazuhConnector,
    "suricata": SuricataConnector,
    "zeek": ZeekConnector,
    "thehive": TheHiveConnector,
    "splunk": SplunkConnector,
    "misp": MISPConnector,
    "cortex": CortexConnector
}

def create_connector(config: dict) -> BaseConnector:
    ctype = config.get("connector_type", "").lower()
    if ctype not in CONNECTOR_REGISTRY:
        raise ValueError(f"Unknown connector type '{ctype}'. Available: {list(CONNECTOR_REGISTRY.keys())}")
    return CONNECTOR_REGISTRY[ctype](config)
