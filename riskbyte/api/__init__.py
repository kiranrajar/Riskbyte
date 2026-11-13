"""RiskByte API Subsystem: FastAPI Enterprise REST API & Standard HTTP Server."""
try:
    from .app import app
except Exception:
    app = None

from .legacy_api import get_request_handler, make_server, CSP, UI, MAX_BODY

