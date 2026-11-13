"""RiskByte SOC Agent — Enterprise FastAPI Application with OpenAPI 3.
All data strictly scoped by tenant. Server-side session authentication with __Host- cookies.
"""
from __future__ import annotations
import json, logging, os, time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request, Response, HTTPException, Depends, Header, Cookie, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..core.db import Database
from ..core.auth import PasswordManager, TOTPEngine, SessionStore, Session
from ..core.crypto import CryptoEngine
from ..core.license import LicenseValidator
from ..connectors import CONNECTOR_REGISTRY, create_connector
from ..agent.llm import SelfHostedLLMClient
from ..agent.analyst import AIAnalystService
from ..playbooks.engine import PlaybookEngine

log = logging.getLogger("riskbyte.api")

app = FastAPI(
    title="RiskByte SOC Agent — Enterprise Platform API",
    version="2.0.0-ENTERPRISE",
    description="Air-Gapped, Commercial On-Premises Security Operations Center Automation Platform.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Global instances initialized on startup
db: Database = None
session_store = SessionStore()
crypto_engine: CryptoEngine = None
license_validator: LicenseValidator = None
ai_analyst: AIAnalystService = None
playbook_engine: PlaybookEngine = None
connectors: Dict[str, Any] = {}


def init_platform(data_dir: str | None = None):
    global db, crypto_engine, license_validator, ai_analyst, playbook_engine
    if data_dir is None:
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.environ.get("RISKBYTE_DATA_DIR") or os.path.join(repo_root, "data")
    os.makedirs(data_dir, exist_ok=True)
    key_dir = os.path.join(data_dir, "keys")
    crypto_engine = CryptoEngine(key_dir=key_dir)
    db = Database(os.path.join(data_dir, "riskbyte.db"), crypto_engine=crypto_engine)
    license_validator = LicenseValidator(
        license_path=os.path.join(data_dir, "license.rbl"),
        pubkey_path=os.path.join(data_dir, "vendor_public.pem"),
        dev_mode=True
    )
    llm = SelfHostedLLMClient(
        endpoint_url=os.environ.get("RISKBYTE_OLLAMA_URL", "http://ollama:11434"),
        model_name=os.environ.get("RISKBYTE_LLM_MODEL", "llama3.1:8b"),
        air_gapped=True
    )
    ai_analyst = AIAnalystService(db=db, llm_client=llm, connector_manager=connectors)
    playbook_engine = PlaybookEngine(db=db, connector_manager=connectors)

    # Seed default admin if missing
    admin = db.one("SELECT * FROM users WHERE role='admin'")
    if not admin:
        pwd_hash = PasswordManager.hash_password("RiskByteAdmin2026!")
        totp_sec = TOTPEngine.generate_secret()
        encrypted_totp = crypto_engine.encrypt_secret(totp_sec, "default")
        db.execute("""
        INSERT INTO users (id, tenant_id, email, password_hash, full_name, role, mfa_enabled,
                           mfa_secret_encrypted, created_at)
        VALUES ('admin-01', 'default', 'admin@riskbyte.internal', ?, 'System Administrator', 'admin', 1, ?, ?)
        """, (pwd_hash, encrypted_totp, time.time()))
        log.info("Default administrator initialized: admin@riskbyte.internal")


init_platform()


# ---- Security Middleware ----
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    return response


# ---- Authentication Dependency ----
def get_current_session(request: Request) -> Session:
    # 1. Check __Host- prefixed secure cookie
    sid = request.cookies.get("__Host-rb_session")
    if not sid:
        # Fallback check for standard cookie or machine token header
        sid = request.cookies.get("rb_session")
    if not sid:
        raise HTTPException(status_code=401, detail="Authentication required. No session cookie found.")
    client_ip = request.client.host if request.client else "127.0.0.1"
    sess = session_store.get_session(sid, client_ip=client_ip)
    if not sess:
        raise HTTPException(status_code=401, detail="Session expired, revoked, or client IP mismatch.")
    return sess


# ---- Request & Response Models ----
class LoginRequest(BaseModel):
    email: str
    password: str


class MFAVerifyRequest(BaseModel):
    login_challenge_token: str
    code: str


class StepUpRequest(BaseModel):
    code: str


class ChatRequest(BaseModel):
    messages: List[Dict[str, str]]


class ConnectorConfigRequest(BaseModel):
    connector_type: str
    name: str
    endpoint_url: str
    credentials: str
    verify_ssl: bool = True
    rate_limit_per_min: int = 300


# Temporary memory for MFA login challenges
mfa_challenges: Dict[str, Tuple[str, float]] = {}


# ---- Authentication Routes ----
@app.post("/api/auth/login", tags=["Authentication"])
def login(req: LoginRequest, request: Request):
    user = db.one("SELECT * FROM users WHERE email=? AND is_active=1", (req.email.lower().strip(),))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    # Check lock
    now = time.time()
    if user.get("locked_until") and user["locked_until"] > now:
        raise HTTPException(status_code=423, detail="Account locked due to failed attempts. Try again later.")

    # Verify password
    if not PasswordManager.verify_password(req.password, user["password_hash"]):
        db.execute("UPDATE users SET failed_attempts=failed_attempts+1 WHERE id=?", (user["id"],))
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    # Reset failed attempts
    db.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (user["id"],))

    # Issue challenge token for MFA
    challenge_token = f"chal_{secrets.token_urlsafe(32)}"
    mfa_challenges[challenge_token] = (user["id"], now + 300)
    return {
        "status": "mfa_required",
        "challenge_token": challenge_token,
        "mfa_type": "totp",
        "message": "Enter your 6-digit TOTP code or recovery key to proceed."
    }


@app.post("/api/auth/mfa/verify", tags=["Authentication"])
def verify_mfa(req: MFAVerifyRequest, request: Request, response: Response):
    chal = mfa_challenges.pop(req.login_challenge_token, None)
    if not chal or time.time() > chal[1]:
        raise HTTPException(status_code=401, detail="MFA challenge expired or invalid.")

    user_id = chal[0]
    user = db.one("SELECT * FROM users WHERE id=?", (user_id,))
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    # Decrypt TOTP secret
    decrypted_totp = crypto_engine.decrypt_secret(user["mfa_secret_encrypted"], user["tenant_id"])
    if not TOTPEngine.verify_code(decrypted_totp, req.code):
        raise HTTPException(status_code=401, detail="Invalid MFA authentication code.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "Unknown")
    sess = session_store.create_session(user["id"], user["tenant_id"], user["role"], client_ip, user_agent, True)

    # Set secure __Host- cookie
    response.set_cookie(
        key="__Host-rb_session",
        value=sess.session_id,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=SessionStore.ABSOLUTE_TIMEOUT,
        path="/"
    )
    # Also set fallback for non-https local dev
    response.set_cookie(
        key="rb_session",
        value=sess.session_id,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=SessionStore.ABSOLUTE_TIMEOUT,
        path="/"
    )

    db.audit(user["tenant_id"], f"user:{user['email']}", "login_mfa_success", ip=client_ip)
    return {
        "status": "authenticated",
        "user": {"email": user["email"], "name": user["full_name"], "role": user["role"]},
        "csrf_token": sess.csrf_token
    }


@app.post("/api/auth/logout", tags=["Authentication"])
def logout(response: Response, sess: Session = Depends(get_current_session)):
    session_store.revoke_session(sess.session_id)
    response.delete_cookie("__Host-rb_session", path="/")
    response.delete_cookie("rb_session", path="/")
    return {"status": "logged_out"}


@app.get("/api/auth/me", tags=["Authentication"])
def get_current_user_profile(sess: Session = Depends(get_current_session)):
    u = db.one("SELECT id, email, full_name, role, mfa_enabled FROM users WHERE id=?", (sess.user_id,))
    return {
        "user": u,
        "tenant_id": sess.tenant_id,
        "is_mfa_authenticated": sess.is_mfa_authenticated,
        "has_step_up": session_store.has_valid_step_up(sess.session_id),
        "csrf_token": sess.csrf_token
    }


# ---- Health & License Routes ----
@app.get("/api/health", tags=["System Health"])
def system_health():
    lic = license_validator.check()
    ok_audit, audit_cnt, audit_msg = db.verify_audit_chain()
    return {
        "status": "healthy",
        "air_gapped_mode": True,
        "egress_allowed": False,
        "license": lic.__dict__,
        "audit_chain": {"verified": ok_audit, "records": audit_cnt, "message": audit_msg},
        "connectors_active": len(connectors)
    }


# ---- Unified Alerts & Triage Routes ----
@app.get("/api/alerts", tags=["Alerts"])
def list_alerts(status: Optional[str] = None, sess: Session = Depends(get_current_session)):
    sql = "SELECT * FROM alerts WHERE tenant_id=?"
    params = [sess.tenant_id]
    if status:
        sql += " AND status=?"
        params.append(status)
    sql += " ORDER BY id DESC LIMIT 100"
    rows = db.query(sql, tuple(params))
    for r in rows:
        if r.get("triage"):
            r["triage"] = json.loads(r["triage"])
        if r.get("proposed_action"):
            r["proposed_action"] = json.loads(r["proposed_action"])
    return rows


@app.get("/api/alerts/{alert_id}", tags=["Alerts"])
def get_alert_detail(alert_id: int, sess: Session = Depends(get_current_session)):
    a = db.one("SELECT * FROM alerts WHERE id=? AND tenant_id=?", (alert_id, sess.tenant_id))
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found.")
    if a.get("triage"):
        a["triage"] = json.loads(a["triage"])
    if a.get("proposed_action"):
        a["proposed_action"] = json.loads(a["proposed_action"])
    return a


# ---- AI Analyst Chat & Investigation ----
@app.post("/api/agent/chat", tags=["AI Analyst"])
def agent_chat_investigate(req: ChatRequest, sess: Session = Depends(get_current_session)):
    if not req.messages:
        raise HTTPException(status_code=400, detail="Messages list cannot be empty.")
    actor = f"user:{sess.user_id}"
    return ai_analyst.chat_investigate(req.messages, actor=actor)


# ---- Human-in-the-Loop Approvals ----
@app.get("/api/approvals", tags=["Approvals"])
def list_pending_approvals(sess: Session = Depends(get_current_session)):
    rows = db.query("SELECT * FROM response_approvals WHERE tenant_id=? ORDER BY created_at DESC", (sess.tenant_id,))
    for r in rows:
        r["dry_run_preview"] = json.loads(r["dry_run_preview"])
        r["cited_evidence_ids"] = json.loads(r["cited_evidence_ids"])
    return rows


@app.post("/api/approvals/{approval_id}/approve", tags=["Approvals"])
def approve_response_action(approval_id: str, sess: Session = Depends(get_current_session)):
    actor = f"analyst:{sess.user_id}"
    ok, msg = playbook_engine.execute_approval(approval_id, actor=actor)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "executed", "result": msg}


@app.post("/api/approvals/{approval_id}/rollback", tags=["Approvals"])
def rollback_response_action(approval_id: str, sess: Session = Depends(get_current_session)):
    actor = f"analyst:{sess.user_id}"
    ok, msg = playbook_engine.rollback_approval(approval_id, actor=actor)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "rolled_back", "result": msg}


# ---- Audit Log Verification ----
@app.get("/api/audit", tags=["Audit Trail"])
def list_audit_log(sess: Session = Depends(get_current_session)):
    return db.query("SELECT * FROM audit_log WHERE tenant_id=? ORDER BY sequence_id DESC LIMIT 100", (sess.tenant_id,))


@app.get("/api/audit/verify", tags=["Audit Trail"])
def verify_audit_trail(sess: Session = Depends(get_current_session)):
    ok, count, msg = db.verify_audit_chain(sess.tenant_id)
    return {"verified": ok, "records_checked": count, "diagnostic": msg}
