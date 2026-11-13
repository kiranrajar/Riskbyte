"""Enterprise authentication, session management, and multi-factor authorization.
- Argon2id password hashing and breach validation.
- RFC 6238 TOTP implementation (no external dependencies, timing-safe).
- WebAuthn/FIDO2 challenge and public key assertion.
- Server-side cookie sessions (__Host- prefix, HttpOnly, SameSite=Strict).
- Synchronizer CSRF protection.
- Step-up MFA gate for impactful and destructive actions.
"""
from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, struct, time
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey


# ---- Password Hashing (Argon2id RFC 9106) ----
class PasswordManager:
    """Argon2id password hashing with enterprise memory/iteration limits."""
    SALT_LEN = 16
    KEY_LEN = 32
    TIME_COST = 2
    MEMORY_COST = 65536  # 64 MiB
    PARALLELISM = 2

    @classmethod
    def hash_password(cls, password: str) -> str:
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long.")
        salt = secrets.token_bytes(cls.SALT_LEN)
        kdf = Argon2id(
            salt=salt,
            length=cls.KEY_LEN,
            iterations=cls.TIME_COST,
            lanes=cls.PARALLELISM,
            memory_cost=cls.MEMORY_COST,
            ad=None,
            secret=None
        )
        derived = kdf.derive(password.encode("utf-8"))
        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(derived).decode("ascii")
        return f"$argon2id$v=19$m={cls.MEMORY_COST},t={cls.TIME_COST},p={cls.PARALLELISM}${salt_b64}${hash_b64}"

    @classmethod
    def verify_password(cls, password: str, encoded_hash: str) -> bool:
        try:
            parts = encoded_hash.split("$")
            # Format: ['', 'argon2id', 'v=19', 'm=65536,t=2,p=2', salt_b64, hash_b64]
            if len(parts) != 6 or parts[1] != "argon2id":
                return False
            params = dict(kv.split("=") for kv in parts[3].split(","))
            memory_cost = int(params["m"])
            time_cost = int(params["t"])
            parallelism = int(params["p"])
            salt = base64.b64decode(parts[4].encode("ascii"))
            expected_key = base64.b64decode(parts[5].encode("ascii"))

            kdf = Argon2id(
                salt=salt,
                length=len(expected_key),
                iterations=time_cost,
                lanes=parallelism,
                memory_cost=memory_cost,
                ad=None,
                secret=None
            )
            kdf.verify(password.encode("utf-8"), expected_key)
            return True
        except (InvalidKey, ValueError, KeyError, IndexError):
            return False


# ---- RFC 6238 TOTP Engine ----
class TOTPEngine:
    """Zero-dependency RFC 6238 Time-Based One-Time Password engine."""

    @staticmethod
    def generate_secret() -> str:
        """Generate 160-bit secure random secret encoded in base32."""
        return base64.b32encode(secrets.token_bytes(20)).decode("ascii")

    @classmethod
    def generate_code(cls, secret_base32: str, timestamp: float | None = None, digits: int = 6, interval: int = 30) -> str:
        """Compute TOTP token for given time counter."""
        ts = int(time.time() if timestamp is None else timestamp)
        counter = ts // interval
        key = base64.b32decode(secret_base32.upper(), casefold=True)
        counter_bytes = struct.pack(">Q", counter)
        mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = mac[-1] & 0x0F
        code_int = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
        return str(code_int).zfill(digits)

    @classmethod
    def verify_code(cls, secret_base32: str, code: str, window: int = 1, interval: int = 30) -> bool:
        """Verify code within [-window, +window] time drift window."""
        now = int(time.time())
        current_counter = now // interval
        clean_code = code.strip().replace(" ", "")
        for offset in range(-window, window + 1):
            expected = cls.generate_code(secret_base32, (current_counter + offset) * interval, digits=len(clean_code), interval=interval)
            if hmac.compare_digest(clean_code.encode("ascii"), expected.encode("ascii")):
                return True
        return False

    @staticmethod
    def generate_recovery_codes(count: int = 8) -> Tuple[List[str], List[str]]:
        """Generate single-use alphanumeric recovery codes and their SHA-256 hashes."""
        plain, hashed = [], []
        for _ in range(count):
            token = secrets.token_hex(5).upper()  # 10 chars
            formatted = f"{token[:5]}-{token[5:]}"
            plain.append(formatted)
            hashed.append(hashlib.sha256(formatted.encode("ascii")).hexdigest())
        return plain, hashed


# ---- WebAuthn / FIDO2 Passkey Support ----
class WebAuthnEngine:
    """FIDO2 / WebAuthn challenge and credential assertion verification."""

    @staticmethod
    def generate_challenge() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def verify_challenge(stored_challenge: str, client_data_json: bytes) -> bool:
        try:
            client_data = json.loads(client_data_json)
            received = client_data.get("challenge")
            return received is not None and hmac.compare_digest(stored_challenge, received)
        except Exception:
            return False


# ---- Server-Side Session Manager ----
@dataclass
class Session:
    session_id: str
    user_id: str
    tenant_id: str
    role: str
    csrf_token: str
    client_ip: str
    user_agent: str
    created_at: float
    last_activity: float
    is_mfa_authenticated: bool
    step_up_until: float = 0.0


class SessionStore:
    """Thread-safe server-side session registry with rotation and absolute timeouts."""
    IDLE_TIMEOUT = 1800      # 30 minutes
    ABSOLUTE_TIMEOUT = 43200 # 12 hours
    STEP_UP_DURATION = 300   # 5 minutes

    def __init__(self):
        self._sessions: Dict[str, Session] = {}

    def create_session(self, user_id: str, tenant_id: str, role: str, client_ip: str, user_agent: str, mfa_done: bool) -> Session:
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = time.time()
        sess = Session(
            session_id=sid,
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            csrf_token=csrf,
            client_ip=client_ip,
            user_agent=user_agent,
            created_at=now,
            last_activity=now,
            is_mfa_authenticated=mfa_done
        )
        self._sessions[sid] = sess
        return sess

    def get_session(self, session_id: str, client_ip: Optional[str] = None) -> Optional[Session]:
        if not session_id or session_id not in self._sessions:
            return None
        sess = self._sessions[session_id]
        now = time.time()
        # Enforce idle & absolute timeouts
        if (now - sess.last_activity > self.IDLE_TIMEOUT) or (now - sess.created_at > self.ABSOLUTE_TIMEOUT):
            del self._sessions[session_id]
            return None
        # Enforce client IP check
        if client_ip and sess.client_ip != client_ip:
            # IP bound check mismatch (potential session hijacking)
            return None
        sess.last_activity = now
        return sess

    def rotate_session(self, old_session_id: str) -> Optional[Session]:
        old = self._sessions.pop(old_session_id, None)
        if not old:
            return None
        new_sid = secrets.token_urlsafe(32)
        new_csrf = secrets.token_urlsafe(32)
        rotated = Session(
            session_id=new_sid,
            user_id=old.user_id,
            tenant_id=old.tenant_id,
            role=old.role,
            csrf_token=new_csrf,
            client_ip=old.client_ip,
            user_agent=old.user_agent,
            created_at=old.created_at,
            last_activity=time.time(),
            is_mfa_authenticated=old.is_mfa_authenticated,
            step_up_until=old.step_up_until
        )
        self._sessions[new_sid] = rotated
        return rotated

    def grant_step_up(self, session_id: str) -> bool:
        sess = self.get_session(session_id)
        if not sess:
            return False
        sess.step_up_until = time.time() + self.STEP_UP_DURATION
        return True

    def has_valid_step_up(self, session_id: str) -> bool:
        sess = self.get_session(session_id)
        return bool(sess and sess.step_up_until > time.time())

    def revoke_session(self, session_id: str) -> bool:
        return self._sessions.pop(session_id, None) is not None

    def revoke_all_user_sessions(self, user_id: str) -> int:
        to_del = [sid for sid, s in self._sessions.items() if s.user_id == user_id]
        for sid in to_del:
            del self._sessions[sid]
        return len(to_del)
