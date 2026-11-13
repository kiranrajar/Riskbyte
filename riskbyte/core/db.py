"""Enterprise Database Engine.
Thread-safe connection management, parameterized SQL execution,
automatic schema migration, and hash-chained audit logging.
"""
from __future__ import annotations
import json, logging, os, sqlite3, threading, time
from typing import Dict, Any, List, Optional, Tuple

from .crypto import CryptoEngine

log = logging.getLogger("riskbyte.core.db")


class Database:
    """Universal enterprise persistence layer with thread-local connection pooling."""

    def __init__(self, db_path: str, crypto_engine: Optional[CryptoEngine] = None):
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.crypto = crypto_engine or CryptoEngine()
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            c = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=15000")
            self._local.conn = c
        return self._local.conn

    def _init_schema(self):
        c = self._conn()
        with c:
            # Tenants
            c.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                settings TEXT NOT NULL DEFAULT '{}'
            )
            """)

            # Users
            c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(id),
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin','soc_manager','analyst_l2','analyst_l1','auditor','api_service')),
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                mfa_secret_encrypted TEXT,
                mfa_recovery_hashes TEXT DEFAULT '[]',
                is_active INTEGER NOT NULL DEFAULT 1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL,
                last_login_at REAL,
                created_at REAL NOT NULL
            )
            """)

            # WebAuthn
            c.execute("""
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                credential_id TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                friendly_name TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """)

            # Integrations
            c.execute("""
            CREATE TABLE IF NOT EXISTS integrations (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(id),
                connector_type TEXT NOT NULL,
                name TEXT NOT NULL,
                endpoint_url TEXT NOT NULL,
                credentials_encrypted TEXT NOT NULL,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                verify_ssl INTEGER NOT NULL DEFAULT 1,
                ca_cert_pem TEXT,
                rate_limit_per_min INTEGER NOT NULL DEFAULT 300,
                status TEXT NOT NULL DEFAULT 'disconnected',
                last_sync_at REAL,
                last_error TEXT,
                latency_ms INTEGER,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """)

            # Cases & Incidents
            c.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL REFERENCES tenants(id),
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
                status TEXT NOT NULL CHECK (status IN ('open','in_investigation','pending_approval','contained','closed')),
                primary_entity TEXT NOT NULL,
                mitre_tactics TEXT NOT NULL DEFAULT '[]',
                mitre_techniques TEXT NOT NULL DEFAULT '[]',
                assigned_user_id TEXT REFERENCES users(id),
                thehive_case_id TEXT,
                ai_verdict TEXT,
                ai_confidence REAL,
                ai_summary TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                closed_at REAL
            )
            """)

            # Alerts Queue
            c.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL REFERENCES tenants(id),
                case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new',
                host TEXT,
                user TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                event_ids TEXT,
                triage TEXT,
                proposed_action TEXT,
                raw_payload TEXT,
                created_at REAL NOT NULL
            )
            """)

            # Playbooks
            c.execute("""
            CREATE TABLE IF NOT EXISTS playbooks (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(id),
                name TEXT NOT NULL,
                description TEXT,
                trigger_condition TEXT NOT NULL,
                autonomy_level TEXT NOT NULL CHECK (autonomy_level IN ('observe','recommend','approve_to_execute','auto_execute')),
                action_type TEXT NOT NULL,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                requires_step_up_mfa INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            )
            """)

            # Human-in-the-Loop Response Approvals
            c.execute("""
            CREATE TABLE IF NOT EXISTS response_approvals (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL REFERENCES tenants(id),
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                playbook_id TEXT REFERENCES playbooks(id),
                action_type TEXT NOT NULL,
                target_entity TEXT NOT NULL,
                dry_run_preview TEXT NOT NULL,
                ai_rationale TEXT NOT NULL,
                cited_evidence_ids TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_by TEXT NOT NULL DEFAULT 'riskbyte_ai',
                approved_by_user TEXT,
                approved_at REAL,
                step_up_mfa_token TEXT,
                execution_result TEXT,
                rollback_supported INTEGER NOT NULL DEFAULT 1,
                rollback_state TEXT,
                rolled_back_at REAL,
                created_at REAL NOT NULL
            )
            """)

            # Cryptographically Chained Audit Log
            c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                actor TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target_resource TEXT,
                ip_address TEXT,
                action_details TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                batch_signed INTEGER NOT NULL DEFAULT 0,
                batch_signature TEXT
            )
            """)

            # Insert default primary tenant if absent
            cur = c.execute("SELECT COUNT(*) FROM tenants")
            if cur.fetchone()[0] == 0:
                c.execute(
                    "INSERT INTO tenants (id, name, slug, created_at, is_active, settings) VALUES (?, ?, ?, ?, 1, ?)",
                    ("default", "Primary Security Operations", "primary", time.time(), "{}")
                )

    # ---- Query Execution Helpers ----
    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        c = self._conn()
        cur = c.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    def one(self, sql: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple = ()) -> Any:
        with self._lock:
            c = self._conn()
            with c:
                cur = c.execute(sql, params)
                return cur.lastrowid

    # ---- Cryptographic Audit Logging ----
    def audit(self, tenant_id: str, actor: str, event_type: str, target: Optional[str] = None,
              ip: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> int:
        """Atomically append a cryptographically hash-chained entry to the audit trail."""
        details = details or {}
        now = time.time()
        with self._lock:
            c = self._conn()
            with c:
                last_row = c.execute("SELECT sequence_id, record_hash FROM audit_log ORDER BY sequence_id DESC LIMIT 1").fetchone()
                if last_row:
                    prev_hash = last_row["record_hash"]
                    seq_id = last_row["sequence_id"] + 1
                else:
                    prev_hash = "0" * 64
                    seq_id = 1

                record_hash = CryptoEngine.compute_record_hash(prev_hash, seq_id, now, actor, event_type, details)
                cur = c.execute("""
                INSERT INTO audit_log (tenant_id, timestamp, actor, event_type, target_resource, ip_address,
                                       action_details, previous_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (tenant_id, now, actor, event_type, target, ip, json.dumps(details), prev_hash, record_hash))
                inserted_id = cur.lastrowid

                # Every 50 entries, sign the block
                if inserted_id % 50 == 0:
                    sig = self.crypto.sign_audit_block(record_hash, {"latest_seq": inserted_id, "tenant": tenant_id})
                    c.execute("UPDATE audit_log SET batch_signed=1, batch_signature=? WHERE sequence_id=?", (sig, inserted_id))

                return inserted_id

    def verify_audit_chain(self, tenant_id: str = "default") -> Tuple[bool, int, str]:
        """Verify entire cryptographic audit chain from genesis."""
        rows = self.query("SELECT * FROM audit_log WHERE tenant_id=? ORDER BY sequence_id ASC", (tenant_id,))
        if not rows:
            return True, 0, "Audit log is empty (clean state)."

        prev_hash = "0" * 64
        for idx, r in enumerate(rows):
            seq = r["sequence_id"]
            expected_hash = CryptoEngine.compute_record_hash(
                prev_hash, seq, r["timestamp"], r["actor"], r["event_type"], json.loads(r["action_details"])
            )
            if expected_hash != r["record_hash"]:
                return False, seq, f"Audit chain verification FAILED at sequence #{seq}. Computed hash mismatch (tampered record)."
            if r["previous_hash"] != prev_hash:
                return False, seq, f"Audit chain linkage BROKEN at sequence #{seq}. Previous hash does not match predecessor."
            if r["batch_signed"] and r["batch_signature"]:
                is_sig_ok = self.crypto.verify_audit_block(r["record_hash"], {"latest_seq": seq, "tenant": tenant_id}, r["batch_signature"])
                if not is_sig_ok:
                    return False, seq, f"RSA signature validation FAILED at block #{seq}."
            prev_hash = r["record_hash"]

        return True, len(rows), f"Audit chain verified successfully ({len(rows)} records verified against RSA instance key)."

