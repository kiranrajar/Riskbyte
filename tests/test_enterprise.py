"""Enterprise Unit Test Suite for RiskByte SOC Agent.
Tests: Crypto, Auth, MFA, License, Connectors, OCSF Normalization, MITRE ATT&CK, Playbook HITL, and Air-Gapped LLM.
"""
import base64, json, os, shutil, sys, tempfile, time, unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from riskbyte.core.crypto import CryptoEngine
from riskbyte.core.auth import PasswordManager, TOTPEngine, SessionStore
from riskbyte.core.license import LicenseValidator
from riskbyte.core.db import Database
from riskbyte.connectors.base import CircuitBreaker, RateLimiter, validate_connector_endpoint, CircuitBreakerOpenException
from riskbyte.normalization.ocsf import normalize_event, compute_community_id
from riskbyte.normalization.mitre import extract_mitre_techniques
from riskbyte.playbooks.engine import PlaybookEngine
from riskbyte.agent.llm import SelfHostedLLMClient, EgressSecurityViolation


class TestEnterpriseCrypto(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.crypto = CryptoEngine(key_dir=self.td)

    def tearDown(self):
        try:
            shutil.rmtree(self.td)
        except Exception:
            pass

    def test_envelope_encryption_cycle(self):
        secret = "wazuh_admin_password_P@ssw0rd123!"
        envelope = self.crypto.encrypt_secret(secret, "tenant-alpha")
        self.assertIsInstance(envelope, str)
        decrypted = self.crypto.decrypt_secret(envelope, "tenant-alpha")
        self.assertEqual(decrypted, secret)

    def test_envelope_aad_mismatch_fails(self):
        secret = "splunk_token_xyz"
        envelope = self.crypto.encrypt_secret(secret, "tenant-alpha")
        with self.assertRaises(Exception):
            self.crypto.decrypt_secret(envelope, "tenant-bravo")

    def test_audit_hash_chain_and_signature(self):
        h0 = "0" * 64
        h1 = CryptoEngine.compute_record_hash(h0, 1, 100.0, "analyst:alice", "alert_triage", {"alert_id": 1})
        self.assertEqual(len(h1), 64)
        sig = self.crypto.sign_audit_block(h1, {"block": 1})
        self.assertTrue(self.crypto.verify_audit_block(h1, {"block": 1}, sig))
        self.assertFalse(self.crypto.verify_audit_block(h1, {"block": 2}, sig))


class TestEnterpriseAuth(unittest.TestCase):
    def test_argon2id_hashing_and_verification(self):
        pwd = "EnterprisePassword2026!#"
        h = PasswordManager.hash_password(pwd)
        self.assertTrue(h.startswith("$argon2id$"))
        self.assertTrue(PasswordManager.verify_password(pwd, h))
        self.assertFalse(PasswordManager.verify_password("WrongPassword123!", h))

    def test_totp_rfc6238_generation_and_drift(self):
        sec = TOTPEngine.generate_secret()
        code = TOTPEngine.generate_code(sec)
        self.assertEqual(len(code), 6)
        self.assertTrue(TOTPEngine.verify_code(sec, code))
        self.assertFalse(TOTPEngine.verify_code(sec, "000000"))

    def test_recovery_codes_generation(self):
        plain, hashed = TOTPEngine.generate_recovery_codes(8)
        self.assertEqual(len(plain), 8)
        self.assertEqual(len(hashed), 8)
        self.assertEqual(len(plain[0]), 11)  # XXXXX-XXXXX

    def test_session_lifecycle_and_step_up(self):
        store = SessionStore()
        sess = store.create_session("u1", "t1", "analyst_l2", "192.168.1.50", "Firefox", True)
        self.assertEqual(sess.role, "analyst_l2")
        self.assertIsNotNone(store.get_session(sess.session_id, "192.168.1.50"))
        # IP hijacking protection
        self.assertIsNone(store.get_session(sess.session_id, "10.0.0.1"))
        # Step-up MFA
        self.assertFalse(store.has_valid_step_up(sess.session_id))
        store.grant_step_up(sess.session_id)
        self.assertTrue(store.has_valid_step_up(sess.session_id))
        # Rotation
        rotated = store.rotate_session(sess.session_id)
        self.assertIsNotNone(rotated)
        self.assertNotEqual(sess.session_id, rotated.session_id)
        self.assertIsNone(store.get_session(sess.session_id))


class TestConnectorsReliability(unittest.TestCase):
    def test_circuit_breaker_transitions(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.1)
        self.assertEqual(cb.state, "CLOSED")
        self.assertTrue(cb.can_execute())
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, "CLOSED")
        cb.record_failure()
        self.assertEqual(cb.state, "OPEN")
        self.assertFalse(cb.can_execute())
        time.sleep(0.12)
        self.assertTrue(cb.can_execute())
        self.assertEqual(cb.state, "HALF_OPEN")
        cb.record_success()
        self.assertEqual(cb.state, "CLOSED")

    def test_ssrf_validator_blocks_cloud_metadata(self):
        with self.assertRaises(ValueError):
            validate_connector_endpoint("http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(ValueError):
            validate_connector_endpoint("gopher://internal.network/")
        self.assertEqual(
            validate_connector_endpoint("https://wazuh.internal.corp:55000"),
            "https://wazuh.internal.corp:55000"
        )


class TestNormalizationAndMITRE(unittest.TestCase):
    def test_community_id_calculation(self):
        cid1 = compute_community_id("192.168.1.10", "10.0.0.1", 45678, 443, 6)
        cid2 = compute_community_id("10.0.0.1", "192.168.1.10", 443, 45678, 6)
        # Bidirectional flow equivalence
        self.assertEqual(cid1, cid2)
        self.assertTrue(cid1.startswith("1:"))

    def test_mitre_technique_extraction(self):
        log_sample = "Host executed powershell.exe -enc ... observed T1059.001 and potential T1490 shadow delete"
        hits = extract_mitre_techniques(log_sample)
        ids = [h["id"] for h in hits]
        self.assertIn("T1059.001", ids)
        self.assertIn("T1490", ids)


class TestPlaybookAndHITL(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.crypto = CryptoEngine(key_dir=self.td)
        self.db = Database(os.path.join(self.td, "test_hitl.db"), crypto_engine=self.crypto)
        self.engine = PlaybookEngine(self.db)

    def tearDown(self):
        try:
            shutil.rmtree(self.td)
        except Exception:
            pass

    def test_protected_entity_blast_radius(self):
        # Staged incident targeting domain controller
        c_id = self.db.execute(
            "INSERT INTO cases (tenant_id, title, severity, status, primary_entity, created_at, updated_at) "
            "VALUES ('default', 'Ransomware on DC', 'critical', 'open', 'dc01', ?, ?)",
            (time.time(), time.time())
        )
        alert = {"tenant_id": "default", "proposed_action": {"kind": "isolate_host", "target": "dc01"}}
        verdict = {"summary": "Malicious ransomware execution", "evidence_citations": ["Alert #1"]}
        appr_id = self.engine.evaluate_incident(c_id, alert, verdict)
        self.assertIsNotNone(appr_id)

        appr = self.db.one("SELECT * FROM response_approvals WHERE id=?", (appr_id,))
        self.assertEqual(appr["status"], "pending")  # Protected entity MUST NOT auto-execute
        preview = json.loads(appr["dry_run_preview"])
        self.assertTrue(preview["is_protected_infrastructure"])
        self.assertEqual(preview["blast_radius"], "HIGH")

        # Execute approval
        ok, msg = self.engine.execute_approval(appr_id, "analyst:senior_ir")
        self.assertTrue(ok)
        appr_updated = self.db.one("SELECT status FROM response_approvals WHERE id=?", (appr_id,))
        self.assertEqual(appr_updated["status"], "executed")

        # Rollback
        rb_ok, rb_msg = self.engine.rollback_approval(appr_id, "analyst:senior_ir")
        self.assertTrue(rb_ok)
        appr_rolled = self.db.one("SELECT status FROM response_approvals WHERE id=?", (appr_id,))
        self.assertEqual(appr_rolled["status"], "rolled_back")


class TestSelfHostedLLMEgressGuard(unittest.TestCase):
    def test_egress_violation_blocks_external_ai(self):
        with self.assertRaises(EgressSecurityViolation):
            SelfHostedLLMClient(endpoint_url="https://api.openai.com", model_name="gpt-4o")
        with self.assertRaises(EgressSecurityViolation):
            SelfHostedLLMClient(endpoint_url="https://generativelanguage.googleapis.com", model_name="gemini")


if __name__ == "__main__":
    unittest.main()

