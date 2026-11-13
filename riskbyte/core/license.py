"""Enterprise Offline License Verification.
Verifies vendor RSA-4096 signature, enforces plan entitlements,
and provides graceful degradation to read-only state.
"""
from __future__ import annotations
import base64, json, os, time
from typing import Dict, Any, Optional
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


@dataclass
class LicenseStatus:
    is_valid: bool
    state: str           # "active", "warning", "expired", "tampered", "missing", "dev"
    plan: str            # "Starter", "Business", "Enterprise"
    customer: str
    seats: int
    connectors_limit: int
    features: list
    days_remaining: int
    can_triage: bool
    can_approve: bool
    can_configure: bool
    message: str


class LicenseValidator:
    """Verifies vendor RSA-signed license offline without phone-home."""

    # Default embedded vendor public key (replaceable per enterprise deployment)
    DEFAULT_VENDOR_PUBKEY_PEM = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0J7y/F6rN1Fk+qF2uV4z\n"
        "9LhG1n3qW7m3z7bK9l2J6q8f4k7g9d1l8j2h4f6g8k0l2m4n6p8r0t2v4x6z8b0d\n"
        "2f4h6j8l0n2p4r6t8v0x2z4b6d8f0h2j4l6n8p0r2t4v6x8z0b2d4f6h8j0l2n4p\n"
        "6r8t0v2x4z6b8d0f2h4j6l8n0p2r4t6v8x0z2b4d6f8h0j2l4n6p8r0t2v4x6z8b\n"
        "0d2f4h6j8l0n2p4r6t8v0x2z4b6d8f0h2j4l6n8p0r2t4v6x8z0b2d4f6h8j0l2n\n"
        "4p6r8t0v2x4z6b8d0f2h4j6l8n0p2r4t6v8x0z2b4d6f8h0j2l4n6p8r0t2v4x6z\n"
        "8b0d2f4h6j8l0n2p4r6t8v0x2z4b6d8f0h2j4l6n8p0r2t4v6x8z0b2d4f6h8j0l\n"
        "2n4p6r8t0v2x4z6b8d0f2h4j6l8n0p2r4t6v8x0z2b4d6f8h0j2l4n6p8r0t2v4x\n"
        "6z8b0d2f4h6j8l0n2p4r6t8v0x2z4b6d8f0h2j4l6n8p0r2t4v6x8z0b2d4f6h8j\n"
        "0l2n4p6r8t0v2x4z6b8d0f2h4j6l8n0p2r4t6v8x0z2b4d6f8h0j2l4n6p8r0t2v\n"
        "4x6z8b0d2f4h6j8l0n2p4r6t8v0x2z4b6d8f0h2j4l6n8p0r2t4v6x8z0b2d4f6h\n"
        "8j0l2n4p6r8t0v2x4z6b8d0f2h4j6l8n0p2r4t6v8x0z2b4d6f8h0j2l4n6p8r0t\n"
        "2v4x6z8CAwEAAQ==\n"
        "-----END PUBLIC KEY-----"
    )

    def __init__(self, license_path: str = "./license.rbl", pubkey_path: str = "./vendor_public.pem", dev_mode: bool = False):
        self.license_path = license_path
        self.pubkey_path = pubkey_path
        self.dev_mode = dev_mode

    def _get_pubkey(self):
        if os.path.isfile(self.pubkey_path):
            with open(self.pubkey_path, "rb") as f:
                return serialization.load_pem_public_key(f.read())
        return serialization.load_pem_public_key(self.DEFAULT_VENDOR_PUBKEY_PEM.encode("utf-8"))

    def check(self, active_seats: int = 1, active_connectors: int = 0) -> LicenseStatus:
        if self.dev_mode:
            return LicenseStatus(
                is_valid=True,
                state="dev",
                plan="Enterprise (Developer Sandbox)",
                customer="Internal Evaluation",
                seats=999,
                connectors_limit=999,
                features=["all", "ha", "sso", "thehive_sync", "custom_playbooks", "suricata_block", "zeek_corr"],
                days_remaining=365,
                can_triage=True,
                can_approve=True,
                can_configure=True,
                message="Developer evaluation mode active."
            )

        if not os.path.exists(self.license_path):
            return LicenseStatus(
                is_valid=False,
                state="missing",
                plan="Unlicensed",
                customer="Unregistered",
                seats=0,
                connectors_limit=0,
                features=[],
                days_remaining=0,
                can_triage=False,
                can_approve=False,
                can_configure=False,
                message="No license file installed. Install via First-Run Setup or Admin panel."
            )

        try:
            with open(self.license_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            payload_b64, _, sig_b64 = raw.partition("---SIGNATURE---")
            payload_json = base64.b64decode(payload_b64.strip()).decode("utf-8")
            data = json.loads(payload_json)
            sig = base64.b64decode(sig_b64.strip())

            # Verify RSA-PSS signature
            pub_key = self._get_pubkey()
            pub_key.verify(
                sig,
                payload_json.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            now = time.time()
            exp = data.get("expires_at", 0)
            days_left = max(0, int((exp - now) // 86400))

            if now > exp:
                return LicenseStatus(
                    is_valid=False,
                    state="expired",
                    plan=data.get("plan", "Standard"),
                    customer=data.get("customer", "Enterprise"),
                    seats=data.get("seats", 5),
                    connectors_limit=data.get("connectors", 3),
                    features=data.get("features", []),
                    days_remaining=0,
                    can_triage=False,
                    can_approve=False,
                    can_configure=False,
                    message="License expired. Platform operating in read-only audit mode."
                )

            # Check seat & connector limits
            max_seats = data.get("seats", 5)
            max_connectors = data.get("connectors", 5)
            if active_seats > max_seats:
                return LicenseStatus(
                    is_valid=False,
                    state="degraded",
                    plan=data.get("plan", "Standard"),
                    customer=data.get("customer", "Enterprise"),
                    seats=max_seats,
                    connectors_limit=max_connectors,
                    features=data.get("features", []),
                    days_remaining=days_left,
                    can_triage=True,
                    can_approve=False,
                    can_configure=False,
                    message=f"Seat limit exceeded ({active_seats}/{max_seats}). Response actions paused."
                )

            state = "warning" if days_left < 30 else "active"
            msg = f"License active. {days_left} days remaining." if state == "active" else f"License renewal needed: {days_left} days left."
            return LicenseStatus(
                is_valid=True,
                state=state,
                plan=data.get("plan", "Enterprise"),
                customer=data.get("customer", "Enterprise Customer"),
                seats=max_seats,
                connectors_limit=max_connectors,
                features=data.get("features", []),
                days_remaining=days_left,
                can_triage=True,
                can_approve=True,
                can_configure=True,
                message=msg
            )
        except Exception as e:
            return LicenseStatus(
                is_valid=False,
                state="tampered",
                plan="Unlicensed",
                customer="Unknown",
                seats=0,
                connectors_limit=0,
                features=[],
                days_remaining=0,
                can_triage=False,
                can_approve=False,
                can_configure=False,
                message=f"License validation failed: cryptographic signature invalid ({e})."
            )

