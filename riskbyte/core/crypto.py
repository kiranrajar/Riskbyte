"""Enterprise cryptographic operations:
1. RSA-4096 instance keypair management.
2. Envelope encryption (AES-256-GCM wrapped with RSA-OAEP-4096).
3. Cryptographic hash-chaining and RSASSA-PSS-SHA256 block signing.
4. Offline verification tool for audit integrity.
"""
from __future__ import annotations
import base64, hashlib, json, os, secrets, struct
from typing import Tuple, Dict, Any, List

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoEngine:
    """Enterprise crypto manager for instance keys, credential wrapping, and audit signing."""

    def __init__(self, key_dir: str | None = None):
        if key_dir is None:
            # Place in riskbyte data directory by default
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            key_dir = os.path.join(base, "data", "keys")
        self.key_dir = os.path.abspath(key_dir)
        os.makedirs(self.key_dir, exist_ok=True)
        self.priv_path = os.path.join(self.key_dir, "instance_private.pem")
        self.pub_path = os.path.join(self.key_dir, "instance_public.pem")
        self._private_key: rsa.RSAPrivateKey | None = None
        self._public_key: rsa.RSAPublicKey | None = None
        self._load_or_generate_instance_keys()

    def _load_or_generate_instance_keys(self):
        if os.path.exists(self.priv_path) and os.path.exists(self.pub_path):
            with open(self.priv_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.pub_path, "rb") as f:
                self._public_key = serialization.load_pem_public_key(f.read())
        else:
            # Generate 4096-bit RSA instance keypair
            self._private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            self._public_key = self._private_key.public_key()
            priv_pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            pub_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.priv_path, "wb") as f:
                f.write(priv_pem)
            with open(self.pub_path, "wb") as f:
                f.write(pub_pem)
            try:
                os.chmod(self.priv_path, 0o400)
            except (OSError, AttributeError):
                pass

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    # ---- Envelope Encryption (AES-256-GCM wrapped via RSA-OAEP) ----
    def encrypt_secret(self, plaintext: str, associated_data: str = "") -> str:
        """Encrypt sensitive integration credentials using AES-256-GCM wrapped by RSA-OAEP-4096."""
        dek = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(dek)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data.encode("utf-8") if associated_data else None)

        # Wrap DEK with instance RSA public key
        wrapped_dek = self._public_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Format: [2 bytes len(wrapped_dek)][wrapped_dek][12 bytes nonce][ct]
        packed = struct.pack(">H", len(wrapped_dek)) + wrapped_dek + nonce + ct
        return base64.b64encode(packed).decode("ascii")

    def decrypt_secret(self, encoded_envelope: str, associated_data: str = "") -> str:
        """Decrypt payload using RSA-OAEP-unwrapped DEK with AES-256-GCM verification."""
        data = base64.b64decode(encoded_envelope.encode("ascii"))
        w_len = struct.unpack(">H", data[:2])[0]
        wrapped_dek = data[2:2 + w_len]
        nonce = data[2 + w_len:2 + w_len + 12]
        ct = data[2 + w_len + 12:]

        dek = self._private_key.decrypt(
            wrapped_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aesgcm = AESGCM(dek)
        pt = aesgcm.decrypt(nonce, ct, associated_data.encode("utf-8") if associated_data else None)
        return pt.decode("utf-8")

    # ---- Hash-Chaining & Digital Block Signing ----
    @staticmethod
    def compute_record_hash(prev_hash: str, sequence_id: int, timestamp: float, actor: str, event_type: str, details: dict) -> str:
        """Compute deterministic SHA-256 hash for audit record."""
        canonical = json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)
        feed = f"{prev_hash}|{sequence_id}|{timestamp:.6f}|{actor}|{event_type}|{canonical}".encode("utf-8")
        return hashlib.sha256(feed).hexdigest()

    def sign_audit_block(self, latest_hash: str, block_metadata: dict) -> str:
        """Sign audit block hash using RSASSA-PSS with SHA-256."""
        payload = f"{latest_hash}|{json.dumps(block_metadata, sort_keys=True)}".encode("utf-8")
        signature = self._private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("ascii")

    def verify_audit_block(self, latest_hash: str, block_metadata: dict, b64_sig: str, pub_pem: str | None = None) -> bool:
        """Verify an RSASSA-PSS block signature either against local or external auditor key."""
        pub_key = self._public_key
        if pub_pem:
            pub_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        payload = f"{latest_hash}|{json.dumps(block_metadata, sort_keys=True)}".encode("utf-8")
        sig = base64.b64decode(b64_sig.encode("ascii"))
        try:
            pub_key.verify(
                sig,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
