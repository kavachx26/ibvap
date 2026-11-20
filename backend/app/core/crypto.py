"""
crypto.py
---------
Ed25519 signing key for IBVAP.

The SHA-256 hash chain in storage.py proves that history was not edited
*unless* the attacker also recomputes every hash after the edit. Anyone with
raw database access can do that, because the hash formula is public. A
signature fixes the gap: periodic "checkpoints" sign the current chain head
with a private key that never lives inside the database. Rewriting the chain
then requires the key as well, and evidence bundles exported to investigators
can be verified offline against the public key.

Prototype note: the key is generated on first start and stored in
data/keys/. A production deployment would keep it in an HSM or a separate
signing service so a compromised application server cannot sign.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from app.config import KEYS_DIR

_KEY_PATH = KEYS_DIR / "ibvap_signing_ed25519.pem"
_lock = threading.Lock()
_private_key: Optional[Ed25519PrivateKey] = None


def _load_or_create() -> Ed25519PrivateKey:
    global _private_key
    with _lock:
        if _private_key is not None:
            return _private_key
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        if _KEY_PATH.exists():
            key = serialization.load_pem_private_key(_KEY_PATH.read_bytes(), password=None)
        else:
            key = Ed25519PrivateKey.generate()
            _KEY_PATH.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        _private_key = key  # type: ignore[assignment]
        return _private_key


def public_key() -> Ed25519PublicKey:
    return _load_or_create().public_key()


def public_key_pem() -> str:
    return public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def key_fingerprint() -> str:
    raw = public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def sign(message: bytes) -> str:
    return _load_or_create().sign(message).hex()


def verify(message: bytes, signature_hex: str, pem: Optional[str] = None) -> bool:
    try:
        pub = public_key() if pem is None else serialization.load_pem_public_key(pem.encode("ascii"))
        pub.verify(bytes.fromhex(signature_hex), message)  # type: ignore[union-attr]
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
