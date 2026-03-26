"""
UTP Cryptographic Utilities
Ed25519 key generation, signing, verification, and token encoding.
"""

import json
import base64
import hashlib
import time
from typing import Any, Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError


def generate_keypair() -> tuple[SigningKey, VerifyKey]:
    """Generate an Ed25519 signing/verification keypair."""
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return signing_key, verify_key


def public_key_to_b64(verify_key: VerifyKey) -> str:
    """Encode a public key to base64 string."""
    return verify_key.encode(encoder=Base64Encoder).decode("utf-8")


def signing_key_to_b64(signing_key: SigningKey) -> str:
    """Encode a signing key to base64 string."""
    return signing_key.encode(encoder=Base64Encoder).decode("utf-8")


def b64_to_verify_key(b64: str) -> VerifyKey:
    """Decode a base64 string to a VerifyKey."""
    return VerifyKey(b64.encode("utf-8"), encoder=Base64Encoder)


def b64_to_signing_key(b64: str) -> SigningKey:
    """Decode a base64 string to a SigningKey."""
    return SigningKey(b64.encode("utf-8"), encoder=Base64Encoder)


def generate_did(entity_type: str, verify_key: VerifyKey) -> str:
    """
    Generate a DID from an entity type and public key.
    Format: did:<type>:<fingerprint>
    """
    key_bytes = verify_key.encode()
    fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]
    return f"did:{entity_type}:{fingerprint}"


def sign_payload(payload: bytes, signing_key: SigningKey) -> bytes:
    """Sign raw bytes, return the signature bytes."""
    signed = signing_key.sign(payload)
    return signed.signature


def verify_signature(payload: bytes, signature: bytes, verify_key: VerifyKey) -> bool:
    """Verify a signature against a payload."""
    try:
        verify_key.verify(payload, signature)
        return True
    except BadSignatureError:
        return False


def sign_json(data: dict, signing_key: SigningKey) -> str:
    """Sign a JSON-serializable dict, return base64-encoded signature."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = sign_payload(canonical, signing_key)
    return base64.b64encode(sig).decode("utf-8")


def verify_json(data: dict, signature_b64: str, verify_key: VerifyKey) -> bool:
    """Verify a base64-encoded signature against a JSON dict."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = base64.b64decode(signature_b64)
    return verify_signature(canonical, sig, verify_key)


def create_capability_token(
    issuer_did: str,
    subject_did: str,
    action: str,
    resource: str,
    constraints: dict,
    expires_at: float,
    signing_key: SigningKey,
    delegation_chain: Optional[list] = None,
) -> dict:
    """
    Create a signed capability token (JWT-like with capability semantics).
    """
    payload = {
        "iss": issuer_did,
        "sub": subject_did,
        "action": action,
        "resource": resource,
        "constraints": constraints,
        "iat": time.time(),
        "exp": expires_at,
        "delegation_chain": delegation_chain or [],
    }
    token_id = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()
    ).hexdigest()[:16]
    payload["jti"] = token_id

    signature = sign_json(payload, signing_key)

    return {
        "payload": payload,
        "signature": signature,
        "token_id": token_id,
    }


def verify_capability_token(token: dict, verify_key: VerifyKey) -> tuple[bool, str]:
    """
    Verify a capability token's signature and expiry.
    Returns (is_valid, reason).
    """
    payload = token.get("payload", {})
    signature = token.get("signature", "")

    # Check expiry
    if time.time() > payload.get("exp", 0):
        return False, "Token expired"

    # Verify signature
    if not verify_json(payload, signature, verify_key):
        return False, "Invalid signature"

    return True, "Valid"
