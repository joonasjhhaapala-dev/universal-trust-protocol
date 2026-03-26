"""
Tests for UTP cryptographic operations (Ed25519 signing, verification, tokens).
"""

import time

import pytest
from nacl.signing import SigningKey, VerifyKey

from src import crypto_utils


class TestKeyGeneration:
    """Test Ed25519 key generation."""

    def test_generate_keypair_returns_valid_types(self):
        signing_key, verify_key = crypto_utils.generate_keypair()
        assert isinstance(signing_key, SigningKey)
        assert isinstance(verify_key, VerifyKey)

    def test_generate_keypair_produces_unique_keys(self):
        sk1, vk1 = crypto_utils.generate_keypair()
        sk2, vk2 = crypto_utils.generate_keypair()
        assert sk1.encode() != sk2.encode()
        assert vk1.encode() != vk2.encode()

    def test_public_key_roundtrip(self):
        _, verify_key = crypto_utils.generate_keypair()
        b64 = crypto_utils.public_key_to_b64(verify_key)
        recovered = crypto_utils.b64_to_verify_key(b64)
        assert verify_key.encode() == recovered.encode()

    def test_signing_key_roundtrip(self):
        signing_key, _ = crypto_utils.generate_keypair()
        b64 = crypto_utils.signing_key_to_b64(signing_key)
        recovered = crypto_utils.b64_to_signing_key(b64)
        assert signing_key.encode() == recovered.encode()


class TestSignAndVerify:
    """Test signing and verification of raw payloads."""

    def test_sign_and_verify_succeeds(self):
        signing_key, verify_key = crypto_utils.generate_keypair()
        payload = b"test message"
        signature = crypto_utils.sign_payload(payload, signing_key)
        assert crypto_utils.verify_signature(payload, signature, verify_key)

    def test_verify_fails_with_wrong_key(self):
        sk1, _ = crypto_utils.generate_keypair()
        _, vk2 = crypto_utils.generate_keypair()
        payload = b"test message"
        signature = crypto_utils.sign_payload(payload, sk1)
        assert not crypto_utils.verify_signature(payload, signature, vk2)

    def test_verify_fails_with_tampered_data(self):
        signing_key, verify_key = crypto_utils.generate_keypair()
        payload = b"original message"
        signature = crypto_utils.sign_payload(payload, signing_key)
        tampered = b"tampered message"
        assert not crypto_utils.verify_signature(tampered, signature, verify_key)

    def test_sign_json_and_verify(self):
        signing_key, verify_key = crypto_utils.generate_keypair()
        data = {"action": "test", "value": 42}
        sig_b64 = crypto_utils.sign_json(data, signing_key)
        assert crypto_utils.verify_json(data, sig_b64, verify_key)

    def test_verify_json_fails_with_wrong_key(self):
        sk1, _ = crypto_utils.generate_keypair()
        _, vk2 = crypto_utils.generate_keypair()
        data = {"action": "test", "value": 42}
        sig_b64 = crypto_utils.sign_json(data, sk1)
        assert not crypto_utils.verify_json(data, sig_b64, vk2)

    def test_verify_json_fails_with_tampered_data(self):
        signing_key, verify_key = crypto_utils.generate_keypair()
        data = {"action": "test", "value": 42}
        sig_b64 = crypto_utils.sign_json(data, signing_key)
        tampered = {"action": "test", "value": 999}
        assert not crypto_utils.verify_json(tampered, sig_b64, verify_key)


class TestDIDGeneration:
    """Test DID generation from public keys."""

    def test_did_format_agent(self):
        _, verify_key = crypto_utils.generate_keypair()
        did = crypto_utils.generate_did("agent", verify_key)
        assert did.startswith("did:agent:")
        # Fingerprint is 16 hex chars
        fingerprint = did.split(":")[2]
        assert len(fingerprint) == 16

    def test_did_format_human(self):
        _, verify_key = crypto_utils.generate_keypair()
        did = crypto_utils.generate_did("human", verify_key)
        assert did.startswith("did:human:")

    def test_did_format_org(self):
        _, verify_key = crypto_utils.generate_keypair()
        did = crypto_utils.generate_did("org", verify_key)
        assert did.startswith("did:org:")

    def test_different_keys_produce_different_dids(self):
        _, vk1 = crypto_utils.generate_keypair()
        _, vk2 = crypto_utils.generate_keypair()
        did1 = crypto_utils.generate_did("agent", vk1)
        did2 = crypto_utils.generate_did("agent", vk2)
        assert did1 != did2


class TestCapabilityToken:
    """Test capability token creation and verification."""

    def test_create_and_verify_token(self):
        signing_key, verify_key = crypto_utils.generate_keypair()
        token = crypto_utils.create_capability_token(
            issuer_did="did:human:alice123",
            subject_did="did:agent:bot456",
            action="spend",
            resource="groceries",
            constraints={"max_amount": 500},
            expires_at=time.time() + 3600,
            signing_key=signing_key,
        )
        assert "payload" in token
        assert "signature" in token
        assert "token_id" in token
        valid, reason = crypto_utils.verify_capability_token(token, verify_key)
        assert valid
        assert reason == "Valid"

    def test_expired_token_is_rejected(self):
        signing_key, verify_key = crypto_utils.generate_keypair()
        token = crypto_utils.create_capability_token(
            issuer_did="did:human:alice123",
            subject_did="did:agent:bot456",
            action="spend",
            resource="groceries",
            constraints={},
            expires_at=time.time() - 10,  # Already expired
            signing_key=signing_key,
        )
        valid, reason = crypto_utils.verify_capability_token(token, verify_key)
        assert not valid
        assert "expired" in reason.lower()

    def test_token_verification_fails_with_wrong_key(self):
        sk1, _ = crypto_utils.generate_keypair()
        _, vk2 = crypto_utils.generate_keypair()
        token = crypto_utils.create_capability_token(
            issuer_did="did:human:alice123",
            subject_did="did:agent:bot456",
            action="spend",
            resource="groceries",
            constraints={},
            expires_at=time.time() + 3600,
            signing_key=sk1,
        )
        valid, reason = crypto_utils.verify_capability_token(token, vk2)
        assert not valid
        assert "signature" in reason.lower()

    def test_token_has_delegation_chain(self):
        signing_key, _ = crypto_utils.generate_keypair()
        chain = ["did:human:alice123", "did:agent:bot456"]
        token = crypto_utils.create_capability_token(
            issuer_did="did:agent:bot456",
            subject_did="did:agent:bot789",
            action="spend",
            resource="groceries",
            constraints={},
            expires_at=time.time() + 3600,
            signing_key=signing_key,
            delegation_chain=chain,
        )
        assert token["payload"]["delegation_chain"] == chain
