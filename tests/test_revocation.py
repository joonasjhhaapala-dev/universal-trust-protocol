"""
Tests for UTP instant credential revocation.
"""

import pytest

from src.revocation import RevocationRegistry, RevocationReason


class TestRevocation:
    """Test credential revocation."""

    def test_revoke_credential(self, revocation_registry: RevocationRegistry):
        entry = revocation_registry.revoke(
            credential_id="did:agent:rogue123",
            credential_type="did",
            revoked_by="did:human:alice123",
            reason=RevocationReason.BEHAVIORAL_ANOMALY,
        )
        assert entry.credential_id == "did:agent:rogue123"
        assert entry.credential_type == "did"
        assert entry.revoked_by == "did:human:alice123"
        assert entry.reason == "behavioral_anomaly"
        assert entry.timestamp > 0

    def test_is_revoked(self, revocation_registry: RevocationRegistry):
        revocation_registry.revoke(
            credential_id="did:agent:rogue123",
            credential_type="did",
            revoked_by="did:human:alice123",
        )
        assert revocation_registry.is_revoked("did:agent:rogue123")

    def test_not_revoked(self, revocation_registry: RevocationRegistry):
        assert not revocation_registry.is_revoked("did:agent:clean123")


class TestRevokedCredentialVerification:
    """Test that revoked credentials fail verification."""

    def test_revoked_credential_is_found_in_registry(self, revocation_registry: RevocationRegistry):
        revocation_registry.revoke(
            credential_id="token:abc123",
            credential_type="capability",
            revoked_by="did:human:alice123",
            reason=RevocationReason.COMPROMISED,
        )
        entry = revocation_registry.get_revocation("token:abc123")
        assert entry is not None
        assert entry.reason == "compromised"

    def test_non_revoked_credential_returns_none(self, revocation_registry: RevocationRegistry):
        entry = revocation_registry.get_revocation("token:unknown")
        assert entry is None


class TestMerkleRoot:
    """Test Merkle root computation for revocation registry."""

    def test_empty_registry_has_merkle_root(self, revocation_registry: RevocationRegistry):
        root = revocation_registry.get_merkle_root()
        assert root is not None
        assert len(root) == 64  # SHA256 hex digest

    def test_merkle_root_changes_after_revocation(self, revocation_registry: RevocationRegistry):
        root_before = revocation_registry.get_merkle_root()

        revocation_registry.revoke(
            credential_id="did:agent:rogue123",
            credential_type="did",
            revoked_by="did:human:alice123",
        )

        root_after = revocation_registry.get_merkle_root()
        assert root_before != root_after

    def test_merkle_root_changes_with_additional_revocation(self, revocation_registry: RevocationRegistry):
        revocation_registry.revoke(
            credential_id="did:agent:rogue1",
            credential_type="did",
            revoked_by="did:human:alice123",
        )
        root_one = revocation_registry.get_merkle_root()

        revocation_registry.revoke(
            credential_id="did:agent:rogue2",
            credential_type="did",
            revoked_by="did:human:alice123",
        )
        root_two = revocation_registry.get_merkle_root()

        assert root_one != root_two


class TestRevocationEvents:
    """Test revocation event logging."""

    def test_revocation_logs_events(self, revocation_registry: RevocationRegistry):
        revocation_registry.revoke(
            credential_id="did:agent:rogue123",
            credential_type="did",
            revoked_by="did:human:alice123",
        )
        events = revocation_registry.get_events()
        assert len(events) == 1
        assert events[0]["type"] == "revocation"
        assert events[0]["credential_id"] == "did:agent:rogue123"

    def test_revocation_count(self, revocation_registry: RevocationRegistry):
        assert revocation_registry.get_revocation_count() == 0

        revocation_registry.revoke(
            credential_id="id1", credential_type="did", revoked_by="admin",
        )
        revocation_registry.revoke(
            credential_id="id2", credential_type="capability", revoked_by="admin",
        )

        assert revocation_registry.get_revocation_count() == 2


class TestVerifierPropagation:
    """Test revocation propagation to verifiers."""

    def test_propagation_to_registered_verifiers(self, revocation_registry: RevocationRegistry):
        revocation_registry.register_verifier("verifier-1")
        revocation_registry.register_verifier("verifier-2")

        entry = revocation_registry.revoke(
            credential_id="did:agent:rogue123",
            credential_type="did",
            revoked_by="did:human:alice123",
        )

        assert len(entry.propagated_to) == 2
        assert "verifier-1" in entry.propagated_to
        assert "verifier-2" in entry.propagated_to
