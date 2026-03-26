"""
Tests for UTP Decentralized Identity (DID) system.
"""

import pytest

from src.identity import IdentityManager, DIDDocument
from src import crypto_utils


class TestDIDCreation:
    """Test DID document creation for different entity types."""

    def test_create_agent_identity(self, identity_manager: IdentityManager):
        doc, signing_key = identity_manager.create_identity(
            entity_type="agent",
            capabilities=["shopping"],
            metadata={"name": "TestAgent"},
        )
        assert doc.entity_type == "agent"
        assert doc.did.startswith("did:agent:")
        assert "shopping" in doc.capabilities
        assert doc.status == "active"
        assert signing_key is not None

    def test_create_human_identity(self, identity_manager: IdentityManager):
        doc, signing_key = identity_manager.create_identity(
            entity_type="human",
            metadata={"name": "Alice"},
        )
        assert doc.entity_type == "human"
        assert doc.did.startswith("did:human:")

    def test_create_org_identity(self, identity_manager: IdentityManager):
        doc, signing_key = identity_manager.create_identity(
            entity_type="org",
            metadata={"name": "TrustCorp"},
        )
        assert doc.entity_type == "org"
        assert doc.did.startswith("did:org:")

    def test_invalid_entity_type_raises(self, identity_manager: IdentityManager):
        with pytest.raises(ValueError, match="Invalid entity type"):
            identity_manager.create_identity(entity_type="invalid")


class TestDIDFormat:
    """Test DID format correctness."""

    def test_did_has_three_parts(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        parts = doc.did.split(":")
        assert len(parts) == 3
        assert parts[0] == "did"
        assert parts[1] == "agent"
        assert len(parts[2]) == 16  # SHA256 fingerprint truncated to 16 hex chars

    def test_did_fingerprint_is_hex(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        fingerprint = doc.did.split(":")[2]
        int(fingerprint, 16)  # Should not raise


class TestDIDDocumentFields:
    """Test DID document has all required fields."""

    def test_document_has_required_fields(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(
            entity_type="agent",
            capabilities=["data"],
            constraints={"read_only": True},
            controller="did:human:controller123",
            metadata={"version": "1.0"},
        )
        assert doc.did is not None
        assert doc.entity_type == "agent"
        assert doc.public_key is not None and len(doc.public_key) > 0
        assert doc.capabilities == ["data"]
        assert doc.constraints == {"read_only": True}
        assert doc.controller == "did:human:controller123"
        assert doc.created > 0
        assert doc.expires > doc.created
        assert doc.status == "active"
        assert doc.signature is not None

    def test_document_to_dict(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        d = doc.to_dict()
        assert isinstance(d, dict)
        assert "did" in d
        assert "entity_type" in d
        assert "public_key" in d
        assert "signature" in d

    def test_signable_dict_excludes_signature(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        signable = doc.signable_dict()
        assert "signature" not in signable


class TestDIDDocumentSignature:
    """Test DID document signature validity."""

    def test_document_signature_is_valid(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        valid, reason = identity_manager.verify_document(doc)
        assert valid
        assert "Valid" in reason

    def test_agent_signature_valid(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent", capabilities=["shopping"])
        valid, _ = identity_manager.verify_document(doc)
        assert valid

    def test_human_signature_valid(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="human")
        valid, _ = identity_manager.verify_document(doc)
        assert valid

    def test_org_signature_valid(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="org")
        valid, _ = identity_manager.verify_document(doc)
        assert valid

    def test_tampered_document_fails_verification(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        # Tamper with the document
        doc.capabilities = ["hacked"]
        valid, reason = identity_manager.verify_document(doc)
        assert not valid

    def test_missing_signature_fails_verification(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        doc.signature = None
        valid, reason = identity_manager.verify_document(doc)
        assert not valid
        assert "No signature" in reason


class TestDIDResolution:
    """Test DID resolution and lookup."""

    def test_resolve_existing_did(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        resolved = identity_manager.resolve(doc.did)
        assert resolved is not None
        assert resolved.did == doc.did

    def test_resolve_nonexistent_did_returns_none(self, identity_manager: IdentityManager):
        resolved = identity_manager.resolve("did:agent:nonexistent")
        assert resolved is None

    def test_list_all(self, identity_manager: IdentityManager):
        identity_manager.create_identity(entity_type="agent")
        identity_manager.create_identity(entity_type="human")
        identity_manager.create_identity(entity_type="org")
        all_docs = identity_manager.list_all()
        assert len(all_docs) == 3

    def test_search_by_type(self, identity_manager: IdentityManager):
        identity_manager.create_identity(entity_type="agent")
        identity_manager.create_identity(entity_type="agent")
        identity_manager.create_identity(entity_type="human")
        agents = identity_manager.search(entity_type="agent")
        assert len(agents) == 2

    def test_update_status(self, identity_manager: IdentityManager):
        doc, _ = identity_manager.create_identity(entity_type="agent")
        result = identity_manager.update_status(doc.did, "suspended")
        assert result is True
        updated = identity_manager.resolve(doc.did)
        assert updated.status == "suspended"
