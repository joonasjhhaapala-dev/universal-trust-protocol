"""
Tests for UTP capability-based authorization system.
"""

import time

import pytest

from src.identity import IdentityManager
from src.capabilities import CapabilityManager
from src import crypto_utils


@pytest.fixture
def setup(identity_manager, capability_manager):
    """Create issuer and subject identities and return everything needed for tests."""
    issuer_doc, issuer_sk = identity_manager.create_identity(
        entity_type="human",
        metadata={"name": "Alice"},
    )
    subject_doc, subject_sk = identity_manager.create_identity(
        entity_type="agent",
        capabilities=["shopping"],
        metadata={"name": "GroceryBot"},
    )
    issuer_vk = identity_manager.get_verify_key(issuer_doc.did)
    return {
        "im": identity_manager,
        "cm": capability_manager,
        "issuer_doc": issuer_doc,
        "issuer_sk": issuer_sk,
        "issuer_vk": issuer_vk,
        "subject_doc": subject_doc,
        "subject_sk": subject_sk,
    }


class TestCapabilityGrant:
    """Test capability grant and verification."""

    def test_grant_creates_token(self, setup):
        cm = setup["cm"]
        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
            constraints={"max_amount": 500},
            expires_in=3600,
        )
        assert grant.token_id is not None
        assert grant.issuer == setup["issuer_doc"].did
        assert grant.subject == setup["subject_doc"].did
        assert grant.action == "spend"
        assert grant.resource == "groceries"

    def test_verify_valid_token(self, setup):
        cm = setup["cm"]
        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
        )
        valid, reason = cm.verify(
            token_id=grant.token_id,
            action="spend",
            resource="groceries",
            verify_key=setup["issuer_vk"],
        )
        assert valid
        assert reason == "Valid"


class TestCapabilityExpiry:
    """Test that expired capabilities are rejected."""

    def test_expired_capability_is_rejected(self, setup):
        cm = setup["cm"]
        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
            expires_in=-1,  # Already expired
        )
        valid, reason = cm.verify(
            token_id=grant.token_id,
            action="spend",
            resource="groceries",
            verify_key=setup["issuer_vk"],
        )
        assert not valid
        assert "expired" in reason.lower()


class TestCapabilityScope:
    """Test that out-of-scope actions are rejected."""

    def test_wrong_action_is_rejected(self, setup):
        cm = setup["cm"]
        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
        )
        valid, reason = cm.verify(
            token_id=grant.token_id,
            action="delete",
            resource="groceries",
            verify_key=setup["issuer_vk"],
        )
        assert not valid
        assert "Action mismatch" in reason

    def test_wrong_resource_is_rejected(self, setup):
        cm = setup["cm"]
        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
        )
        valid, reason = cm.verify(
            token_id=grant.token_id,
            action="spend",
            resource="travel",
            verify_key=setup["issuer_vk"],
        )
        assert not valid
        assert "Resource mismatch" in reason

    def test_wildcard_action_accepts_any_action(self, setup):
        cm = setup["cm"]
        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="*",
            resource="groceries",
            signing_key=setup["issuer_sk"],
        )
        valid, _ = cm.verify(
            token_id=grant.token_id,
            action="anything",
            resource="groceries",
            verify_key=setup["issuer_vk"],
        )
        assert valid


class TestCapabilityDelegation:
    """Test capability delegation chain."""

    def test_delegation_works(self, setup):
        cm = setup["cm"]
        im = setup["im"]

        # Create a delegatable grant
        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
            constraints={"max_amount": 500},
            expires_in=3600,
            delegatable=True,
        )

        # Create a delegate agent
        delegate_doc, delegate_sk = im.create_identity(
            entity_type="agent",
            capabilities=["shopping"],
        )

        # Delegate
        delegated = cm.delegate(
            original_token_id=grant.token_id,
            delegator_did=setup["subject_doc"].did,
            delegate_did=delegate_doc.did,
            signing_key=setup["subject_sk"],
        )

        assert delegated is not None
        assert delegate_doc.did == delegated.subject
        assert setup["subject_doc"].did in delegated.delegation_chain

    def test_delegation_reduces_scope(self, setup):
        cm = setup["cm"]
        im = setup["im"]

        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
            constraints={"max_amount": 500},
            expires_in=3600,
            delegatable=True,
        )

        delegate_doc, _ = im.create_identity(entity_type="agent")

        delegated = cm.delegate(
            original_token_id=grant.token_id,
            delegator_did=setup["subject_doc"].did,
            delegate_did=delegate_doc.did,
            signing_key=setup["subject_sk"],
            reduced_constraints={"max_amount": 100},
            reduced_expires_in=1800,
        )

        assert delegated is not None
        # Delegated constraints should be more restrictive
        assert delegated.constraints["max_amount"] == 100
        # Delegated expiry should be shorter
        remaining = delegated.expires_at - time.time()
        assert remaining <= 1800 + 1  # Small tolerance

    def test_non_delegatable_grant_cannot_be_delegated(self, setup):
        cm = setup["cm"]
        im = setup["im"]

        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
            delegatable=False,  # Not delegatable
        )

        delegate_doc, _ = im.create_identity(entity_type="agent")

        delegated = cm.delegate(
            original_token_id=grant.token_id,
            delegator_did=setup["subject_doc"].did,
            delegate_did=delegate_doc.did,
            signing_key=setup["subject_sk"],
        )

        assert delegated is None

    def test_expired_grant_cannot_be_delegated(self, setup):
        cm = setup["cm"]
        im = setup["im"]

        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
            expires_in=-1,  # Already expired
            delegatable=True,
        )

        delegate_doc, _ = im.create_identity(entity_type="agent")

        delegated = cm.delegate(
            original_token_id=grant.token_id,
            delegator_did=setup["subject_doc"].did,
            delegate_did=delegate_doc.did,
            signing_key=setup["subject_sk"],
        )

        assert delegated is None


class TestCapabilityRevocation:
    """Test capability revocation."""

    def test_revoked_token_fails_verification(self, setup):
        cm = setup["cm"]

        grant = cm.grant(
            issuer_did=setup["issuer_doc"].did,
            subject_did=setup["subject_doc"].did,
            action="spend",
            resource="groceries",
            signing_key=setup["issuer_sk"],
        )

        # Verify it works first
        valid, _ = cm.verify(
            token_id=grant.token_id,
            action="spend",
            resource="groceries",
            verify_key=setup["issuer_vk"],
        )
        assert valid

        # Revoke it
        cm.revoke(grant.token_id)

        # Verify fails after revocation
        valid, reason = cm.verify(
            token_id=grant.token_id,
            action="spend",
            resource="groceries",
            verify_key=setup["issuer_vk"],
        )
        assert not valid
        assert "revoked" in reason.lower()
