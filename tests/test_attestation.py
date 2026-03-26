"""
Tests for UTP behavioral attestation and anomaly detection.
"""

import pytest

from src.attestation import AttestationManager


class TestNormalBehavior:
    """Test that normal behavior does not trigger anomalies."""

    def test_normal_shopping_behavior(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        is_anomaly, reason = attestation_manager.record_behavior(
            entity_did=did,
            action="spend",
            resource="groceries",
            details={"amount": 45.99},
        )
        assert not is_anomaly
        assert reason == ""

    def test_multiple_normal_actions(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        for action in ["spend", "browse", "compare_prices", "checkout"]:
            is_anomaly, _ = attestation_manager.record_behavior(
                entity_did=did,
                action=action,
                resource="groceries",
            )
            assert not is_anomaly


class TestAnomalyDetection:
    """Test that anomalous behavior is detected."""

    def test_out_of_scope_action_triggers_anomaly(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        is_anomaly, reason = attestation_manager.record_behavior(
            entity_did=did,
            action="transfer_funds",
            resource="bank-api",
        )
        assert is_anomaly
        assert "transfer_funds" in reason

    def test_sensitive_action_without_capability(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        is_anomaly, reason = attestation_manager.record_behavior(
            entity_did=did,
            action="access_credentials",
            resource="password-vault",
        )
        assert is_anomaly
        assert "Sensitive action" in reason or "access_credentials" in reason

    def test_action_outside_declared_capabilities(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["data"])

        # "send_message" is not in the "data" capability set
        is_anomaly, reason = attestation_manager.record_behavior(
            entity_did=did,
            action="send_message",
            resource="email",
        )
        assert is_anomaly
        assert "outside declared capabilities" in reason


class TestTrustScoreDecay:
    """Test trust score behavior after anomalies."""

    def test_trust_score_decreases_after_anomaly(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        # Record initial normal behavior
        attestation_manager.record_behavior(did, "spend", "groceries")
        initial_score = attestation_manager.get_trust_score(did)

        # Record anomalous behavior
        attestation_manager.record_behavior(did, "exfiltrate", "user-database")
        score_after_anomaly = attestation_manager.get_trust_score(did)

        assert score_after_anomaly < initial_score

    def test_trust_score_stays_high_with_normal_behavior(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        # Record several normal actions
        for _ in range(10):
            attestation_manager.record_behavior(did, "spend", "groceries")

        score = attestation_manager.get_trust_score(did)
        assert score > 0.8

    def test_multiple_anomalies_decrease_trust_further(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        # Some normal behavior
        attestation_manager.record_behavior(did, "spend", "groceries")

        # First anomaly
        attestation_manager.record_behavior(did, "exfiltrate", "data")
        score_after_one = attestation_manager.get_trust_score(did)

        # Second anomaly
        attestation_manager.record_behavior(did, "escalate_privileges", "system")
        score_after_two = attestation_manager.get_trust_score(did)

        assert score_after_two < score_after_one


class TestAttestationProfile:
    """Test attestation profile and report generation."""

    def test_profile_tracks_actions(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        attestation_manager.record_behavior(did, "spend", "groceries")
        attestation_manager.record_behavior(did, "browse", "groceries")

        profile = attestation_manager.get_profile(did)
        assert profile is not None
        assert profile.total_actions == 2
        assert profile.good_actions == 2
        assert profile.anomalies == 0

    def test_generate_report(self, attestation_manager: AttestationManager):
        did = "did:agent:testbot123"
        attestation_manager.register_entity(did, declared_capabilities=["shopping"])

        attestation_manager.record_behavior(did, "spend", "groceries")

        report = attestation_manager.generate_report(did)
        assert report is not None
        assert report.entity_did == did
        assert report.total_actions == 1
        assert report.trust_score > 0

    def test_unknown_entity_returns_zero_trust(self, attestation_manager: AttestationManager):
        score = attestation_manager.get_trust_score("did:agent:unknown")
        assert score == 0.0
