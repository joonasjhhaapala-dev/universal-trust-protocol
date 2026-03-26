"""
Tests for UTP REST API using FastAPI TestClient.
"""

import pytest
from fastapi.testclient import TestClient

from src.api import UTPState, state
from src.main import app


@pytest.fixture(autouse=True)
def reset_state():
    """Reset global state before each test to ensure isolation."""
    from src import api
    api.state = UTPState()
    yield
    api.state = UTPState()


@pytest.fixture
def client():
    """Create a FastAPI TestClient."""
    return TestClient(app)


def _register_entity(client: TestClient, entity_type: str = "agent", name: str = "TestAgent") -> dict:
    """Helper to register an entity and return the response JSON."""
    response = client.post("/register", json={
        "entity_type": entity_type,
        "name": name,
        "description": f"Test {entity_type}",
        "capabilities": ["shopping"],
    })
    assert response.status_code == 200
    return response.json()


class TestRegisterEndpoint:
    """Test POST /register endpoint."""

    def test_register_agent(self, client: TestClient):
        data = _register_entity(client, "agent", "TestBot")
        assert data["did"].startswith("did:agent:")
        assert data["name"] == "TestBot"
        assert data["entity_type"] == "agent"
        assert data["public_key"] is not None
        assert data["status"] == "active"
        assert data["trust_score"] == 1.0

    def test_register_human(self, client: TestClient):
        data = _register_entity(client, "human", "Alice")
        assert data["did"].startswith("did:human:")

    def test_register_org(self, client: TestClient):
        data = _register_entity(client, "org", "TrustCorp")
        assert data["did"].startswith("did:org:")

    def test_register_invalid_type(self, client: TestClient):
        response = client.post("/register", json={
            "entity_type": "invalid",
            "name": "Bad",
        })
        assert response.status_code == 400


class TestResolveEndpoint:
    """Test GET /resolve/{did} endpoint."""

    def test_resolve_existing_did(self, client: TestClient):
        reg = _register_entity(client)
        did = reg["did"]

        response = client.get(f"/resolve/{did}")
        assert response.status_code == 200
        data = response.json()
        assert data["did"] == did
        assert data["entity_type"] == "agent"
        assert data["public_key"] is not None

    def test_resolve_nonexistent_did(self, client: TestClient):
        response = client.get("/resolve/did:agent:nonexistent1234")
        assert response.status_code == 404


class TestCapabilityEndpoints:
    """Test capability grant and verify endpoints."""

    def _setup_two_entities(self, client: TestClient) -> tuple[str, str]:
        issuer = _register_entity(client, "human", "Alice")
        subject = _register_entity(client, "agent", "Bot")
        return issuer["did"], subject["did"]

    def test_grant_capability(self, client: TestClient):
        issuer_did, subject_did = self._setup_two_entities(client)

        response = client.post("/capability/grant", json={
            "issuer_did": issuer_did,
            "subject_did": subject_did,
            "action": "spend",
            "resource": "groceries",
            "constraints": {"max_amount": 500},
            "expires_in": 3600,
        })
        assert response.status_code == 200
        data = response.json()
        assert data["token_id"] is not None
        assert data["issuer"] == issuer_did
        assert data["subject"] == subject_did

    def test_verify_capability(self, client: TestClient):
        issuer_did, subject_did = self._setup_two_entities(client)

        # Grant
        grant_resp = client.post("/capability/grant", json={
            "issuer_did": issuer_did,
            "subject_did": subject_did,
            "action": "spend",
            "resource": "groceries",
        })
        token_id = grant_resp.json()["token_id"]

        # Verify
        response = client.post("/capability/verify", json={
            "token_id": token_id,
            "action": "spend",
            "resource": "groceries",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["reason"] == "Valid"

    def test_verify_nonexistent_token(self, client: TestClient):
        response = client.post("/capability/verify", json={
            "token_id": "nonexistent",
            "action": "spend",
            "resource": "groceries",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False

    def test_grant_with_unknown_issuer(self, client: TestClient):
        subject = _register_entity(client, "agent", "Bot")
        response = client.post("/capability/grant", json={
            "issuer_did": "did:human:unknown12345678",
            "subject_did": subject["did"],
            "action": "spend",
            "resource": "groceries",
        })
        assert response.status_code == 404


class TestRevokeEndpoint:
    """Test POST /revoke endpoint."""

    def test_revoke_credential(self, client: TestClient):
        reg = _register_entity(client)
        did = reg["did"]

        response = client.post("/revoke", json={
            "credential_id": did,
            "credential_type": "did",
            "revoked_by": did,
            "reason": "manual",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["revoked"] is True
        assert data["credential_id"] == did

    def test_revoke_capability(self, client: TestClient):
        issuer = _register_entity(client, "human", "Alice")
        subject = _register_entity(client, "agent", "Bot")

        # Grant
        grant_resp = client.post("/capability/grant", json={
            "issuer_did": issuer["did"],
            "subject_did": subject["did"],
            "action": "spend",
            "resource": "groceries",
        })
        token_id = grant_resp.json()["token_id"]

        # Revoke the capability
        response = client.post("/revoke", json={
            "credential_id": token_id,
            "credential_type": "capability",
            "revoked_by": issuer["did"],
            "reason": "compromised",
        })
        assert response.status_code == 200
        assert response.json()["revoked"] is True

        # Verify should now fail
        verify_resp = client.post("/capability/verify", json={
            "token_id": token_id,
            "action": "spend",
            "resource": "groceries",
        })
        assert verify_resp.json()["valid"] is False


class TestTrustEndpoint:
    """Test GET /trust/{did} endpoint."""

    def test_get_trust_score(self, client: TestClient):
        reg = _register_entity(client)
        did = reg["did"]

        response = client.get(f"/trust/{did}")
        assert response.status_code == 200
        data = response.json()
        assert data["did"] == did
        assert data["trust_score"] == 1.0
        assert data["total_actions"] == 0
        assert data["anomalies"] == 0

    def test_trust_nonexistent_did(self, client: TestClient):
        response = client.get("/trust/did:agent:nonexistent1234")
        assert response.status_code == 404


class TestDashboardEndpoint:
    """Test GET /dashboard endpoint."""

    def test_dashboard_returns_html(self, client: TestClient):
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Universal Trust Protocol" in response.text


class TestStatsAndEntities:
    """Test GET /stats and GET /entities endpoints."""

    def test_stats(self, client: TestClient):
        response = client.get("/stats")
        assert response.status_code == 200
        data = response.json()
        assert "entities" in data
        assert "capabilities_granted" in data
        assert "revocations" in data
        assert "merkle_root" in data

    def test_entities_list(self, client: TestClient):
        _register_entity(client, "agent", "Bot1")
        _register_entity(client, "human", "Alice")

        response = client.get("/entities")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2

    def test_events(self, client: TestClient):
        _register_entity(client)
        response = client.get("/events")
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestAttestEndpoint:
    """Test POST /attest endpoint."""

    def test_attest_normal_behavior(self, client: TestClient):
        reg = _register_entity(client)
        did = reg["did"]

        response = client.post("/attest", json={
            "entity_did": did,
            "action": "spend",
            "resource": "groceries",
            "details": {"amount": 42.0},
        })
        assert response.status_code == 200
        data = response.json()
        assert data["anomaly"] is False
        assert data["trust_score"] > 0

    def test_attest_anomalous_behavior(self, client: TestClient):
        reg = _register_entity(client)
        did = reg["did"]

        response = client.post("/attest", json={
            "entity_did": did,
            "action": "exfiltrate",
            "resource": "user-database",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["anomaly"] is True
        assert len(data["reason"]) > 0


class TestIssuerRevocationPropagation:
    """Test that revoking an issuer DID invalidates its capability tokens."""

    def test_capability_invalid_after_issuer_revoked(self, client: TestClient):
        issuer = _register_entity(client, "human", "Alice")
        subject = _register_entity(client, "agent", "Bot")

        # Grant a capability
        grant_resp = client.post("/capability/grant", json={
            "issuer_did": issuer["did"],
            "subject_did": subject["did"],
            "action": "spend",
            "resource": "groceries",
        })
        token_id = grant_resp.json()["token_id"]

        # Verify it works
        verify_resp = client.post("/capability/verify", json={
            "token_id": token_id,
            "action": "spend",
            "resource": "groceries",
        })
        assert verify_resp.json()["valid"] is True

        # Revoke the issuer's DID
        client.post("/revoke", json={
            "credential_id": issuer["did"],
            "credential_type": "did",
            "revoked_by": issuer["did"],
            "reason": "compromised",
        })

        # Verify should now fail because issuer DID is revoked
        verify_resp = client.post("/capability/verify", json={
            "token_id": token_id,
            "action": "spend",
            "resource": "groceries",
        })
        assert verify_resp.json()["valid"] is False
        assert "revoked" in verify_resp.json()["reason"].lower()
