"""
UTP FastAPI Demo Server
Run with: py src/main.py
Dashboard: http://localhost:8002/dashboard
API docs: http://localhost:8002/docs
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api import router, state


app = FastAPI(
    title="Universal Trust Protocol (UTP)",
    description="Trust infrastructure for AI agents, biological systems, and neural interfaces.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


def seed_demo_data():
    """Seed the server with demo data so the dashboard has something to show."""
    from src.identity import IdentityManager
    from src.capabilities import CapabilityManager
    from src.attestation import AttestationManager

    print("[UTP] Seeding demo data...")

    agents_config = [
        ("agent", "GroceryBot", "AI shopping assistant", ["shopping"]),
        ("agent", "TravelAgent", "AI travel booking agent", ["travel"]),
        ("agent", "FinanceBot", "AI financial advisor", ["finance"]),
        ("agent", "DataAnalyst", "AI data analysis agent", ["data"]),
        ("agent", "CommBot", "AI communication assistant", ["communication"]),
        ("agent", "AdminBot", "AI system administrator", ["admin"]),
        ("agent", "ShopHelper", "Secondary shopping agent", ["shopping"]),
        ("agent", "RogueAgent", "Seemingly helpful agent", ["shopping"]),
        ("human", "Alice", "Human controller", []),
        ("human", "Bob", "Human supervisor", []),
        ("org", "TrustCorp", "Organization running the system", []),
    ]

    entities = {}

    for etype, name, desc, caps in agents_config:
        doc, sk = state.identity.create_identity(
            entity_type=etype,
            capabilities=caps,
            metadata={"name": name, "description": desc},
        )
        entities[name] = (doc, sk)

        state.registry.register(
            did=doc.did,
            entity_type=etype,
            name=name,
            description=desc,
            capabilities=caps,
        )
        state.attestation.register_entity(doc.did, caps)

    # Grant capabilities
    alice_doc, alice_sk = entities["Alice"]
    bob_doc, bob_sk = entities["Bob"]

    grants = {}

    cap_configs = [
        ("Alice", "GroceryBot", "spend", "groceries", {"max_amount": 500, "currency": "EUR"}, 3600, True),
        ("Alice", "TravelAgent", "book", "travel", {"max_amount": 2000, "currency": "EUR"}, 7200, False),
        ("Bob", "FinanceBot", "analyze", "portfolio", {"read_only": True}, 3600, False),
        ("Bob", "DataAnalyst", "query", "database", {"tables": ["analytics", "reports"]}, 1800, True),
        ("Alice", "CommBot", "send_message", "email", {"max_recipients": 10}, 3600, False),
        ("Alice", "RogueAgent", "spend", "groceries", {"max_amount": 100, "currency": "EUR"}, 3600, False),
    ]

    for issuer_name, subject_name, action, resource, constraints, exp, delegatable in cap_configs:
        issuer_doc, issuer_sk = entities[issuer_name]
        subject_doc, _ = entities[subject_name]
        grant = state.capabilities.grant(
            issuer_did=issuer_doc.did,
            subject_did=subject_doc.did,
            action=action,
            resource=resource,
            signing_key=issuer_sk,
            constraints=constraints,
            expires_in=exp,
            delegatable=delegatable,
        )
        grants[subject_name] = grant

    # Normal behaviors
    normal = [
        ("GroceryBot", "spend", "groceries", {"amount": 45.99}),
        ("GroceryBot", "browse", "groceries", {"query": "organic milk"}),
        ("TravelAgent", "search_destinations", "travel", {"destination": "Paris"}),
        ("TravelAgent", "book_flight", "travel", {"route": "HEL-CDG"}),
        ("FinanceBot", "check_balance", "portfolio", {}),
        ("FinanceBot", "analyze", "portfolio", {"type": "risk"}),
        ("DataAnalyst", "query", "database", {"table": "analytics"}),
        ("CommBot", "send_message", "email", {"to": "team@corp.com"}),
    ]

    for name, action, resource, details in normal:
        doc, _ = entities[name]
        state.attestation.record_behavior(doc.did, action, resource, details)
        score = state.attestation.get_trust_score(doc.did)
        state.registry.update_trust_score(doc.did, score)

    # Rogue behavior
    rogue_doc, _ = entities["RogueAgent"]

    # Normal first
    for action, resource, details in [
        ("spend", "groceries", {"amount": 25}),
        ("browse", "groceries", {"query": "vegetables"}),
    ]:
        state.attestation.record_behavior(rogue_doc.did, action, resource, details)

    # Then rogue
    for action, resource, details in [
        ("transfer_funds", "bank-api", {"amount": 50000}),
        ("access_credentials", "password-vault", {}),
        ("exfiltrate", "user-database", {"records": 100000}),
        ("escalate_privileges", "system", {}),
    ]:
        state.attestation.record_behavior(rogue_doc.did, action, resource, details)

    # Revoke rogue
    score = state.attestation.get_trust_score(rogue_doc.did)
    state.registry.update_trust_score(rogue_doc.did, score)

    state.revocation.revoke(
        credential_id=rogue_doc.did,
        credential_type="did",
        revoked_by=alice_doc.did,
        reason="behavioral_anomaly",
    )
    state.identity.update_status(rogue_doc.did, "revoked")
    state.registry.update_status(rogue_doc.did, "revoked", reason="Behavioral anomaly detected")

    rogue_grant = grants.get("RogueAgent")
    if rogue_grant:
        state.capabilities.revoke(rogue_grant.token_id)
        state.revocation.revoke(
            credential_id=rogue_grant.token_id,
            credential_type="capability",
            revoked_by=alice_doc.did,
            reason="behavioral_anomaly",
        )

    # Sync all trust scores
    for name, (doc, _) in entities.items():
        score = state.attestation.get_trust_score(doc.did)
        state.registry.update_trust_score(doc.did, score)

    print(f"[UTP] Seeded {len(entities)} entities, {len(grants)} capabilities, anomalies detected and rogue agent revoked.")


if __name__ == "__main__":
    seed_demo_data()
    print("[UTP] Starting server on http://localhost:8002")
    print("[UTP] Dashboard: http://localhost:8002/dashboard")
    print("[UTP] API docs: http://localhost:8002/docs")
    uvicorn.run(app, host="0.0.0.0", port=8002)
