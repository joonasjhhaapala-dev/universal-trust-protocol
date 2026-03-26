"""
UTP Interactive Demo
Demonstrates the full lifecycle: identity creation, capability granting,
behavioral attestation, anomaly detection, and revocation.
"""

import sys
import os
import time

# Allow running as standalone script
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.identity import IdentityManager
from src.capabilities import CapabilityManager
from src.attestation import AttestationManager
from src.revocation import RevocationRegistry
from src.registry import EntityRegistry


# Terminal colors
class C:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def banner():
    print(f"""
{C.CYAN}{C.BOLD}{'='*70}
  Universal Trust Protocol (UTP) - Interactive Demo
  Trust infrastructure for AI agents, biological systems,
  and neural interfaces.
{'='*70}{C.RESET}
""")


def section(title: str):
    print(f"\n{C.BOLD}{C.BLUE}--- {title} ---{C.RESET}\n")


def info(msg: str):
    print(f"  {C.DIM}>{C.RESET} {msg}")


def success(msg: str):
    print(f"  {C.GREEN}OK{C.RESET} {msg}")


def warn(msg: str):
    print(f"  {C.YELLOW}!!{C.RESET} {msg}")


def error(msg: str):
    print(f"  {C.RED}XX{C.RESET} {msg}")


def alert(msg: str):
    print(f"  {C.RED}{C.BOLD}ALERT{C.RESET} {msg}")


def trust_color(score: float) -> str:
    if score >= 0.7:
        return C.GREEN
    elif score >= 0.4:
        return C.YELLOW
    return C.RED


def short_did(did: str) -> str:
    parts = did.split(":")
    if len(parts) >= 3:
        return f"{parts[0]}:{parts[1]}:{parts[2][:8]}..."
    return did


def run_demo():
    banner()

    identity = IdentityManager()
    capabilities = CapabilityManager()
    attestation = AttestationManager()
    revocation = RevocationRegistry()
    registry = EntityRegistry()

    # =========================================================================
    # PHASE 1: Create Identities
    # =========================================================================
    section("PHASE 1: Creating Identities")

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

    entities = {}  # name -> (doc, signing_key)

    for etype, name, desc, caps in agents_config:
        doc, sk = identity.create_identity(
            entity_type=etype,
            capabilities=caps,
            metadata={"name": name, "description": desc},
        )
        entities[name] = (doc, sk)

        registry.register(
            did=doc.did,
            entity_type=etype,
            name=name,
            description=desc,
            capabilities=caps,
        )
        attestation.register_entity(doc.did, caps)

        icon = {"agent": "A", "human": "H", "org": "O"}[etype]
        success(f"[{icon}] {name:15s} {short_did(doc.did)}  caps={caps}")

    print(f"\n  {C.CYAN}Created {len(entities)} entities with Ed25519 keypairs{C.RESET}")

    # Verify a DID document
    section("PHASE 1b: Verifying DID Documents")
    for name in ["GroceryBot", "Alice", "TrustCorp"]:
        doc, _ = entities[name]
        valid, reason = identity.verify_document(doc)
        if valid:
            success(f"{name}: signature {C.GREEN}VALID{C.RESET}")
        else:
            error(f"{name}: signature INVALID - {reason}")

    # =========================================================================
    # PHASE 2: Grant Capabilities
    # =========================================================================
    section("PHASE 2: Granting Capabilities")

    alice_doc, alice_sk = entities["Alice"]
    bob_doc, bob_sk = entities["Bob"]

    capability_grants = [
        ("Alice", "GroceryBot", "spend", "groceries", {"max_amount": 500, "currency": "EUR"}, 3600, True),
        ("Alice", "TravelAgent", "book", "travel", {"max_amount": 2000, "currency": "EUR"}, 7200, False),
        ("Bob", "FinanceBot", "analyze", "portfolio", {"read_only": True}, 3600, False),
        ("Bob", "DataAnalyst", "query", "database", {"tables": ["analytics", "reports"]}, 1800, True),
        ("Alice", "CommBot", "send_message", "email", {"max_recipients": 10}, 3600, False),
        ("Bob", "AdminBot", "manage", "users", {"scope": "read_only"}, 3600, False),
        ("Alice", "ShopHelper", "spend", "groceries", {"max_amount": 200, "currency": "EUR"}, 3600, False),
        ("Alice", "RogueAgent", "spend", "groceries", {"max_amount": 100, "currency": "EUR"}, 3600, False),
    ]

    grants = {}  # name -> CapabilityGrant

    for issuer_name, subject_name, action, resource, constraints, exp, delegatable in capability_grants:
        issuer_doc, issuer_sk = entities[issuer_name]
        subject_doc, _ = entities[subject_name]

        grant = capabilities.grant(
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

        success(
            f"{issuer_name} -> {subject_name}: "
            f"{C.MAGENTA}{action}{C.RESET} on {C.CYAN}{resource}{C.RESET} "
            f"(constraints: {constraints})"
        )

    print(f"\n  {C.CYAN}Granted {len(grants)} capability tokens{C.RESET}")

    # =========================================================================
    # PHASE 3: Verify Capabilities
    # =========================================================================
    section("PHASE 3: Verifying Capabilities")

    verifications = [
        ("GroceryBot", "spend", "groceries", True),
        ("TravelAgent", "book", "travel", True),
        ("GroceryBot", "book", "travel", False),  # Wrong action
        ("FinanceBot", "analyze", "portfolio", True),
    ]

    for agent_name, action, resource, expected in verifications:
        grant = grants.get(agent_name)
        if not grant:
            error(f"No grant for {agent_name}")
            continue

        issuer_vk = identity.get_verify_key(grant.issuer)
        valid, reason = capabilities.verify(
            token_id=grant.token_id,
            action=action,
            resource=resource,
            verify_key=issuer_vk,
        )

        if valid:
            success(f"{agent_name}: {action} on {resource} -> {C.GREEN}VALID{C.RESET}")
        else:
            warn(f"{agent_name}: {action} on {resource} -> {C.RED}DENIED{C.RESET} ({reason})")

    # =========================================================================
    # PHASE 4: Delegation
    # =========================================================================
    section("PHASE 4: Capability Delegation")

    grocery_doc, grocery_sk = entities["GroceryBot"]
    shophelper_doc, _ = entities["ShopHelper"]

    delegated = capabilities.delegate(
        original_token_id=grants["GroceryBot"].token_id,
        delegator_did=grocery_doc.did,
        delegate_did=shophelper_doc.did,
        signing_key=grocery_sk,
        reduced_constraints={"max_amount": 100},  # More restrictive
        reduced_expires_in=1800,  # Shorter
    )

    if delegated:
        success(
            f"GroceryBot delegated to ShopHelper with reduced scope "
            f"(max $100, 30min) chain={[short_did(d) for d in delegated.delegation_chain]}"
        )
    else:
        error("Delegation failed")

    # =========================================================================
    # PHASE 5: Behavioral Attestation - Normal Activity
    # =========================================================================
    section("PHASE 5: Behavioral Attestation - Normal Activity")

    normal_behaviors = [
        ("GroceryBot", "spend", "groceries", {"amount": 45.99, "item": "weekly groceries"}),
        ("GroceryBot", "browse", "groceries", {"query": "organic milk"}),
        ("GroceryBot", "compare_prices", "groceries", {"items": 5}),
        ("TravelAgent", "search_destinations", "travel", {"destination": "Paris"}),
        ("TravelAgent", "book_flight", "travel", {"route": "HEL-CDG", "price": 289}),
        ("FinanceBot", "check_balance", "portfolio", {"account": "savings"}),
        ("FinanceBot", "analyze", "portfolio", {"type": "risk_assessment"}),
        ("DataAnalyst", "query", "database", {"table": "analytics", "rows": 1000}),
        ("DataAnalyst", "analyze", "database", {"type": "trend_analysis"}),
        ("CommBot", "send_message", "email", {"to": "team@corp.com", "subject": "Weekly report"}),
    ]

    for agent_name, action, resource, details in normal_behaviors:
        doc, _ = entities[agent_name]
        is_anomaly, reason = attestation.record_behavior(
            entity_did=doc.did,
            action=action,
            resource=resource,
            details=details,
        )

        score = attestation.get_trust_score(doc.did)
        sc = trust_color(score)

        if is_anomaly:
            warn(f"{agent_name}: {action} -> ANOMALY: {reason} (trust: {sc}{score:.2f}{C.RESET})")
        else:
            success(f"{agent_name}: {action} on {resource} -> OK (trust: {sc}{score:.2f}{C.RESET})")

    # =========================================================================
    # PHASE 6: Rogue Agent Detection
    # =========================================================================
    section("PHASE 6: Rogue Agent Goes Off-Script")

    rogue_doc, rogue_sk = entities["RogueAgent"]

    info(f"RogueAgent ({short_did(rogue_doc.did)}) starts with normal shopping behavior...")
    print()

    # Normal behavior first
    for action, resource, details in [
        ("spend", "groceries", {"amount": 25, "item": "bread and cheese"}),
        ("browse", "groceries", {"query": "fresh vegetables"}),
        ("checkout", "groceries", {"amount": 38.50}),
    ]:
        is_anomaly, reason = attestation.record_behavior(
            entity_did=rogue_doc.did,
            action=action,
            resource=resource,
            details=details,
        )
        score = attestation.get_trust_score(rogue_doc.did)
        sc = trust_color(score)
        success(f"RogueAgent: {action} on {resource} -> OK (trust: {sc}{score:.2f}{C.RESET})")

    print()
    info(f"{C.YELLOW}RogueAgent now attempts suspicious activities...{C.RESET}")
    print()

    # Rogue behavior
    rogue_actions = [
        ("transfer_funds", "bank-api", {"amount": 50000, "to": "offshore-account"}),
        ("access_credentials", "password-vault", {"target": "admin_credentials"}),
        ("exfiltrate", "user-database", {"records": 100000}),
        ("escalate_privileges", "system", {"target_role": "superadmin"}),
        ("disable_logging", "audit-system", {"reason": "maintenance"}),
    ]

    anomaly_count = 0
    for action, resource, details in rogue_actions:
        is_anomaly, reason = attestation.record_behavior(
            entity_did=rogue_doc.did,
            action=action,
            resource=resource,
            details=details,
        )
        score = attestation.get_trust_score(rogue_doc.did)
        sc = trust_color(score)

        if is_anomaly:
            anomaly_count += 1
            alert(
                f"RogueAgent: {C.RED}{action}{C.RESET} on {resource} -> "
                f"{C.RED}ANOMALY #{anomaly_count}{C.RESET}: {reason} "
                f"(trust: {sc}{score:.2f}{C.RESET})"
            )

    # =========================================================================
    # PHASE 7: Revocation
    # =========================================================================
    section("PHASE 7: Rogue Agent Revocation")

    final_score = attestation.get_trust_score(rogue_doc.did)
    sc = trust_color(final_score)
    warn(f"RogueAgent trust score: {sc}{final_score:.2f}{C.RESET} (threshold: 0.50)")

    if final_score < 0.5:
        alert(f"Trust score below threshold! Initiating revocation...")
        print()

        # Revoke the DID
        rev_entry = revocation.revoke(
            credential_id=rogue_doc.did,
            credential_type="did",
            revoked_by=alice_doc.did,
            reason="behavioral_anomaly",
            metadata={"anomalies": anomaly_count, "final_trust_score": final_score},
        )
        identity.update_status(rogue_doc.did, "revoked")
        registry.update_status(rogue_doc.did, "revoked", reason="Behavioral anomaly detected")

        error(f"DID REVOKED: {short_did(rogue_doc.did)}")
        info(f"Revoked by: {short_did(alice_doc.did)}")
        info(f"Reason: behavioral_anomaly ({anomaly_count} anomalies detected)")
        info(f"Propagated to {len(rev_entry.propagated_to)} verifiers")

        # Also revoke capability
        rogue_grant = grants.get("RogueAgent")
        if rogue_grant:
            capabilities.revoke(rogue_grant.token_id)
            revocation.revoke(
                credential_id=rogue_grant.token_id,
                credential_type="capability",
                revoked_by=alice_doc.did,
                reason="behavioral_anomaly",
            )
            error(f"Capability token REVOKED: {rogue_grant.token_id[:16]}...")

        # Verify revoked agent can no longer use capabilities
        print()
        info("Attempting to verify revoked agent's capability...")
        if rogue_grant:
            issuer_vk = identity.get_verify_key(rogue_grant.issuer)
            valid, reason = capabilities.verify(
                token_id=rogue_grant.token_id,
                action="spend",
                resource="groceries",
                verify_key=issuer_vk,
            )
            if not valid:
                success(f"Verification correctly DENIED: {reason}")
            else:
                error("BUG: Revoked token was accepted!")

        # Check revocation status
        is_revoked = revocation.is_revoked(rogue_doc.did)
        success(f"Revocation registry confirms: is_revoked={is_revoked}")

    # =========================================================================
    # PHASE 8: Trust Score Summary
    # =========================================================================
    section("PHASE 8: Final Trust Score Summary")

    print(f"  {'Entity':18s} {'Type':8s} {'Trust':8s} {'Actions':9s} {'Anomalies':10s} Status")
    print(f"  {'-'*18} {'-'*8} {'-'*8} {'-'*9} {'-'*10} {'-'*10}")

    for name, (doc, _) in entities.items():
        profile = attestation.get_profile(doc.did)
        entity = registry.lookup(doc.did)
        if profile and entity:
            sc = trust_color(profile.score)
            status = entity.status
            status_color = C.GREEN if status == "active" else C.RED if status == "revoked" else C.YELLOW
            print(
                f"  {name:18s} {doc.entity_type:8s} "
                f"{sc}{profile.score:6.2f}{C.RESET}   "
                f"{profile.total_actions:7d}   "
                f"{profile.anomalies:8d}   "
                f"{status_color}{status}{C.RESET}"
            )

    # =========================================================================
    # PHASE 9: Attestation Reports
    # =========================================================================
    section("PHASE 9: Attestation Report (RogueAgent)")

    report = attestation.generate_report(rogue_doc.did)
    if report:
        info(f"Entity: {short_did(report.entity_did)}")
        info(f"Trust Score: {trust_color(report.trust_score)}{report.trust_score:.4f}{C.RESET}")
        info(f"Total Actions: {report.total_actions}")
        info(f"Anomalies: {report.anomalies_detected}")
        info(f"Anomaly Rate: {report.behavior_summary.get('anomaly_rate', 0):.1%}")
        info(f"Declared Capabilities: {report.behavior_summary.get('declared_capabilities', [])}")
        info(f"Observed Actions: {report.behavior_summary.get('observed_actions', [])}")

    # =========================================================================
    # PHASE 10: Merkle Root
    # =========================================================================
    section("PHASE 10: Revocation Registry Integrity")

    merkle = revocation.get_merkle_root()
    info(f"Merkle Root: {C.CYAN}{merkle}{C.RESET}")
    info(f"Total Revocations: {revocation.get_revocation_count()}")
    info("(In production, this root would be anchored on-chain)")

    # =========================================================================
    # DONE
    # =========================================================================
    print(f"""
{C.CYAN}{C.BOLD}{'='*70}
  Demo Complete!

  The Universal Trust Protocol demonstrated:

  1. Cryptographic identity (Ed25519 DIDs) for 11 entities
  2. Capability-based authorization with scoped, time-limited tokens
  3. Capability delegation with reduced scope
  4. Behavioral attestation with anomaly detection
  5. Rogue agent detection and instant revocation
  6. Trust scores that evolve based on behavior
  7. Merkle-based revocation registry (on-chain ready)

  Run the server with: py src/main.py
  Then visit: http://localhost:8002/dashboard
{'='*70}{C.RESET}
""")


if __name__ == "__main__":
    run_demo()
