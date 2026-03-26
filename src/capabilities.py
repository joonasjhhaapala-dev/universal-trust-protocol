"""
UTP Capability-based Authorization
Create, verify, delegate, and revoke capability tokens.
"""

import time
from typing import Optional
from dataclasses import dataclass, field, asdict

from nacl.signing import SigningKey, VerifyKey

from . import crypto_utils


@dataclass
class CapabilityGrant:
    token_id: str
    issuer: str  # DID of the issuer
    subject: str  # DID of the entity receiving the capability
    action: str  # e.g., "spend", "read", "write", "execute"
    resource: str  # e.g., "groceries", "travel-booking", "bank-account"
    constraints: dict = field(default_factory=dict)  # e.g., {"max_amount": 500, "currency": "USD"}
    issued_at: float = 0.0
    expires_at: float = 0.0
    delegation_chain: list[str] = field(default_factory=list)  # DIDs in the delegation chain
    delegatable: bool = False
    revoked: bool = False
    signature: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CapabilityManager:
    """Manages capability token creation, verification, delegation, and revocation."""

    def __init__(self):
        # token_id -> CapabilityGrant
        self._grants: dict[str, CapabilityGrant] = {}
        # subject_did -> list of token_ids
        self._subject_index: dict[str, list[str]] = {}
        # Event log
        self._events: list[dict] = []

    def grant(
        self,
        issuer_did: str,
        subject_did: str,
        action: str,
        resource: str,
        signing_key: SigningKey,
        constraints: Optional[dict] = None,
        expires_in: float = 3600,  # 1 hour default
        delegatable: bool = False,
        delegation_chain: Optional[list[str]] = None,
    ) -> CapabilityGrant:
        """
        Grant a capability token from issuer to subject.
        Example: "Agent X can spend up to $500 on groceries for User Y until March 31"
        """
        now = time.time()
        token = crypto_utils.create_capability_token(
            issuer_did=issuer_did,
            subject_did=subject_did,
            action=action,
            resource=resource,
            constraints=constraints or {},
            expires_at=now + expires_in,
            signing_key=signing_key,
            delegation_chain=delegation_chain,
        )

        # Use iat and exp from the signed payload to ensure signature verification works
        token_payload = token["payload"]
        grant = CapabilityGrant(
            token_id=token["token_id"],
            issuer=issuer_did,
            subject=subject_did,
            action=action,
            resource=resource,
            constraints=constraints or {},
            issued_at=token_payload["iat"],
            expires_at=token_payload["exp"],
            delegation_chain=delegation_chain or [],
            delegatable=delegatable,
            signature=token["signature"],
        )

        self._grants[grant.token_id] = grant

        if subject_did not in self._subject_index:
            self._subject_index[subject_did] = []
        self._subject_index[subject_did].append(grant.token_id)

        self._events.append({
            "type": "grant",
            "token_id": grant.token_id,
            "issuer": issuer_did,
            "subject": subject_did,
            "action": action,
            "resource": resource,
            "timestamp": now,
        })

        return grant

    def verify(
        self,
        token_id: str,
        action: str,
        resource: str,
        verify_key: VerifyKey,
    ) -> tuple[bool, str]:
        """
        Verify a capability token:
        - Exists and not revoked
        - Signature is valid
        - Not expired
        - Action and resource match scope
        """
        grant = self._grants.get(token_id)
        if not grant:
            return False, "Token not found"

        if grant.revoked:
            return False, "Token has been revoked"

        if time.time() > grant.expires_at:
            return False, "Token has expired"

        if grant.action != action and grant.action != "*":
            return False, f"Action mismatch: token grants '{grant.action}', requested '{action}'"

        if grant.resource != resource and grant.resource != "*":
            return False, f"Resource mismatch: token grants '{grant.resource}', requested '{resource}'"

        # Verify cryptographic signature
        payload = {
            "iss": grant.issuer,
            "sub": grant.subject,
            "action": grant.action,
            "resource": grant.resource,
            "constraints": grant.constraints,
            "iat": grant.issued_at,
            "exp": grant.expires_at,
            "delegation_chain": grant.delegation_chain,
            "jti": grant.token_id,
        }
        sig_valid = crypto_utils.verify_json(payload, grant.signature, verify_key)
        if not sig_valid:
            return False, "Invalid signature"

        self._events.append({
            "type": "verify",
            "token_id": token_id,
            "action": action,
            "resource": resource,
            "result": "valid",
            "timestamp": time.time(),
        })

        return True, "Valid"

    def delegate(
        self,
        original_token_id: str,
        delegator_did: str,
        delegate_did: str,
        signing_key: SigningKey,
        reduced_constraints: Optional[dict] = None,
        reduced_expires_in: Optional[float] = None,
    ) -> Optional[CapabilityGrant]:
        """
        Delegate a capability to another entity with optionally reduced scope.
        The delegation chain tracks the full provenance.
        """
        original = self._grants.get(original_token_id)
        if not original:
            return None

        if not original.delegatable:
            return None

        if original.revoked:
            return None

        if time.time() > original.expires_at:
            return None

        if original.subject != delegator_did:
            return None

        # Merge constraints (delegated constraints can only be more restrictive)
        constraints = dict(original.constraints)
        if reduced_constraints:
            for key, value in reduced_constraints.items():
                if key in constraints:
                    # For numeric constraints, take the more restrictive (lower) value
                    if isinstance(value, (int, float)) and isinstance(constraints[key], (int, float)):
                        constraints[key] = min(value, constraints[key])
                    else:
                        constraints[key] = value
                else:
                    constraints[key] = value

        # Expiry can only be shorter
        max_remaining = original.expires_at - time.time()
        if reduced_expires_in:
            expires_in = min(reduced_expires_in, max_remaining)
        else:
            expires_in = max_remaining

        chain = original.delegation_chain + [delegator_did]

        new_grant = self.grant(
            issuer_did=delegator_did,
            subject_did=delegate_did,
            action=original.action,
            resource=original.resource,
            signing_key=signing_key,
            constraints=constraints,
            expires_in=expires_in,
            delegatable=original.delegatable,
            delegation_chain=chain,
        )

        self._events.append({
            "type": "delegate",
            "original_token_id": original_token_id,
            "new_token_id": new_grant.token_id,
            "delegator": delegator_did,
            "delegate": delegate_did,
            "timestamp": time.time(),
        })

        return new_grant

    def revoke(self, token_id: str) -> bool:
        """Revoke a capability token."""
        grant = self._grants.get(token_id)
        if not grant:
            return False
        grant.revoked = True

        self._events.append({
            "type": "revoke",
            "token_id": token_id,
            "timestamp": time.time(),
        })

        return True

    def get_grants_for(self, subject_did: str) -> list[CapabilityGrant]:
        """Get all capability grants for a subject."""
        token_ids = self._subject_index.get(subject_did, [])
        return [self._grants[tid] for tid in token_ids if tid in self._grants]

    def get_grant(self, token_id: str) -> Optional[CapabilityGrant]:
        """Get a specific grant by token ID."""
        return self._grants.get(token_id)

    def get_events(self, limit: int = 50) -> list[dict]:
        """Get recent capability events."""
        return self._events[-limit:]

    def list_all(self) -> list[CapabilityGrant]:
        """List all grants."""
        return list(self._grants.values())
