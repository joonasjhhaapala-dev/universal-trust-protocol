"""
UTP Instant Credential Revocation
In-memory revocation registry designed for future on-chain migration.
"""

import time
from typing import Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class RevocationReason(str, Enum):
    COMPROMISED = "compromised"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    MANUAL = "manual"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class RevocationEntry:
    credential_id: str  # DID or token_id being revoked
    credential_type: str  # "did" or "capability"
    revoked_by: str  # DID of the revoker
    reason: str
    timestamp: float
    propagated_to: list[str] = field(default_factory=list)  # Verifiers that were notified
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class RevocationRegistry:
    """
    In-memory revocation registry.
    Designed with the interface for future on-chain storage (Merkle tree, etc).
    """

    def __init__(self):
        # credential_id -> RevocationEntry
        self._registry: dict[str, RevocationEntry] = {}
        # Registered verifiers (in production these would be network nodes)
        self._verifiers: list[str] = []
        # Revocation event log
        self._events: list[dict] = []

    def revoke(
        self,
        credential_id: str,
        credential_type: str,
        revoked_by: str,
        reason: str = RevocationReason.MANUAL,
        metadata: Optional[dict] = None,
    ) -> RevocationEntry:
        """
        Revoke a credential and propagate to all registered verifiers.
        """
        now = time.time()

        entry = RevocationEntry(
            credential_id=credential_id,
            credential_type=credential_type,
            revoked_by=revoked_by,
            reason=reason,
            timestamp=now,
            metadata=metadata or {},
        )

        self._registry[credential_id] = entry

        # Propagate to verifiers
        propagated = self._propagate(entry)
        entry.propagated_to = propagated

        self._events.append({
            "type": "revocation",
            "credential_id": credential_id,
            "credential_type": credential_type,
            "revoked_by": revoked_by,
            "reason": reason,
            "propagated_count": len(propagated),
            "timestamp": now,
        })

        return entry

    def is_revoked(self, credential_id: str) -> bool:
        """Check if a credential is revoked."""
        return credential_id in self._registry

    def get_revocation(self, credential_id: str) -> Optional[RevocationEntry]:
        """Get the revocation entry for a credential."""
        return self._registry.get(credential_id)

    def _propagate(self, entry: RevocationEntry) -> list[str]:
        """
        Propagate revocation to all registered verifiers.
        In production, this would broadcast to a P2P network or write to a blockchain.
        """
        propagated = []
        for verifier in self._verifiers:
            # Simulate propagation (in production: HTTP call / blockchain tx)
            propagated.append(verifier)
        return propagated

    def register_verifier(self, verifier_id: str):
        """Register a verifier to receive revocation notifications."""
        if verifier_id not in self._verifiers:
            self._verifiers.append(verifier_id)

    def unregister_verifier(self, verifier_id: str):
        """Unregister a verifier."""
        self._verifiers = [v for v in self._verifiers if v != verifier_id]

    def get_all_revocations(self) -> list[RevocationEntry]:
        """Get all revocation entries."""
        return list(self._registry.values())

    def get_events(self, limit: int = 50) -> list[dict]:
        """Get recent revocation events."""
        return self._events[-limit:]

    def get_revocation_count(self) -> int:
        """Get total number of revocations."""
        return len(self._registry)

    def get_merkle_root(self) -> str:
        """
        Compute a Merkle-like root hash of all revocations.
        Placeholder for future on-chain integration.
        """
        import hashlib
        if not self._registry:
            return hashlib.sha256(b"empty").hexdigest()

        hashes = []
        for cid in sorted(self._registry.keys()):
            entry = self._registry[cid]
            h = hashlib.sha256(
                f"{entry.credential_id}:{entry.timestamp}:{entry.reason}".encode()
            ).hexdigest()
            hashes.append(h)

        # Simple hash chain (not a real Merkle tree, but demonstrates the concept)
        combined = ":".join(hashes)
        return hashlib.sha256(combined.encode()).hexdigest()
