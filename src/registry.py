"""
UTP Agent/Entity Registry
Register, lookup, search, and track entity lifecycle.
"""

import time
from typing import Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class EntityStatus(str, Enum):
    CREATED = "created"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


@dataclass
class EntityRecord:
    did: str
    entity_type: str  # "agent", "human", "org"
    name: str
    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    status: str = EntityStatus.CREATED
    trust_score: float = 1.0
    controller: Optional[str] = None
    created_at: float = 0.0
    updated_at: float = 0.0
    metadata: dict = field(default_factory=dict)
    lifecycle_events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class EntityRegistry:
    """Manages the registration, lookup, and lifecycle of entities."""

    def __init__(self):
        # DID -> EntityRecord
        self._entities: dict[str, EntityRecord] = {}
        # name -> DID (for name-based lookup)
        self._name_index: dict[str, str] = {}
        # Events log
        self._events: list[dict] = []

    def register(
        self,
        did: str,
        entity_type: str,
        name: str,
        description: str = "",
        capabilities: Optional[list[str]] = None,
        controller: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> EntityRecord:
        """Register a new entity in the registry."""
        now = time.time()

        record = EntityRecord(
            did=did,
            entity_type=entity_type,
            name=name,
            description=description,
            capabilities=capabilities or [],
            status=EntityStatus.ACTIVE,
            trust_score=1.0,
            controller=controller,
            created_at=now,
            updated_at=now,
            metadata=metadata or {},
            lifecycle_events=[{
                "event": "registered",
                "timestamp": now,
                "details": {"entity_type": entity_type},
            }],
        )

        self._entities[did] = record
        self._name_index[name.lower()] = did

        self._events.append({
            "type": "register",
            "did": did,
            "name": name,
            "entity_type": entity_type,
            "timestamp": now,
        })

        return record

    def lookup(self, did: str) -> Optional[EntityRecord]:
        """Look up an entity by DID."""
        return self._entities.get(did)

    def lookup_by_name(self, name: str) -> Optional[EntityRecord]:
        """Look up an entity by name."""
        did = self._name_index.get(name.lower())
        if did:
            return self._entities.get(did)
        return None

    def update_status(self, did: str, status: str, reason: str = "") -> bool:
        """Update an entity's lifecycle status."""
        record = self._entities.get(did)
        if not record:
            return False

        old_status = record.status
        record.status = status
        record.updated_at = time.time()
        record.lifecycle_events.append({
            "event": "status_change",
            "from": old_status,
            "to": status,
            "reason": reason,
            "timestamp": time.time(),
        })

        self._events.append({
            "type": "status_change",
            "did": did,
            "from": old_status,
            "to": status,
            "reason": reason,
            "timestamp": time.time(),
        })

        return True

    def update_trust_score(self, did: str, score: float) -> bool:
        """Update an entity's trust score."""
        record = self._entities.get(did)
        if not record:
            return False
        record.trust_score = score
        record.updated_at = time.time()
        return True

    def search(
        self,
        entity_type: Optional[str] = None,
        capability: Optional[str] = None,
        status: Optional[str] = None,
        min_trust_score: Optional[float] = None,
    ) -> list[EntityRecord]:
        """Search entities by various criteria."""
        results = list(self._entities.values())

        if entity_type:
            results = [e for e in results if e.entity_type == entity_type]
        if capability:
            results = [e for e in results if capability in e.capabilities]
        if status:
            results = [e for e in results if e.status == status]
        if min_trust_score is not None:
            results = [e for e in results if e.trust_score >= min_trust_score]

        return results

    def list_all(self) -> list[EntityRecord]:
        """List all registered entities."""
        return list(self._entities.values())

    def get_events(self, limit: int = 50) -> list[dict]:
        """Get recent registry events."""
        return self._events[-limit:]

    def count(self) -> dict:
        """Get entity counts by type and status."""
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for e in self._entities.values():
            by_type[e.entity_type] = by_type.get(e.entity_type, 0) + 1
            by_status[e.status] = by_status.get(e.status, 0) + 1
        return {"by_type": by_type, "by_status": by_status, "total": len(self._entities)}
