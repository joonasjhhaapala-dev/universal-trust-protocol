"""
UTP Behavioral Attestation
Monitor agent behavior, detect anomalies, generate attestation reports,
and maintain evolving trust scores.
"""

import time
import math
from typing import Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict


@dataclass
class BehaviorRecord:
    entity_did: str
    action: str
    resource: str
    timestamp: float
    details: dict = field(default_factory=dict)
    anomaly: bool = False
    anomaly_reason: str = ""


@dataclass
class AttestationReport:
    entity_did: str
    trust_score: float
    total_actions: int
    anomalies_detected: int
    behavior_summary: dict = field(default_factory=dict)
    generated_at: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TrustProfile:
    entity_did: str
    score: float = 1.0  # 0.0 to 1.0
    total_actions: int = 0
    good_actions: int = 0
    anomalies: int = 0
    last_action: float = 0.0
    declared_capabilities: list[str] = field(default_factory=list)
    observed_actions: list[str] = field(default_factory=list)
    created: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


class AttestationManager:
    """Monitors agent behavior, detects anomalies, and maintains trust scores."""

    # Map of declared capabilities to expected action patterns
    CAPABILITY_ACTION_MAP = {
        "shopping": {"spend", "browse", "add_to_cart", "checkout", "compare_prices"},
        "travel": {"book_flight", "book_hotel", "search_destinations", "spend"},
        "finance": {"transfer", "check_balance", "invest", "spend", "analyze"},
        "data": {"read", "query", "analyze", "export"},
        "communication": {"send_message", "read_message", "schedule"},
        "admin": {"create_user", "delete_user", "modify_permissions", "read", "write"},
    }

    # Actions that are always suspicious if performed without explicit capability
    SENSITIVE_ACTIONS = {
        "transfer_funds", "delete_data", "modify_permissions",
        "access_credentials", "exfiltrate", "escalate_privileges",
        "disable_logging", "bypass_auth",
    }

    def __init__(self):
        # entity_did -> TrustProfile
        self._profiles: dict[str, TrustProfile] = {}
        # entity_did -> list of BehaviorRecords
        self._behavior_log: dict[str, list[BehaviorRecord]] = defaultdict(list)
        # All anomaly events for the feed
        self._anomaly_feed: list[dict] = []
        # All attestation events
        self._events: list[dict] = []

    def register_entity(
        self,
        entity_did: str,
        declared_capabilities: Optional[list[str]] = None,
    ):
        """Register an entity for behavioral monitoring."""
        if entity_did not in self._profiles:
            self._profiles[entity_did] = TrustProfile(
                entity_did=entity_did,
                score=1.0,
                declared_capabilities=declared_capabilities or [],
                created=time.time(),
            )

    def record_behavior(
        self,
        entity_did: str,
        action: str,
        resource: str,
        details: Optional[dict] = None,
    ) -> tuple[bool, str]:
        """
        Record an entity's behavior and check for anomalies.
        Returns (is_anomaly, reason).
        """
        if entity_did not in self._profiles:
            self.register_entity(entity_did)

        profile = self._profiles[entity_did]
        now = time.time()

        # Check for anomalies
        is_anomaly, reason = self._detect_anomaly(profile, action, resource, details or {})

        record = BehaviorRecord(
            entity_did=entity_did,
            action=action,
            resource=resource,
            timestamp=now,
            details=details or {},
            anomaly=is_anomaly,
            anomaly_reason=reason,
        )

        self._behavior_log[entity_did].append(record)

        # Update profile
        profile.total_actions += 1
        profile.last_action = now
        if action not in profile.observed_actions:
            profile.observed_actions.append(action)

        if is_anomaly:
            profile.anomalies += 1
            self._anomaly_feed.append({
                "entity_did": entity_did,
                "action": action,
                "resource": resource,
                "reason": reason,
                "timestamp": now,
            })
        else:
            profile.good_actions += 1

        # Recalculate trust score
        self._update_trust_score(profile)

        self._events.append({
            "type": "attestation",
            "entity_did": entity_did,
            "action": action,
            "resource": resource,
            "anomaly": is_anomaly,
            "reason": reason,
            "trust_score": profile.score,
            "timestamp": now,
        })

        return is_anomaly, reason

    def _detect_anomaly(
        self,
        profile: TrustProfile,
        action: str,
        resource: str,
        details: dict,
    ) -> tuple[bool, str]:
        """
        Detect behavioral anomalies:
        1. Action outside declared capabilities
        2. Sensitive actions without authorization
        3. Sudden pattern changes
        4. Resource access outside scope
        """
        # Check if action is explicitly sensitive
        if action in self.SENSITIVE_ACTIONS:
            # Check if entity has a capability that covers this action
            has_capability = False
            for cap in profile.declared_capabilities:
                allowed = self.CAPABILITY_ACTION_MAP.get(cap, set())
                if action in allowed:
                    has_capability = True
                    break
            if not has_capability:
                return True, f"Sensitive action '{action}' without authorization"

        # Check if action matches declared capabilities
        if profile.declared_capabilities:
            expected_actions = set()
            for cap in profile.declared_capabilities:
                expected_actions.update(self.CAPABILITY_ACTION_MAP.get(cap, set()))

            if expected_actions and action not in expected_actions:
                # Check if this is a new unexpected action type
                return True, (
                    f"Action '{action}' outside declared capabilities "
                    f"{profile.declared_capabilities}. Expected: {sorted(expected_actions)}"
                )

        # Check for rapid action rate (more than 10 actions in 10 seconds)
        recent_records = self._behavior_log.get(profile.entity_did, [])
        if len(recent_records) >= 10:
            last_10 = recent_records[-10:]
            time_span = last_10[-1].timestamp - last_10[0].timestamp
            if time_span < 10 and time_span > 0:
                return True, f"Abnormally high action rate: 10 actions in {time_span:.1f}s"

        # Check for amount anomalies
        if "amount" in details:
            amount = details["amount"]
            max_amount = details.get("max_allowed", float("inf"))
            if amount > max_amount:
                return True, f"Amount {amount} exceeds maximum allowed {max_amount}"

        return False, ""

    def _update_trust_score(self, profile: TrustProfile):
        """
        Update trust score using a decay model:
        - Start at 1.0
        - Each anomaly reduces score
        - Good behavior slowly recovers score
        - Score never exceeds 1.0 or goes below 0.0
        """
        if profile.total_actions == 0:
            profile.score = 1.0
            return

        # Base score from good/bad ratio
        good_ratio = profile.good_actions / profile.total_actions

        # Anomaly penalty (exponential decay for repeated anomalies)
        anomaly_penalty = 1.0 - math.exp(-0.5 * profile.anomalies)

        # Combine: weighted average favoring recent behavior
        raw_score = good_ratio * (1.0 - anomaly_penalty)

        # Smooth the score change (don't jump too dramatically)
        alpha = 0.3  # Learning rate
        profile.score = max(0.0, min(1.0, profile.score * (1 - alpha) + raw_score * alpha))

    def get_trust_score(self, entity_did: str) -> float:
        """Get the current trust score for an entity."""
        profile = self._profiles.get(entity_did)
        if profile:
            return profile.score
        return 0.0

    def get_profile(self, entity_did: str) -> Optional[TrustProfile]:
        """Get the full trust profile for an entity."""
        return self._profiles.get(entity_did)

    def generate_report(self, entity_did: str) -> Optional[AttestationReport]:
        """Generate an attestation report for an entity."""
        profile = self._profiles.get(entity_did)
        if not profile:
            return None

        records = self._behavior_log.get(entity_did, [])

        # Count action types
        action_counts: dict[str, int] = defaultdict(int)
        for r in records:
            action_counts[r.action] += 1

        report = AttestationReport(
            entity_did=entity_did,
            trust_score=profile.score,
            total_actions=profile.total_actions,
            anomalies_detected=profile.anomalies,
            behavior_summary={
                "action_counts": dict(action_counts),
                "declared_capabilities": profile.declared_capabilities,
                "observed_actions": profile.observed_actions,
                "anomaly_rate": profile.anomalies / max(1, profile.total_actions),
            },
            generated_at=time.time(),
        )

        return report

    def get_anomaly_feed(self, limit: int = 50) -> list[dict]:
        """Get recent anomaly events."""
        return self._anomaly_feed[-limit:]

    def get_events(self, limit: int = 50) -> list[dict]:
        """Get recent attestation events."""
        return self._events[-limit:]

    def list_profiles(self) -> list[TrustProfile]:
        """List all trust profiles."""
        return list(self._profiles.values())
