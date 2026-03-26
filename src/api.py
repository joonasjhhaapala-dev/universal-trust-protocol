"""
UTP REST API
FastAPI routes for the Universal Trust Protocol.
"""

import os
import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .identity import IdentityManager
from .capabilities import CapabilityManager
from .attestation import AttestationManager
from .revocation import RevocationRegistry, RevocationReason
from .registry import EntityRegistry


# --- Pydantic models for request/response ---

class RegisterRequest(BaseModel):
    entity_type: str  # "agent", "human", "org"
    name: str
    description: str = ""
    capabilities: list[str] = []
    controller: Optional[str] = None
    metadata: dict = {}


class RegisterResponse(BaseModel):
    did: str
    name: str
    entity_type: str
    public_key: str
    status: str
    trust_score: float


class CapabilityGrantRequest(BaseModel):
    issuer_did: str
    subject_did: str
    action: str
    resource: str
    constraints: dict = {}
    expires_in: float = 3600
    delegatable: bool = False


class CapabilityGrantResponse(BaseModel):
    token_id: str
    issuer: str
    subject: str
    action: str
    resource: str
    expires_at: float


class CapabilityVerifyRequest(BaseModel):
    token_id: str
    action: str
    resource: str


class CapabilityVerifyResponse(BaseModel):
    valid: bool
    reason: str


class AttestRequest(BaseModel):
    entity_did: str
    action: str
    resource: str
    details: dict = {}


class AttestResponse(BaseModel):
    anomaly: bool
    reason: str
    trust_score: float


class RevokeRequest(BaseModel):
    credential_id: str
    credential_type: str = "did"  # "did" or "capability"
    revoked_by: str
    reason: str = "manual"


class RevokeResponse(BaseModel):
    credential_id: str
    revoked: bool
    reason: str
    timestamp: float


class TrustResponse(BaseModel):
    did: str
    trust_score: float
    total_actions: int
    anomalies: int


class DIDResponse(BaseModel):
    did: str
    entity_type: str
    public_key: str
    capabilities: list[str]
    constraints: dict
    controller: Optional[str]
    status: str
    created: float
    expires: float


# --- Shared state (initialized by main.py) ---

class UTPState:
    """Shared state for all UTP components."""

    def __init__(self):
        self.identity = IdentityManager()
        self.capabilities = CapabilityManager()
        self.attestation = AttestationManager()
        self.revocation = RevocationRegistry()
        self.registry = EntityRegistry()


# Global state instance
state = UTPState()


def get_state() -> UTPState:
    return state


# --- Router ---

router = APIRouter()


@router.post("/register", response_model=RegisterResponse)
async def register_entity(req: RegisterRequest):
    """Register a new entity (agent, human, or organization)."""
    try:
        doc, signing_key = state.identity.create_identity(
            entity_type=req.entity_type,
            capabilities=req.capabilities,
            controller=req.controller,
            metadata=req.metadata,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Register in entity registry
    state.registry.register(
        did=doc.did,
        entity_type=req.entity_type,
        name=req.name,
        description=req.description,
        capabilities=req.capabilities,
        controller=req.controller,
        metadata=req.metadata,
    )

    # Register for attestation monitoring
    state.attestation.register_entity(doc.did, req.capabilities)

    return RegisterResponse(
        did=doc.did,
        name=req.name,
        entity_type=req.entity_type,
        public_key=doc.public_key,
        status=doc.status,
        trust_score=1.0,
    )


@router.get("/resolve/{did}", response_model=DIDResponse)
async def resolve_did(did: str):
    """Resolve a DID to its document."""
    doc = state.identity.resolve(did)
    if not doc:
        raise HTTPException(status_code=404, detail=f"DID not found: {did}")

    return DIDResponse(
        did=doc.did,
        entity_type=doc.entity_type,
        public_key=doc.public_key,
        capabilities=doc.capabilities,
        constraints=doc.constraints,
        controller=doc.controller,
        status=doc.status,
        created=doc.created,
        expires=doc.expires,
    )


@router.post("/capability/grant", response_model=CapabilityGrantResponse)
async def grant_capability(req: CapabilityGrantRequest):
    """Grant a capability token from issuer to subject."""
    signing_key = state.identity.get_signing_key(req.issuer_did)
    if not signing_key:
        raise HTTPException(status_code=404, detail=f"Issuer DID not found: {req.issuer_did}")

    subject_doc = state.identity.resolve(req.subject_did)
    if not subject_doc:
        raise HTTPException(status_code=404, detail=f"Subject DID not found: {req.subject_did}")

    grant = state.capabilities.grant(
        issuer_did=req.issuer_did,
        subject_did=req.subject_did,
        action=req.action,
        resource=req.resource,
        signing_key=signing_key,
        constraints=req.constraints,
        expires_in=req.expires_in,
        delegatable=req.delegatable,
    )

    return CapabilityGrantResponse(
        token_id=grant.token_id,
        issuer=grant.issuer,
        subject=grant.subject,
        action=grant.action,
        resource=grant.resource,
        expires_at=grant.expires_at,
    )


@router.post("/capability/verify", response_model=CapabilityVerifyResponse)
async def verify_capability(req: CapabilityVerifyRequest):
    """Verify a capability token."""
    grant = state.capabilities.get_grant(req.token_id)
    if not grant:
        return CapabilityVerifyResponse(valid=False, reason="Token not found")

    # Check if the capability token itself is revoked in the revocation registry
    if state.revocation.is_revoked(req.token_id):
        return CapabilityVerifyResponse(valid=False, reason="Token has been revoked")

    # Check if the issuer's DID has been revoked
    if state.revocation.is_revoked(grant.issuer):
        return CapabilityVerifyResponse(valid=False, reason="Issuer DID has been revoked")

    verify_key = state.identity.get_verify_key(grant.issuer)
    if not verify_key:
        return CapabilityVerifyResponse(valid=False, reason="Issuer public key not found")

    valid, reason = state.capabilities.verify(
        token_id=req.token_id,
        action=req.action,
        resource=req.resource,
        verify_key=verify_key,
    )

    return CapabilityVerifyResponse(valid=valid, reason=reason)


@router.post("/attest", response_model=AttestResponse)
async def submit_attestation(req: AttestRequest):
    """Submit a behavioral attestation for an entity."""
    is_anomaly, reason = state.attestation.record_behavior(
        entity_did=req.entity_did,
        action=req.action,
        resource=req.resource,
        details=req.details,
    )

    trust_score = state.attestation.get_trust_score(req.entity_did)

    # Sync trust score to registry
    state.registry.update_trust_score(req.entity_did, trust_score)

    return AttestResponse(
        anomaly=is_anomaly,
        reason=reason,
        trust_score=trust_score,
    )


@router.post("/revoke", response_model=RevokeResponse)
async def revoke_credential(req: RevokeRequest):
    """Revoke a credential (DID or capability token)."""
    entry = state.revocation.revoke(
        credential_id=req.credential_id,
        credential_type=req.credential_type,
        revoked_by=req.revoked_by,
        reason=req.reason,
    )

    # If revoking a DID, update its status everywhere
    if req.credential_type == "did":
        state.identity.update_status(req.credential_id, "revoked")
        state.registry.update_status(req.credential_id, "revoked", reason=req.reason)

    # If revoking a capability, mark it revoked
    if req.credential_type == "capability":
        state.capabilities.revoke(req.credential_id)

    return RevokeResponse(
        credential_id=entry.credential_id,
        revoked=True,
        reason=entry.reason,
        timestamp=entry.timestamp,
    )


@router.get("/trust/{did}", response_model=TrustResponse)
async def get_trust_score(did: str):
    """Get the trust score for an entity."""
    profile = state.attestation.get_profile(did)
    if not profile:
        raise HTTPException(status_code=404, detail=f"No trust profile for: {did}")

    return TrustResponse(
        did=did,
        trust_score=profile.score,
        total_actions=profile.total_actions,
        anomalies=profile.anomalies,
    )


@router.get("/entities")
async def list_entities():
    """List all registered entities."""
    entities = state.registry.list_all()
    return [e.to_dict() for e in entities]


@router.get("/events")
async def get_events():
    """Get recent events from all subsystems."""
    cap_events = state.capabilities.get_events(20)
    att_events = state.attestation.get_events(20)
    rev_events = state.revocation.get_events(20)
    reg_events = state.registry.get_events(20)

    all_events = cap_events + att_events + rev_events + reg_events
    all_events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    return all_events[:50]


@router.get("/stats")
async def get_stats():
    """Get system statistics."""
    return {
        "entities": state.registry.count(),
        "capabilities_granted": len(state.capabilities.list_all()),
        "revocations": state.revocation.get_revocation_count(),
        "anomalies": len(state.attestation.get_anomaly_feed()),
        "merkle_root": state.revocation.get_merkle_root(),
    }


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the HTML dashboard."""
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(dashboard_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
