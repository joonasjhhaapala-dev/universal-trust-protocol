"""
UTP Decentralized Identity (DID) System
Generate, sign, verify, and resolve DID documents for agents, humans, and organizations.
"""

import time
from typing import Optional
from dataclasses import dataclass, field, asdict

from nacl.signing import SigningKey, VerifyKey

from . import crypto_utils


@dataclass
class DIDDocument:
    did: str
    entity_type: str  # "agent", "human", "org"
    public_key: str  # base64-encoded Ed25519 public key
    capabilities: list[str] = field(default_factory=list)
    constraints: dict = field(default_factory=dict)
    controller: Optional[str] = None  # DID of the controlling entity
    created: float = 0.0
    expires: float = 0.0
    status: str = "active"  # active, suspended, revoked
    metadata: dict = field(default_factory=dict)
    signature: Optional[str] = None  # Signature over the document by the controller or self

    def to_dict(self) -> dict:
        return asdict(self)

    def signable_dict(self) -> dict:
        """Return dict without signature for signing purposes."""
        d = self.to_dict()
        d.pop("signature", None)
        return d


class IdentityManager:
    """Manages DID creation, resolution, signing, and verification."""

    def __init__(self):
        # DID -> DIDDocument
        self._documents: dict[str, DIDDocument] = {}
        # DID -> SigningKey (stored for demo purposes; in production, keys stay with the owner)
        self._signing_keys: dict[str, SigningKey] = {}

    def create_identity(
        self,
        entity_type: str,
        capabilities: Optional[list[str]] = None,
        constraints: Optional[dict] = None,
        controller: Optional[str] = None,
        expires_in: float = 86400 * 365,  # 1 year default
        metadata: Optional[dict] = None,
    ) -> tuple[DIDDocument, SigningKey]:
        """
        Create a new DID identity.
        Returns the DID document and the signing key.
        """
        if entity_type not in ("agent", "human", "org"):
            raise ValueError(f"Invalid entity type: {entity_type}. Must be agent, human, or org.")

        signing_key, verify_key = crypto_utils.generate_keypair()
        did = crypto_utils.generate_did(entity_type, verify_key)

        now = time.time()
        doc = DIDDocument(
            did=did,
            entity_type=entity_type,
            public_key=crypto_utils.public_key_to_b64(verify_key),
            capabilities=capabilities or [],
            constraints=constraints or {},
            controller=controller,
            created=now,
            expires=now + expires_in,
            status="active",
            metadata=metadata or {},
        )

        # Self-sign the document
        doc.signature = crypto_utils.sign_json(doc.signable_dict(), signing_key)

        self._documents[did] = doc
        self._signing_keys[did] = signing_key

        return doc, signing_key

    def resolve(self, did: str) -> Optional[DIDDocument]:
        """Resolve a DID to its document."""
        return self._documents.get(did)

    def verify_document(self, doc: DIDDocument) -> tuple[bool, str]:
        """Verify the signature on a DID document."""
        if not doc.signature:
            return False, "No signature present"

        try:
            verify_key = crypto_utils.b64_to_verify_key(doc.public_key)
            valid = crypto_utils.verify_json(doc.signable_dict(), doc.signature, verify_key)
            if valid:
                return True, "Valid signature"
            else:
                return False, "Invalid signature"
        except Exception as e:
            return False, f"Verification error: {e}"

    def update_status(self, did: str, status: str) -> bool:
        """Update the status of a DID document."""
        doc = self._documents.get(did)
        if not doc:
            return False
        doc.status = status
        # Re-sign with stored key
        signing_key = self._signing_keys.get(did)
        if signing_key:
            doc.signature = crypto_utils.sign_json(doc.signable_dict(), signing_key)
        return True

    def get_signing_key(self, did: str) -> Optional[SigningKey]:
        """Get the signing key for a DID (demo only)."""
        return self._signing_keys.get(did)

    def get_verify_key(self, did: str) -> Optional[VerifyKey]:
        """Get the verify key for a DID."""
        doc = self._documents.get(did)
        if doc:
            return crypto_utils.b64_to_verify_key(doc.public_key)
        return None

    def list_all(self) -> list[DIDDocument]:
        """List all DID documents."""
        return list(self._documents.values())

    def search(
        self,
        entity_type: Optional[str] = None,
        capability: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[DIDDocument]:
        """Search DID documents by criteria."""
        results = list(self._documents.values())
        if entity_type:
            results = [d for d in results if d.entity_type == entity_type]
        if capability:
            results = [d for d in results if capability in d.capabilities]
        if status:
            results = [d for d in results if d.status == status]
        return results
