"""
Shared fixtures for UTP tests.
"""

import pytest

from src.identity import IdentityManager
from src.capabilities import CapabilityManager
from src.attestation import AttestationManager
from src.revocation import RevocationRegistry
from src.registry import EntityRegistry
from src import crypto_utils


@pytest.fixture
def identity_manager() -> IdentityManager:
    """Fresh IdentityManager for each test."""
    return IdentityManager()


@pytest.fixture
def capability_manager() -> CapabilityManager:
    """Fresh CapabilityManager for each test."""
    return CapabilityManager()


@pytest.fixture
def attestation_manager() -> AttestationManager:
    """Fresh AttestationManager for each test."""
    return AttestationManager()


@pytest.fixture
def revocation_registry() -> RevocationRegistry:
    """Fresh RevocationRegistry for each test."""
    return RevocationRegistry()


@pytest.fixture
def entity_registry() -> EntityRegistry:
    """Fresh EntityRegistry for each test."""
    return EntityRegistry()


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair."""
    return crypto_utils.generate_keypair()


@pytest.fixture
def agent_identity(identity_manager: IdentityManager):
    """Create an agent identity and return (doc, signing_key)."""
    return identity_manager.create_identity(
        entity_type="agent",
        capabilities=["shopping"],
        metadata={"name": "TestAgent"},
    )


@pytest.fixture
def human_identity(identity_manager: IdentityManager):
    """Create a human identity and return (doc, signing_key)."""
    return identity_manager.create_identity(
        entity_type="human",
        metadata={"name": "TestHuman"},
    )
