# Universal Trust Protocol (UTP)

**Cryptographic trust infrastructure for AI agents.**

[![CI](https://github.com/joonas/utp/actions/workflows/ci.yml/badge.svg)](https://github.com/joonas/utp/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What is UTP?

The Universal Trust Protocol is a framework that provides cryptographic identity, scoped authorization, behavioral monitoring, and instant revocation for AI agents. It answers a fundamental question in multi-agent systems: **how do you trust an autonomous agent with real-world actions?** UTP solves this with Ed25519-signed decentralized identifiers (DIDs), time-limited capability tokens with delegation chains, behavioral attestation that detects anomalies in real time, and an instant revocation registry that can disable a compromised agent in milliseconds.

## Features

- **Decentralized Identity (DID)** -- Ed25519 keypairs with self-signed DID documents for agents, humans, and organizations
- **Capability-based Authorization** -- Time-limited, action-scoped, delegatable tokens with cryptographic signatures
- **Behavioral Attestation** -- Anomaly detection against declared capabilities with evolving trust scores
- **Instant Revocation** -- Credential revocation with Merkle root integrity and verifier propagation
- **REST API** -- Full FastAPI server with OpenAPI docs
- **Dashboard** -- Real-time web dashboard for monitoring entities, capabilities, and anomalies

## Architecture

```
+------------------------------------------------------------------+
|                    Universal Trust Protocol                       |
+------------------------------------------------------------------+
|                                                                  |
|  1. IDENTITY LAYER                                               |
|  +------------------------------------------------------------+  |
|  |  Ed25519 Keypairs  ->  DID Documents  ->  Self-Signatures  |  |
|  |  did:agent:a1b2... | did:human:c3d4... | did:org:e5f6...   |  |
|  +------------------------------------------------------------+  |
|                              |                                   |
|  2. AUTHORIZATION LAYER      v                                   |
|  +------------------------------------------------------------+  |
|  |  Capability Tokens (signed, scoped, time-limited)           |  |
|  |  [issuer] --grant--> [subject]: action on resource          |  |
|  |  Delegation chains with scope reduction                     |  |
|  +------------------------------------------------------------+  |
|                              |                                   |
|  3. ATTESTATION LAYER        v                                   |
|  +------------------------------------------------------------+  |
|  |  Behavior Monitoring  ->  Anomaly Detection                 |  |
|  |  Declared capabilities vs. observed actions                 |  |
|  |  Trust scores: 0.0 (untrusted) to 1.0 (fully trusted)      |  |
|  +------------------------------------------------------------+  |
|                              |                                   |
|  4. REVOCATION LAYER         v                                   |
|  +------------------------------------------------------------+  |
|  |  Revocation Registry  ->  Merkle Root  ->  Propagation      |  |
|  |  Instant credential invalidation, verifier notification     |  |
|  +------------------------------------------------------------+  |
|                                                                  |
+------------------------------------------------------------------+
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/joonas/utp.git
cd utp

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
python -m pip install -r requirements.txt

# Run the server (seeds demo data automatically)
python src/main.py
```

Then open:
- **Dashboard**: http://localhost:8002/dashboard
- **API docs**: http://localhost:8002/docs

To run the interactive CLI demo instead:

```bash
python src/demo.py
```

## Running Tests

```bash
# Install test dependencies
python -m pip install pytest httpx

# Run all tests
python -m pytest tests/ -v
```

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Register a new entity (agent, human, or org) |
| `GET` | `/resolve/{did}` | Resolve a DID to its document |
| `POST` | `/capability/grant` | Grant a scoped capability token |
| `POST` | `/capability/verify` | Verify a capability token against action and resource |
| `POST` | `/attest` | Submit behavioral attestation for anomaly detection |
| `POST` | `/revoke` | Revoke a credential (DID or capability token) |
| `GET` | `/trust/{did}` | Get the current trust score for an entity |
| `GET` | `/entities` | List all registered entities |
| `GET` | `/events` | Get recent events from all subsystems |
| `GET` | `/stats` | Get system statistics and Merkle root |
| `GET` | `/dashboard` | HTML dashboard |

## How the Cryptography Works

UTP uses **Ed25519** (via PyNaCl/libsodium) for all cryptographic operations:

1. **Key Generation** -- Each entity gets an Ed25519 signing/verification keypair. The public key is encoded in base64 and embedded in the DID document.

2. **DID Creation** -- A DID is derived by hashing the public key with SHA-256 and taking the first 16 hex characters as a fingerprint: `did:<type>:<fingerprint>`.

3. **Document Signing** -- DID documents are self-signed: the document contents (excluding the signature field) are JSON-canonicalized, signed with the entity's private key, and the base64-encoded signature is stored in the document.

4. **Capability Tokens** -- Capability tokens contain the issuer DID, subject DID, action, resource, constraints, expiry, and delegation chain. The entire payload is signed by the issuer's private key. Verification checks the signature, expiry, and scope match.

5. **Revocation** -- The revocation registry computes a hash chain (Merkle-like root) over all revoked credentials, providing tamper-evident integrity suitable for future on-chain anchoring.

## DID Document Example

```json
{
  "did": "did:agent:a1b2c3d4e5f60a8b",
  "entity_type": "agent",
  "public_key": "base64-encoded-ed25519-public-key",
  "capabilities": ["shopping"],
  "constraints": {},
  "controller": "did:human:c3d4e5f6a1b2c3d0",
  "created": 1711468800.0,
  "expires": 1743004800.0,
  "status": "active",
  "metadata": {"name": "GroceryBot"},
  "signature": "base64-encoded-ed25519-signature"
}
```

## Capability Token Example

```json
{
  "payload": {
    "iss": "did:human:alice1234abcd",
    "sub": "did:agent:bot5678efgh",
    "action": "spend",
    "resource": "groceries",
    "constraints": {"max_amount": 500, "currency": "EUR"},
    "iat": 1711468800.0,
    "exp": 1711472400.0,
    "delegation_chain": [],
    "jti": "a1b2c3d4e5f60a8b"
  },
  "signature": "base64-encoded-ed25519-signature",
  "token_id": "a1b2c3d4e5f60a8b"
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
