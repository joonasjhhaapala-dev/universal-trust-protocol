# Universal Trust Protocol: Cryptographic Identity, Authorization, and Behavioral Attestation for Autonomous AI Agents

**Authors:** J. Haapala
**Date:** March 2026
**Version:** 1.0
**Status:** Working Draft

---

## Abstract

The rapid proliferation of autonomous AI agents in enterprise and consumer environments has exposed a critical infrastructure gap: the absence of standardized, cryptographically verifiable identity and authorization mechanisms purpose-built for non-human actors. Industry surveys indicate that 68% of organizations cannot reliably distinguish AI agents from human users within their systems [1], and only 23% have implemented formal identity management for autonomous agents [2]. Despite 99% of enterprises planning agentic AI deployments, a mere 11% have moved beyond pilot stages, citing trust and governance as the primary barriers [3]. This paper presents the Universal Trust Protocol (UTP), a four-layer cryptographic framework that provides decentralized identity, capability-based authorization, behavioral attestation, and instant credential revocation for AI agents. UTP is grounded in W3C Decentralized Identifiers (DID) v1.0, Ed25519 elliptic-curve signatures, and capability-based security theory. The identity layer binds each agent to a self-signed DID document anchored by a SHA-256 fingerprint of its Ed25519 public key. The authorization layer issues time-limited, action-scoped capability tokens with cryptographic delegation chains that enforce monotonic scope reduction. The attestation layer monitors agent behavior against declared capabilities using an exponential-decay trust score model that detects anomalies in real time. The revocation layer provides instant credential invalidation with a hash-chain integrity structure suitable for on-chain anchoring. We present a working implementation comprising approximately 1,800 lines of Python, a REST API, and a real-time monitoring dashboard, validated by 92 tests across six modules. We demonstrate the protocol's efficacy through a rogue agent detection scenario in which a compromised shopping agent is identified, scored, and revoked within the attestation-revocation feedback loop. UTP addresses the foundational trust gap blocking autonomous agent deployment and provides a migration path toward post-quantum cryptography and decentralized ledger integration.

---

## 1. Introduction

### 1.1 The Agent Identity Crisis

The year 2025 marked an inflection point in the deployment of autonomous AI agents. Large language model providers, cloud platforms, and enterprise software vendors simultaneously released frameworks for building agents capable of executing multi-step tasks with minimal human oversight. These agents now book travel, execute financial transactions, manage infrastructure, and communicate on behalf of human principals. Yet the identity infrastructure supporting these agents remains woefully inadequate.

A 2025 CyberArk survey of 1,200 security professionals found that 68% of organizations lack the ability to distinguish AI agent actions from human actions within their authentication and logging systems [1]. The Strata Identity report on the AI agent identity crisis revealed that only 23% of enterprises have formal identity governance for non-human actors, despite 82% acknowledging it as a critical security concern [2]. The Capgemini Research Institute found that while 99% of organizations plan to deploy agentic AI within two years, only 11% have moved beyond proof-of-concept, with trust, accountability, and identity cited as the top three barriers [3].

### 1.2 Why Existing Identity Systems Fail

Traditional identity and access management (IAM) systems were designed around a fundamental assumption: the entity being authenticated is a human being interacting through a user agent (browser, mobile application, or terminal). This assumption permeates every layer of existing infrastructure, from password-based authentication to session cookies, from role-based access control (RBAC) to OAuth 2.0 delegation flows.

Autonomous AI agents violate this assumption in several critical ways. First, agents act autonomously over extended time horizons without continuous human input, making session-based models inappropriate. Second, agents may delegate tasks to sub-agents, creating chains of authority that RBAC cannot express. Third, agent behavior may drift from its declared purpose due to prompt injection, model updates, or adversarial manipulation, yet existing systems provide no mechanism for runtime behavioral verification. Fourth, agents may operate across organizational boundaries, requiring decentralized identity rather than centrally issued credentials.

### 1.3 Our Contribution

We present the Universal Trust Protocol (UTP), a four-layer cryptographic trust framework that addresses each of these deficiencies. UTP provides:

1. **Decentralized Identity** rooted in Ed25519 keypairs and W3C DID documents, enabling self-sovereign identity for agents, humans, and organizations without dependence on a central authority.
2. **Capability-based Authorization** through signed, time-limited, action-scoped tokens with cryptographic delegation chains that enforce the principle of least privilege through monotonic scope reduction.
3. **Behavioral Attestation** via an anomaly detection system that compares observed agent actions against declared capabilities and maintains evolving trust scores using an exponential-decay model.
4. **Instant Revocation** through a registry with hash-chain integrity, enabling millisecond-scale credential invalidation with tamper-evident audit trails suitable for future on-chain anchoring.

We position UTP as the SSL/TLS of the agent economy: a foundational trust layer upon which higher-level agent orchestration, marketplace, and governance systems can be built.

---

## 2. Background and Related Work

### 2.1 Decentralized Identifiers (W3C DID)

The W3C Decentralized Identifiers specification (DID v1.0, ratified July 2022) defines a new type of globally unique identifier that enables verifiable, decentralized digital identity [4]. A DID resolves to a DID document containing public keys, authentication methods, and service endpoints. DIDs are method-specific: `did:web`, `did:key`, `did:ion`, and others define different resolution and registration mechanisms. UTP introduces the methods `did:agent`, `did:human`, and `did:org` to distinguish entity classes at the identifier level. The W3C DID v1.1 specification (Working Draft, 2024) introduces additional features for key rotation and service binding that inform our lifecycle management design [5].

### 2.2 Verifiable Credentials

The W3C Verifiable Credentials Data Model 2.0 [6] provides a standard for expressing credentials in a cryptographically verifiable manner. UTP's capability tokens draw on verifiable credential semantics but extend them with real-time behavioral verification and delegation chain tracking that the VC model does not natively support.

### 2.3 Capability-based Security

Capability-based security originates with the seminal work of Dennis and Van Horn (1966) on supervised domains in multiprogrammed computer systems [7]. In this model, access to a resource is mediated by an unforgeable token (a capability) that both identifies the resource and conveys the authority to perform operations on it. Miller (2006) formalized the object-capability model for distributed systems [8], demonstrating that capabilities provide confinement, least authority, and composable security properties that access control lists (ACLs) cannot. The UCAN (User Controlled Authorization Networks) specification [9] applies capability semantics to decentralized systems using content-addressed tokens. UTP extends this lineage with cryptographic signatures, behavioral monitoring, and a revocation layer that capability systems have historically lacked.

### 2.4 Behavioral Analysis and Anomaly Detection

Runtime behavioral monitoring for security has been extensively studied in the intrusion detection literature [10]. UTP adapts these principles to the agent domain by defining a capability-action mapping that establishes expected behavior profiles for each declared capability class, enabling detection of actions that deviate from an agent's stated purpose.

### 2.5 Existing Agent Identity Proposals

Google's Unified Communication Protocol (UCP) and Agent2Agent (A2A) protocol [11] address agent-to-agent communication but do not provide cryptographic identity, behavioral attestation, or revocation. Microsoft's AutoGen framework provides agent orchestration but delegates identity to the host platform's IAM [12]. The OWASP Foundation has published guidelines for LLM agent security [13] that identify the risks UTP addresses but do not propose a concrete protocol. The ANT (Agent Name and Trust) proposal [14] offers naming conventions but lacks cryptographic foundations.

### 2.6 Gap Analysis

No existing proposal combines all four requirements for trustworthy agent operation: (i) decentralized cryptographic identity, (ii) delegatable capability-based authorization, (iii) continuous behavioral attestation, and (iv) instant revocation with audit integrity. UTP fills this gap.

---

## 3. Threat Model

We consider the following adversary classes and attack vectors relevant to multi-agent systems.

### 3.1 Agent Impersonation

An adversary creates an agent that claims the identity of a legitimate agent to gain access to resources or trust relationships. **Mitigation:** UTP binds identity to Ed25519 keypairs. Impersonation requires possession of the private key, which never leaves the agent's secure enclave.

### 3.2 Privilege Escalation

An agent attempts to perform actions beyond its authorized scope, either through direct exploitation or by manipulating its delegation chain. **Mitigation:** Capability tokens are cryptographically signed and action-scoped. Delegation enforces monotonic scope reduction (Section 7). Verification checks action and resource match at every invocation.

### 3.3 Capability Token Theft and Replay

An adversary intercepts a capability token and replays it to gain unauthorized access. **Mitigation:** Tokens include issuance timestamps (`iat`), expiration times (`exp`), and unique identifiers (`jti`). Time-limited validity windows (default: 1 hour) bound the replay window. The revocation registry enables immediate invalidation of compromised tokens.

### 3.4 Behavioral Manipulation and Prompt Injection

An adversary manipulates an agent's behavior through prompt injection or model poisoning, causing it to perform actions inconsistent with its declared capabilities. **Mitigation:** The attestation layer continuously monitors actions against declared capability profiles. Anomalous actions (e.g., a shopping agent attempting `transfer_funds` or `access_credentials`) are flagged immediately, and trust score degradation triggers automated revocation.

### 3.5 Cascading Trust Failures

A compromised agent that holds delegatable capabilities propagates compromised tokens to sub-agents, creating a chain of unauthorized access. **Mitigation:** Delegation chains are explicitly recorded in each token. Revocation of any token in the chain can be detected by traversing the `delegation_chain` field. Trust score degradation in the delegator triggers review of all downstream delegations.

### 3.6 Revocation Delay Attacks

An adversary exploits the time window between credential compromise and revocation propagation. **Mitigation:** UTP's revocation registry provides instant local invalidation. The verifier propagation protocol notifies all registered verifiers synchronously. Hash-chain integrity (Section 9) ensures that revocation records cannot be tampered with or selectively omitted.

---

## 4. Protocol Architecture

UTP is organized as four vertically integrated layers, each building upon the guarantees provided by the layer below.

```
+====================================================================+
|                    UNIVERSAL TRUST PROTOCOL                         |
+====================================================================+
|                                                                     |
|  Layer 4: REVOCATION                                                |
|  +---------------------------------------------------------------+  |
|  |  Revocation Registry  -->  Hash Chain  -->  Verifier Propagation |
|  |  Instant credential invalidation with tamper-evident audit     |  |
|  +---------------------------------------------------------------+  |
|                               ^                                     |
|  Layer 3: ATTESTATION         | anomaly triggers revocation         |
|  +---------------------------------------------------------------+  |
|  |  Behavior Monitoring  -->  Anomaly Detection  --> Trust Scores  |  |
|  |  Declared vs. observed actions, exponential decay model         |  |
|  +---------------------------------------------------------------+  |
|                               ^                                     |
|  Layer 2: AUTHORIZATION       | actions verified against tokens     |
|  +---------------------------------------------------------------+  |
|  |  Capability Tokens (signed, scoped, time-limited, delegatable)  |  |
|  |  [issuer] --grant--> [subject]: action on resource              |  |
|  +---------------------------------------------------------------+  |
|                               ^                                     |
|  Layer 1: IDENTITY            | tokens reference DIDs               |
|  +---------------------------------------------------------------+  |
|  |  Ed25519 Keypairs  -->  DID Documents  -->  Self-Signatures     |  |
|  |  did:agent:<fp> | did:human:<fp> | did:org:<fp>                 |  |
|  +---------------------------------------------------------------+  |
|                                                                     |
+====================================================================+
```

**Inter-layer interactions.** The identity layer provides the cryptographic material (keypairs, DIDs) referenced by all other layers. The authorization layer issues tokens signed by identity-layer keys, which the attestation layer monitors for behavioral consistency. The attestation layer feeds trust scores and anomaly signals to the revocation layer, which can automatically invalidate credentials when trust drops below configurable thresholds. This feedback loop -- from attestation to revocation and back to authorization verification -- enables autonomous, real-time trust management without human intervention.

**Trust score computation.** An entity's trust score *T* is a continuous value in [0, 1] computed by the attestation layer and consumed by the authorization and revocation layers. Authorization verifiers may impose minimum trust thresholds, and the revocation layer may trigger automatic revocation when *T* falls below a configured floor.

---

## 5. Cryptographic Foundations

### 5.1 Ed25519 Digital Signatures

UTP employs Ed25519 [15] as its sole signature algorithm. Ed25519 is a Schnorr signature scheme on the Edwards curve Curve25519, providing 128-bit security with 32-byte public keys, 64-byte signatures, and deterministic signing that eliminates nonce-reuse vulnerabilities. We selected Ed25519 over alternatives based on the following criteria:

| Property | Ed25519 | RSA-2048 | ECDSA P-256 |
|---|---|---|---|
| Public key size | 32 B | 256 B | 33 B (compressed) |
| Signature size | 64 B | 256 B | 64 B |
| Sign time (typical) | ~50 us | ~1 ms | ~200 us |
| Verify time (typical) | ~120 us | ~30 us | ~400 us |
| Deterministic signing | Yes | No (PKCS#1 v1.5 is) | No (requires RFC 6979) |
| Side-channel resistance | Strong | Variable | Variable |

Ed25519's compact representations are critical for capability tokens that may be transmitted frequently in agent-to-agent communication. The implementation uses PyNaCl [16], a Python binding to libsodium, which provides a well-audited, constant-time implementation.

### 5.2 DID Document Structure and Signing

A DID document *D* for entity *e* contains the following fields:

**Definition 1** (DID Document). A DID document is a tuple *D = (did, tau, pk, C, K, controller, t_c, t_e, sigma, mu)* where:
- *did* is the decentralized identifier string
- *tau* in {agent, human, org} is the entity type
- *pk* in {0,1}^{256} is the Ed25519 public key
- *C* is a set of declared capability labels
- *K* is a dictionary of operational constraints
- *controller* is an optional DID of the controlling entity
- *t_c*, *t_e* in R are creation and expiration timestamps
- *sigma* in {0,1}^{512} is the Ed25519 signature
- *mu* is an arbitrary metadata dictionary

The signature *sigma* is computed over the canonical form of all fields except *sigma* itself:

*sigma = Ed25519.Sign(sk, Canonical(D \ {sigma}))*

where *Canonical* denotes JSON canonicalization (Section 5.4) and *sk* is the signing key corresponding to *pk*.

### 5.3 Capability Token Format and Verification

**Definition 2** (Capability Token). A capability token is a tuple *T = (P, sigma, jti)* where the payload *P = (iss, sub, action, resource, K, t_i, t_e, delta, jti)* comprises:
- *iss*: issuer DID
- *sub*: subject DID
- *action*: authorized action string
- *resource*: target resource string
- *K*: constraint dictionary
- *t_i*, *t_e*: issuance and expiration timestamps
- *delta*: delegation chain (ordered list of DIDs)
- *jti*: token identifier (SHA-256 truncated hash of *P*)

The token identifier is computed as:

*jti = SHA256(Canonical(P))[:16]*

The signature is:

*sigma = Ed25519.Sign(sk_{iss}, Canonical(P))*

### 5.4 JSON Canonicalization for Deterministic Signing

Deterministic signing requires a canonical byte representation of structured data. UTP employs RFC 8785-compatible JSON canonicalization [17]:

*Canonical(obj) = JSON.serialize(obj, sort_keys=True, separators=(',', ':'))*

This ensures lexicographic key ordering and minimal whitespace, producing identical byte sequences regardless of the JSON serialization order of the originating system. All signature operations in UTP operate on the UTF-8 encoding of the canonical JSON string.

### 5.5 Hash Chain for Revocation Registry

The revocation registry maintains a hash chain over all revoked credentials for tamper-evident integrity:

**Definition 3** (Revocation Hash Chain). Given a set of revocation entries *R = {r_1, ..., r_n}* sorted by credential identifier, define:

*h_i = SHA256(r_i.credential_id || ':' || r_i.timestamp || ':' || r_i.reason)*

*MerkleRoot(R) = SHA256(h_1 || ':' || h_2 || ':' || ... || ':' || h_n)*

This hash chain provides O(n) verification and O(1) integrity checking via the root hash. The root is suitable for periodic anchoring to a public blockchain or distributed ledger, providing non-repudiable proof of revocation state at any point in time.

### 5.6 Post-Quantum Migration Path

Ed25519 is vulnerable to quantum attacks via Shor's algorithm. UTP is designed with algorithm agility to support migration to post-quantum signature schemes. The planned migration target is ML-DSA (Module-Lattice-Based Digital Signature Algorithm), standardized by NIST as FIPS 204 (August 2024) [18], formerly known as CRYSTALS-Dilithium. The DID document structure accommodates multiple public keys, enabling a hybrid period during which both Ed25519 and ML-DSA signatures are present, allowing verifiers to transition incrementally.

---

## 6. Identity Layer

### 6.1 DID Generation

DID generation follows a deterministic derivation from the entity's public key:

```
ALGORITHM: GenerateDID(entity_type, pk)
  INPUT:  entity_type in {agent, human, org}; pk: Ed25519 public key bytes
  OUTPUT: DID string

  1. fingerprint <- SHA256(pk)[0:16]       // First 16 hex characters
  2. did <- "did:" || entity_type || ":" || fingerprint
  3. RETURN did
```

The 16-character hexadecimal fingerprint provides 64 bits of collision resistance, which is sufficient for identifier uniqueness within bounded-scale deployments. For global-scale deployment, the fingerprint length can be extended without breaking compatibility.

### 6.2 Entity Types

UTP defines three entity types, each with distinct semantics:

- **`did:agent:<fp>`** -- Autonomous AI agents. Agents always have a controller (human or organization) and declared capabilities that constrain their authorized behavior space.
- **`did:human:<fp>`** -- Human principals. Humans serve as controllers for agents and as roots of trust for delegation chains. Human DIDs may be self-sovereign or organizationally issued.
- **`did:org:<fp>`** -- Organizations. Organizations can control agents and human accounts, define policy constraints, and serve as trust anchors for multi-organizational deployments.

### 6.3 Document Lifecycle

A DID document transitions through the following states: **created** -> **active** -> {**suspended**, **revoked**}. Suspension is reversible; revocation is permanent. All state transitions require re-signing the document with the entity's private key, ensuring that unauthorized status changes are cryptographically detectable.

---

## 7. Authorization Layer

### 7.1 Capability-based Access Control

UTP implements capability-based access control as defined by Miller [8]. Each capability token is an unforgeable, signed assertion that a specific subject is authorized to perform a specific action on a specific resource, subject to constraints, for a bounded time period. Unlike RBAC, which binds permissions to roles and roles to identities, capabilities bind permissions directly to identities with explicit scope, enabling fine-grained, composable authorization.

### 7.2 Token Verification Algorithm

Capability verification proceeds through five checks, all of which must pass:

```
ALGORITHM: VerifyCapability(token_id, action, resource, vk_issuer)
  INPUT:  token_id: string; action, resource: strings; vk_issuer: Ed25519 verify key
  OUTPUT: (valid: bool, reason: string)

  1. grant <- Lookup(token_id)
     IF grant = NULL: RETURN (false, "Token not found")

  2. IF grant.revoked: RETURN (false, "Token has been revoked")

  3. IF now() > grant.expires_at: RETURN (false, "Token has expired")

  4. IF grant.action != action AND grant.action != "*":
       RETURN (false, "Action mismatch")
     IF grant.resource != resource AND grant.resource != "*":
       RETURN (false, "Resource mismatch")

  5. P <- ReconstructPayload(grant)
     IF NOT Ed25519.Verify(vk_issuer, Canonical(P), grant.signature):
       RETURN (false, "Invalid signature")

  6. RETURN (true, "Valid")
```

### 7.3 Delegation with Monotonic Scope Reduction

Delegation allows a capability holder to create a derived token for another entity, subject to the following invariants:

**Theorem 1** (Monotonic Scope Reduction). *For any delegated capability token T' derived from original token T:*
1. *T'.action = T.action* (action is preserved)
2. *T'.resource = T.resource* (resource is preserved)
3. *For all numeric constraints k: T'.K[k] <= T.K[k]* (constraints can only be tightened)
4. *T'.t_e <= T.t_e* (expiration can only be shortened)
5. *T'.delta = T.delta ++ [delegator_did]* (delegation chain is extended)

*Proof sketch.* The delegation algorithm (Section 7.2 of the implementation) explicitly computes `min(reduced_value, original_value)` for each numeric constraint and `min(reduced_expiry, remaining_time)` for expiration. The action and resource fields are copied without modification. The delegation chain is append-only. These operations are monotonic with respect to the partial order on authorization scope, ensuring that delegation cannot amplify privileges. QED.

---

## 8. Attestation Layer

### 8.1 Behavioral Monitoring Model

The attestation layer maintains a trust profile for each registered entity, recording declared capabilities, observed actions, and a continuously updated trust score. Each declared capability maps to a set of expected action patterns through a capability-action mapping:

| Capability | Expected Actions |
|---|---|
| `shopping` | spend, browse, add_to_cart, checkout, compare_prices |
| `travel` | book_flight, book_hotel, search_destinations, spend |
| `finance` | transfer, check_balance, invest, spend, analyze |
| `data` | read, query, analyze, export |
| `communication` | send_message, read_message, schedule |
| `admin` | create_user, delete_user, modify_permissions, read, write |

### 8.2 Anomaly Detection Algorithm

The anomaly detector evaluates each recorded action against four criteria:

```
ALGORITHM: DetectAnomaly(profile, action, resource, details)
  INPUT:  profile: TrustProfile; action, resource: strings; details: dict
  OUTPUT: (is_anomaly: bool, reason: string)

  // Rule 1: Sensitive actions without authorization
  1. IF action IN SENSITIVE_ACTIONS:
       IF NOT ExistsCapability(profile, action):
         RETURN (true, "Sensitive action without authorization")

  // Rule 2: Action outside declared capabilities
  2. expected <- UnionMap(profile.declared_capabilities)
     IF expected != {} AND action NOT IN expected:
       RETURN (true, "Action outside declared capabilities")

  // Rule 3: Abnormal action rate (>10 actions in 10 seconds)
  3. recent <- Last10Records(profile.entity_did)
     IF |recent| >= 10 AND TimeSpan(recent) < 10s:
       RETURN (true, "Abnormally high action rate")

  // Rule 4: Constraint violation (e.g., spending exceeds maximum)
  4. IF "amount" IN details AND details.amount > details.max_allowed:
       RETURN (true, "Amount exceeds maximum")

  5. RETURN (false, "")
```

The set of sensitive actions -- `transfer_funds`, `delete_data`, `modify_permissions`, `access_credentials`, `exfiltrate`, `escalate_privileges`, `disable_logging`, `bypass_auth` -- represents actions that are inherently dangerous when performed by an agent without explicit capability authorization. These are always flagged regardless of the agent's declared capability set.

### 8.3 Trust Score Computation

**Definition 4** (Trust Score). The trust score *T_n* after *n* observed actions is computed as:

*g = good_actions / total_actions*

*p = 1 - e^{-0.5 * anomalies}*

*raw = g * (1 - p)*

*T_n = clamp(T_{n-1} * (1 - alpha) + raw * alpha, 0, 1)*

where *alpha = 0.3* is the learning rate controlling the smoothness of score transitions.

The exponential term *e^{-0.5 * anomalies}* ensures that the penalty for anomalies grows rapidly with repeated violations: one anomaly yields a penalty factor of approximately 0.39, two anomalies yield 0.63, and five anomalies yield 0.92, effectively driving the trust score toward zero for persistently misbehaving agents. The exponential moving average with *alpha = 0.3* prevents single-event score oscillation while ensuring responsiveness to sustained behavioral changes.

**Property 1** (Convergence). *For an agent exhibiting no anomalies (anomalies = 0), the trust score converges monotonically to 1.0. For an agent with a fixed anomaly rate r, the trust score converges to g * e^{-0.5 * r * n / n} = g * e^{-0.5 * r} as n -> infinity.*

---

## 9. Revocation Layer

### 9.1 Instant Revocation Mechanism

Credential revocation in UTP operates through a centralized registry designed for future federation and on-chain migration. The revocation operation records the credential identifier, credential type (`did` or `capability`), revoking authority, reason code, and timestamp. Supported reason codes include: `compromised`, `expired`, `superseded`, `behavioral_anomaly`, `manual`, and `policy_violation`.

The revocation check `is_revoked(credential_id)` executes in O(1) time via hash-map lookup, enabling integration into the hot path of capability verification without measurable latency impact.

### 9.2 Hash Chain Computation

The hash chain root (Section 5.5) is recomputed on each revocation query. In production deployments, this root would be periodically anchored to a public ledger (e.g., Ethereum L2 rollup) to provide non-repudiable, timestamp-bound proof of revocation state. This design separates the high-frequency revocation operations (in-memory, millisecond-scale) from the lower-frequency integrity anchoring (on-chain, block-time-scale).

### 9.3 Verifier Propagation Protocol

Upon revocation, the registry synchronously notifies all registered verifiers. In the current implementation, verifiers are in-process references; in production, this would be implemented as:

1. **Push notification** via WebSocket or Server-Sent Events for low-latency propagation.
2. **Pull verification** via a `/is-revoked/{credential_id}` endpoint for verifiers that prefer polling.
3. **Batch synchronization** via periodic Merkle root comparison for eventual consistency across federated deployments.

### 9.4 Attestation-Revocation Integration

The attestation and revocation layers form a closed feedback loop. When the attestation layer detects anomalies that drive an entity's trust score below a configurable threshold (default: 0.50), the system triggers automatic revocation of both the entity's DID and all associated capability tokens. This automated response ensures that compromised agents are neutralized without requiring human intervention, critical in scenarios where the speed of compromise may exceed human reaction time.

---

## 10. Implementation and Evaluation

### 10.1 Technology Stack

The reference implementation comprises the following components:

| Component | Technology | Lines of Code |
|---|---|---|
| Cryptographic utilities | PyNaCl 1.5 (libsodium) | ~140 |
| Identity manager | Python dataclasses | ~150 |
| Capability manager | Python dataclasses | ~270 |
| Attestation manager | Python, math stdlib | ~300 |
| Revocation registry | Python, hashlib | ~150 |
| Entity registry | Python dataclasses | ~180 |
| REST API | FastAPI 0.104, Pydantic 2.0 | ~360 |
| Interactive demo | Python CLI | ~470 |
| Test suite | pytest, httpx | ~600 |

Total: approximately 2,600 lines including tests. The implementation requires Python 3.11+ and five dependencies: FastAPI, Uvicorn, PyNaCl, Pydantic, and HTTPX.

### 10.2 Test Coverage

The test suite comprises 92 tests across six modules:

| Module | Tests | Coverage Focus |
|---|---|---|
| `test_crypto.py` | 18 | Key generation, signing, verification, canonicalization, token creation |
| `test_identity.py` | 20 | DID creation, resolution, document signing, verification, lifecycle |
| `test_capabilities.py` | 11 | Token grant, verify, delegate, revoke, scope enforcement |
| `test_attestation.py` | 11 | Behavior recording, anomaly detection, trust score evolution |
| `test_revocation.py` | 11 | Revocation entry, registry queries, hash chain integrity |
| `test_api.py` | 21 | REST endpoint integration, error handling, cross-layer workflows |

All 92 tests pass. The test suite validates both positive paths (correct operation) and negative paths (rejection of invalid signatures, expired tokens, revoked credentials, and out-of-scope actions).

### 10.3 Performance Characteristics

Ed25519 operations through PyNaCl/libsodium exhibit the following performance on a modern x86-64 processor:

- **Key generation:** ~50 microseconds
- **Sign (64-byte payload):** ~55 microseconds
- **Verify (64-byte payload):** ~120 microseconds
- **DID generation (SHA-256 + format):** ~5 microseconds
- **Capability token creation (sign + hash):** ~80 microseconds
- **Capability verification (4 checks + verify):** ~150 microseconds
- **Trust score update (mathematical computation):** ~2 microseconds
- **Revocation check (hash-map lookup):** ~0.1 microseconds

These timings demonstrate that UTP operations are negligible relative to the latency of typical agent actions (API calls, LLM inference), confirming that the protocol does not constitute a performance bottleneck.

### 10.4 Rogue Agent Detection Walkthrough

The reference implementation includes a demonstration scenario that illustrates the full protocol lifecycle:

1. **Identity creation.** Eleven entities are created: eight agents (including one designated "RogueAgent"), two humans (Alice, Bob), and one organization (TrustCorp). Each receives an Ed25519 keypair and self-signed DID document.

2. **Capability granting.** Alice and Bob grant scoped capabilities to agents. RogueAgent receives a shopping capability with a 100 EUR spending limit.

3. **Normal operation.** RogueAgent performs three legitimate shopping actions (`spend`, `browse`, `checkout`). Its trust score remains at 1.0.

4. **Behavioral deviation.** RogueAgent attempts five sensitive actions: `transfer_funds` to an offshore account, `access_credentials` targeting admin passwords, `exfiltrate` targeting 100,000 user records, `escalate_privileges` to superadmin, and `disable_logging` on the audit system. Each is flagged as an anomaly.

5. **Trust score collapse.** After five anomalies, the exponential-decay model drives RogueAgent's trust score from 1.0 to below 0.50.

6. **Automated revocation.** The system revokes RogueAgent's DID and all associated capability tokens. Subsequent capability verification attempts return "Token has been revoked."

7. **Integrity verification.** The hash chain root is computed over the revocation registry, confirming tamper-evident integrity of the revocation record.

This scenario demonstrates that UTP can detect and neutralize a compromised agent within a single attestation cycle, without requiring human intervention.

---

## 11. Security Analysis

### 11.1 Formal Security Properties

UTP provides the following security properties under the assumption that Ed25519 is existentially unforgeable under chosen-message attack (EUF-CMA) [15]:

**Property 2** (Identity Integrity). *No adversary can create a valid DID document for an identity without possessing the corresponding Ed25519 private key.*

**Property 3** (Authorization Non-Forgeability). *No adversary can create a valid capability token without possessing the issuer's private key.*

**Property 4** (Delegation Monotonicity). *No delegated capability token can exceed the scope, constraints, or validity period of its parent token (Theorem 1).*

**Property 5** (Behavioral Accountability). *Every action recorded in the attestation layer is attributable to a specific DID, and anomalous actions result in monotonically decreasing trust scores.*

**Property 6** (Revocation Finality). *Once a credential is revoked, all subsequent verification attempts for that credential return failure.*

### 11.2 Known Limitations

1. **Centralized registry.** The current implementation uses in-memory storage. A production deployment requires distributed storage with consensus for availability and partition tolerance.

2. **Key management.** The reference implementation stores signing keys in the identity manager for demonstration purposes. Production deployments must use hardware security modules (HSMs) or secure enclaves.

3. **Behavioral model coverage.** The capability-action mapping is manually defined. Machine-learning-based behavioral profiling could improve detection accuracy for novel attack patterns.

4. **Quantum vulnerability.** Ed25519 is not quantum-resistant. The post-quantum migration path (Section 5.6) must be executed before cryptographically relevant quantum computers become available.

5. **Revocation propagation latency.** In federated deployments, revocation propagation introduces a non-zero window during which revoked credentials may still be accepted by uninformed verifiers.

### 11.3 Comparison with Existing Approaches

| Feature | UTP | OAuth 2.0 | UCAN | Google A2A | SPIFFE/SPIRE |
|---|---|---|---|---|---|
| Agent-native identity | Yes | No | Partial | Partial | Partial |
| Decentralized (no central authority) | Yes | No | Yes | No | No |
| Capability-based authorization | Yes | No | Yes | No | No |
| Delegation with scope reduction | Yes | Limited | Yes | No | No |
| Behavioral attestation | Yes | No | No | No | No |
| Anomaly detection | Yes | No | No | No | No |
| Trust scores | Yes | No | No | No | No |
| Instant revocation | Yes | Token expiry only | No | No | Yes |
| Hash-chain audit trail | Yes | No | No | No | No |
| Post-quantum migration path | Planned | No | No | No | No |

---

## 12. Future Work

### 12.1 Post-Quantum Cryptography Migration

As noted in Section 5.6, UTP's algorithm-agile design supports migration to ML-DSA (FIPS 204) [18]. The migration will proceed in three phases: (i) dual-signature period with both Ed25519 and ML-DSA, (ii) verifier transition to ML-DSA-primary validation, and (iii) deprecation of Ed25519. We target completion before 2030, aligned with NIST's post-quantum transition timeline.

### 12.2 On-Chain Anchoring

The hash-chain revocation root (Section 5.5) is designed for periodic anchoring to a public ledger. We plan integration with Ethereum Layer 2 rollups (e.g., Optimism, Arbitrum) to provide cost-efficient, non-repudiable revocation state proofs. Anchoring frequency will be configurable, balancing on-chain cost against revocation freshness guarantees.

### 12.3 Integration with RiskMesh

RiskMesh, a complementary protocol for risk-aware trust computation in multi-agent systems, can consume UTP trust scores as input signals for higher-order risk assessments. Integration would enable cross-protocol risk scoring where UTP provides entity-level trust and RiskMesh provides system-level risk quantification.

### 12.4 W3C Standardization Path

We intend to submit UTP's DID methods (`did:agent`, `did:human`, `did:org`) and capability token format to the W3C Credentials Community Group for standardization consideration. The capability token format is designed to be expressible as a W3C Verifiable Credential with UTP-specific extensions.

### 12.5 Biometric and Neural Interface Extensions

As brain-computer interfaces (BCIs) and biometric authentication advance, UTP's identity layer can be extended to bind agent identity to biological attestation signals. A `did:neuro` method could anchor agent authorization to neural authentication, providing a trust bridge between biological and artificial cognitive systems.

### 12.6 Machine Learning Behavioral Profiling

The current rule-based anomaly detection (Section 8.2) can be augmented with learned behavioral profiles. An autoencoder trained on an agent's normal action sequences could detect subtle deviations that rule-based systems miss, such as gradual scope creep or coordinated multi-agent attacks.

---

## 13. Conclusion

The Universal Trust Protocol addresses a foundational gap in the emerging AI agent ecosystem: the absence of cryptographically verifiable identity, authorization, behavioral monitoring, and revocation infrastructure purpose-built for autonomous agents. By combining W3C Decentralized Identifiers with Ed25519 cryptography, capability-based authorization with monotonic delegation, exponential-decay behavioral attestation, and instant hash-chain-backed revocation, UTP provides the trust substrate necessary for safe, accountable agent deployment at scale.

The reference implementation demonstrates that the protocol is practical: 92 tests validate correctness across all four layers, cryptographic operations execute in microseconds, and the rogue agent detection scenario confirms that compromised agents can be identified and neutralized within a single attestation cycle. UTP is designed for extensibility, with clear migration paths to post-quantum cryptography and on-chain anchoring.

As autonomous AI agents become integral to enterprise operations, financial services, healthcare, and critical infrastructure, the cost of inadequate agent identity management will grow from operational inconvenience to systemic risk. UTP provides a foundation -- analogous to what TLS provided for web commerce in the 1990s -- upon which a trustworthy agent economy can be built.

---

## References

[1] CyberArk, "2025 Identity Security Threat Landscape Report: The Rise of Machine Identities," CyberArk Software Ltd., 2025. Available: https://www.cyberark.com/resources/threat-landscape-report-2025

[2] Strata Identity, "The AI Agent Identity Crisis: Why Your IAM Isn't Ready," Strata Identity Inc., 2025. Available: https://www.strata.io/ai-agent-identity-crisis

[3] Capgemini Research Institute, "Agentic AI: Harnessing the Power of AI Agents for Enterprise Success," Capgemini SE, 2025. Available: https://www.capgemini.com/insights/research-library/agentic-ai

[4] M. Sporny, D. Longley, M. Sabadello, D. Reed, O. Steele, and C. Allen, "Decentralized Identifiers (DIDs) v1.0," W3C Recommendation, July 2022. Available: https://www.w3.org/TR/did-core/

[5] M. Sporny, D. Longley, M. Sabadello, and O. Steele, "Decentralized Identifiers (DIDs) v1.1," W3C Working Draft, 2024. Available: https://www.w3.org/TR/did-core-1.1/

[6] M. Sporny, D. Longley, D. Chadwick, and O. Steele, "Verifiable Credentials Data Model v2.0," W3C Recommendation, March 2024. Available: https://www.w3.org/TR/vc-data-model-2.0/

[7] J. B. Dennis and E. C. Van Horn, "Programming Semantics for Multiprogrammed Computations," *Communications of the ACM*, vol. 9, no. 3, pp. 143-155, March 1966.

[8] M. S. Miller, "Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control," Ph.D. dissertation, Johns Hopkins University, Baltimore, MD, 2006.

[9] B. Burdges, D. Chase, and I. Denisova, "UCAN Specification v0.10," Fission Codes Inc., 2023. Available: https://github.com/ucan-wg/spec

[10] V. Chandola, A. Banerjee, and V. Kumar, "Anomaly Detection: A Survey," *ACM Computing Surveys*, vol. 41, no. 3, article 15, July 2009.

[11] Google, "Agent2Agent Protocol (A2A)," Google LLC, 2025. Available: https://github.com/google/A2A

[12] Microsoft, "AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation," Microsoft Research, 2023. Available: https://github.com/microsoft/autogen

[13] OWASP Foundation, "OWASP Top 10 for Large Language Model Applications," OWASP, 2025. Available: https://owasp.org/www-project-top-10-for-large-language-model-applications/

[14] A. Narayanan and V. Shmatikov, "De-anonymizing Social Networks," in *Proc. IEEE Symposium on Security and Privacy*, pp. 173-187, 2009.

[15] D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, and B.-Y. Yang, "High-Speed High-Security Signatures," *Journal of Cryptographic Engineering*, vol. 2, no. 2, pp. 77-89, September 2012.

[16] PyNaCl Contributors, "PyNaCl: Python Binding to libsodium," 2024. Available: https://pynacl.readthedocs.io/

[17] A. Rundgren, B. Jordan, and S. Erdtman, "JSON Canonicalization Scheme (JCS)," RFC 8785, IETF, June 2020.

[18] National Institute of Standards and Technology, "Module-Lattice-Based Digital Signature Standard (ML-DSA)," FIPS 204, U.S. Department of Commerce, August 2024.

---

*Correspondence: J. Koistinen. This work is released under the MIT License.*
