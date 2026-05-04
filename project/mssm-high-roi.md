# Lite-Vault: High-ROI Feature Roadmap

This document outlines four high-impact architectural and operational enhancements designed to elevate `lite-vault` (Minimal Secure Secrets Manager) from a functional prototype to a robust, enterprise-grade system.

## Implementation Order & Dependencies

Features have implicit dependencies that must be respected:

- **Feature 1 (JDBC)** is a prerequisite for Feature 2 (AppRole needs `secret_id` storage) and optionally for Feature 3 (persistent audit log store).
- **Feature 2 (AppRole)** can begin once Feature 1's schema is stable.
- **Feature 3 (AI)** requires a concrete decision on audit log access pattern before the daemon can be built.
- **Feature 4 (Transit)** is the most self-contained and closest to implementation-ready; it can be built in parallel with Feature 1.

---

## 1. Distributed Storage & High Availability (HA)

### The Challenge
Currently, the persistence layer uses `FileSystemStorageBackend`, which writes encrypted blobs to the local filesystem. This creates a single point of failure and prevents deploying `lite-vault` in a multi-node, horizontally scaled cluster.

### The Solution: JDBC Storage Backend
We will implement a distributed, consensus-driven storage backend using PostgreSQL, leveraging the existing `spring-boot-starter-jdbc` dependency.

**Implementation Details:**
- **`JdbcStorageBackend`**: Create a new class implementing the `StorageBackend` interface.
- **Schema**: Create a `vault_storage` table with columns `key_path` (VARCHAR PRIMARY KEY) and `encrypted_data` (BYTEA).
- **Cluster Coordination**: Use database-backed distributed locks to handle leader election. This is crucial for tasks like background lease expiration or policy rotation across multiple nodes. Concrete mechanism must be chosen from: Postgres advisory locks (`pg_try_advisory_lock`), a dedicated lock table, or `SELECT FOR UPDATE SKIP LOCKED`.
- **State Replication**: Because state is persisted centrally in PostgreSQL, node replication is inherently consistent as long as we maintain transactional integrity on writes.

**Open Design Questions:**
- **`listDirectory` semantics**: The flat `key_path` table must emulate directory listing. The implementation will require a query pattern like `WHERE key_path LIKE 'prefix/%' AND key_path NOT LIKE 'prefix/%/%'` to return only immediate children of a path. This needs explicit testing.
- **`EncryptedData` serialization**: The `StorageBackend` interface operates on `EncryptedData` objects, not raw bytes. The JDBC backend must define whether it serializes the object as raw bytes into BYTEA or as a JSON envelope.
- **Backend selection config**: A new `mssm.storage.backend` discriminator property (e.g., `filesystem` vs `jdbc`) must be added to `MssmProperties` and wired into a `StorageBackend` `@Bean` factory in configuration.
- **Seal state interaction**: Behavior when a node is sealed must be defined — should sealed nodes block all JDBC writes, or only reads that require decryption?

**Migration Strategy:**
A one-time migration utility or script is required to move existing `FileSystemStorageBackend` secrets into the `vault_storage` table. This must be completed (or explicitly skipped for greenfield deployments) before switching the active backend.

---

## 2. Advanced Authentication Mechanisms

### The Challenge
The current `StaticTokenAuthFilter` limits the system to static tokens, which is a security anti-pattern for machine-to-machine (M2M) communications.

### The Solution: AppRole Authentication
Introduce dynamic, identity-based access by implementing an "AppRole" authentication engine.

**Implementation Details:**
- **AppRole Entities**: Create an API that allows administrators to define "Roles". Each Role binds to a specific `PolicyRule`.
- **Credential Exchange**: Introduce an endpoint `POST /v1/auth/approle/login`. A client service provides a `role_id` and a `secret_id` to this endpoint.
- **Dynamic JWT Generation**: If the credentials are valid, the `AppRoleService` generates a short-lived JSON Web Token (JWT). The JWT claims will contain the authorized policies.
- **Filter Refactoring**: Update `PolicyEnforcementFilter` to parse incoming JWTs, extract the authorized policies from the claims, and enforce them on the requested API paths. Static token authentication and AppRole JWT authentication must coexist — the filter must handle both code paths without breaking existing `POLICY_*` authority resolution.

**Open Design Questions:**
- **JWT signing key**: The existing `JwtSecretsEngine` uses RSA/EC keys loaded from config. AppRole JWTs need a dedicated signing key (HMAC or RSA). A JWT library decision is required — either reuse the existing infrastructure or add `jjwt` / `nimbus-jose-jwt` as a dependency.
- **`secret_id` lifecycle & storage**: `secret_id`s must be single-use or time-bound and stored server-side for validation. Storage options are: (a) in the JDBC `vault_storage` table (depends on Feature 1), (b) a dedicated `approle_credentials` table, or (c) in-memory with no persistence across restarts. This must be decided before implementation.
- **AppRole role storage schema**: AppRole role definitions (`role_id` → policy binding) must be persisted. Options: a dedicated `approle_roles` table, or stored as KV secrets in the existing backend.
- **Token TTL & revocation**: JWTs are stateless by design, making revocation non-trivial. Options are: short TTL (accepting a window of unauthorized use after revocation) or a server-side token blocklist. This must be a conscious, documented design decision.

---

## 3. Agentic AI Integration for Operations

### The Challenge
Security policy authoring and audit log monitoring are complex and time-consuming operational tasks.

### The Solution: LLM-Assisted Tooling
Introduce local Agentic AI workflows to drastically simplify `lite-vault` operations.

**Implementation Details:**
- **Natural Language Policy Generation (CLI)**:
  - Enhance `lite-vault-cli.sh`.
  - Introduce a `generate-policy` command that accepts plain English (e.g., "Allow read to prod db, deny delete").
  - The CLI will interface with a local LLM (like Ollama) using a system prompt that enforces outputting the strict JSON/YAML format required by the `PolicyRepository`.
  - LLM output must be validated against the `PolicyDefinition` / `PolicyRule` schema before being written, to guard against malformed policies from a bad model response.
  - The output format (JSON or YAML) and the loading mechanism must be defined — `PolicyRepository` currently loads policies from `MssmProperties` at startup via `@PostConstruct`, so either a vault restart or a new dynamic reload endpoint is required to apply generated policies.
- **Anomaly Detection Daemon**:
  - Build a lightweight Spring `@Scheduled` daemon (`AnomalyDetectionDaemon`).
  - It periodically sends batches of access logs to an AI inference endpoint. The model acts as a heuristic engine, flagging anomalous behaviors like unexpected access times or unseen IP ranges.

**Open Design Questions:**
- **Audit log access pattern**: `LogAuditBackend` writes to SLF4j and is not queryable at runtime. The daemon cannot "tail" it directly. A concrete decision is required before implementation: (a) add an in-memory ring-buffer event store to the `AuditBackend` that the daemon can poll, or (b) mandate `FileAuditBackend` and have the daemon parse the log file.
- **AI inference endpoint**: If the inference endpoint is remote rather than local (Ollama is local), audit log payloads must be reviewed for sensitive data before transmission — `AuditEvent` records contain `RequestInfo` with paths, outcomes, and client metadata.
- **Ollama model selection**: A specific recommended model (e.g., `llama3`, `mistral`) and the system prompt template for `generate-policy` should be documented.

---

## 4. Encryption as a Service (Transit Engine)

### The Challenge
Client applications often need to encrypt data before storing it in their own databases, but managing cryptographic keys securely within those applications is difficult.

### The Solution: Transit Secrets Engine
Expose the existing robust `EncryptionService` to external clients, allowing `lite-vault` to handle encryption offloading. This ensures cryptographic keys never leave the vault's memory.

**Implementation Details:**
- **API Endpoints**:
  - `POST /v1/transit/encrypt/{keyName}`: Accepts a JSON payload with a Base64-encoded `plaintext` field.
  - `POST /v1/transit/decrypt/{keyName}`: Accepts a JSON payload with a Base64-encoded `ciphertext` field.
  - Paths include `{keyName}` for future key namespacing compatibility, even if only a single global key is supported initially.
- **Integration**: Route these endpoints to the existing `EncryptionService.encrypt()` and `EncryptionService.decrypt()` methods. Note that `EncryptionService` checks `SealManager.checkUnsealed()` — transit endpoints will be unavailable when the vault is sealed (this is intentional and must be documented).
- **Format**: The returned ciphertext will maintain the `nonce || ciphertext` byte format, Base64-encoded for transit over HTTP.
- **Policy integration**: Define which `PolicyCapability` maps to transit operations. Recommended: `WRITE` for encrypt (data transformation), `READ` for decrypt. Policy paths should follow the pattern `transit/encrypt/{keyName}` and `transit/decrypt/{keyName}` so `PolicyEnforcementFilter` can protect them.
- **OpenAPI**: Annotate new endpoints with `@Operation` / `@ApiResponse` to keep the `springdoc-openapi` spec current.

**Open Design Questions:**
- **Key rotation**: The current `EncryptionService` uses a single global master key from config. Vault's transit engine supports versioned key rotation (the `vault:v1:...` ciphertext format) so that decryption of old ciphertexts does not break after a key change. This must either be implemented or explicitly declared as a non-goal for this iteration, with the implication that key rotation will require re-encrypting all transit-encrypted data.
- **Multiple named keys**: Supporting multiple named transit keys (each with its own key material and rotation schedule) is a natural extension. If not in scope for this iteration, the API path should still include `{keyName}` as a forward-compatible placeholder.

---

## Cross-Cutting Concerns

- **Testing strategy**: Each feature requires a dedicated testing approach. HA behavior (lock contention, multi-node consistency) and AppRole (token expiry, `secret_id` single-use enforcement) are particularly important to cover with integration tests.
- **OpenAPI coverage**: All new endpoints should be annotated for `springdoc-openapi` to keep the generated spec complete.
- **Seal state contract**: Each feature must document its behavior when the vault is sealed. As a baseline, any operation that requires decryption should fail with a `VaultSealedException`.
