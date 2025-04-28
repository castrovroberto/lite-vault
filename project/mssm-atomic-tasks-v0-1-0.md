# Minimal Secure Secrets Manager (MSSM) v0.1.0

## Atomic Tasks Roadmap: Phase 1 - Core System Setup

> **Goal:** Lay the groundwork for a secure system, focusing on encryption, sealing, basic storage, and secure API access.

---

### First 10 Atomic Tasks

#### 1. [x] Initialize Project & Basic Structure
- **Description:**
    - Set up the project repository (Git).
    - Choose primary language/framework (e.g., Go, Java/Spring Boot, Python/FastAPI).
    - Initialize the build system (e.g., Go modules, Maven, Pipenv/Poetry).
    - Create a basic directory structure:
        - For Go: `cmd/`, `internal/`, `pkg/`
        - For Java: `src/main/java`, `src/test/java`
    - Add a standard `.gitignore`.
- **Rationale:**
    - Establishes the development environment and enforces code organization discipline early.

#### 2. [x] Implement Core Encryption/Decryption Logic (AES-GCM)
- **Description:**
    - Implement functions/methods to encrypt and decrypt byte arrays using AES-GCM.
    - Generate nonces correctly and ensure nonce reuse protection.
    - Use a hardcoded key initially for local unit testing only.
- **Rationale:**
    - AES-GCM provides authenticated encryption.
    - Core primitive required for F-CORE-100 (data encryption at rest).

#### 3. [x] Define Encrypted Storage Format
- **Description:**
    - Create a simple storage format, preferably JSON or binary:
        - Nonce
        - Ciphertext
        - Optional metadata (e.g., version, timestamp).
- **Rationale:**
    - Defines how encrypted data blobs are structured for persistence.

#### 4. [x] Implement Basic File System Storage Backend
- **Description:**
    - Define a `StorageBackend` interface.
    - Implement a file system-based backend:
        - `Put(key, encryptedBlob)`
        - `Get(key)`
        - `Delete(key)`
- **Rationale:**
    - Initial persistence layer for secrets.
    - Foundation for modular storage extensibility.

#### 5. [x] Implement Core Seal/Unseal Logic
- **Description:**
    - Implement a "sealed" state where the master key is not loaded.
    - Implement an "unseal" process:
        - Initially use a master key from an environment variable or config.
    - Block all crypto operations when sealed.
- **Rationale:**
    - Critical for protecting secrets if the system restarts or is compromised.

#### 6. [x] Set Up Minimal HTTP Server & Routing
- **Description:**
    - Initialize a basic HTTP server with request routing.
    - No authentication initially.
- **Rationale:**
    - Core foundation for the API (F-CORE-150).

#### 7. [x] Create `/sys/seal-status` API Endpoint
- **Description:**
    - Implement a GET endpoint that returns the current seal status.
    - Response Example: `{ "sealed": true }`
- **Rationale:**
    - Enables minimal API interaction and monitoring.

#### 8. [x] Configure Basic TLS for API Server
- **Description:**
    - Generate a self-signed certificate for local development.
    - Configure server to serve only via HTTPS.
- **Rationale:**
    - Meet security requirements for encrypted transport (NFR-SEC-110).

#### 9. [x] Implement Basic Configuration Loading
- **Description:**
    - Allow the system to load basic settings:
        - Storage path
        - Master key source
        - TLS settings
    - From environment variables or a lightweight config file.
- **Rationale:**
    - Prepares the system for flexible deployment environments.

#### 10. [x] Write Unit Tests for Encryption & Storage
- **Description:**
    - Implement unit tests for:
        - AES-GCM encrypt/decrypt correctness.
        - File system storage backend (read/write/delete operations).
    - Cover edge cases:
        - Invalid keys
        - Nonexistent keys
- **Rationale:**
    - Establishes a testing baseline and confidence for future features.

---

## Result After Phase 1 Completion

- Core encryption capability in place.
- Secrets can be encrypted, stored, and retrieved securely.
- System maintains a secure sealed/unsealed lifecycle.
- A basic API server exposes operational health.
- TLS encryption protects all API traffic.
- Configuration flexibility enabled.
- Basic unit tests validate key components.

---

## Suggested Improvements for Next Steps

- **Authentication:** Protect API endpoints with token-based authentication.
- **Secrets Engines:** Add modular support for dynamic database credentials, static secret storage.
- **Audit Logging:** Begin capturing immutable audit events.
- **Key Management:** Implement key rotation primitives.
- **Lease Management:** Start tracking dynamic secret lifetimes.

---

> **Reminder:** Security, modularity, and testability are the top priorities from the start.

---