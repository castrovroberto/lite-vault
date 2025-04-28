# Minimal Secure Secrets Manager (MSSM) - LiteVault

**Version:** 1.0.0-SNAPSHOT

A minimal implementation of a secure secrets manager inspired by HashiCorp Vault, focusing on core security primitives and essential features like dynamic secrets and key rotation. Built with Java 21 and Spring Boot.

## Project Goal

To provide a secure, centralized system for managing dynamic database credentials, JWT key rotation, and secure storage of static secrets (like password peppers), reducing risks associated with hardcoded or statically managed sensitive information.

*(Keep Introduction, Scope, etc. if you have them)*

## Current Status & Features (In Progress)

- **Project Setup:** Maven project initialized with Java 21 and Spring Boot. Basic directory structure and `.gitignore` in place.
- **Core Encryption:**
  - **Implemented:** Foundational cryptographic layer using **AES-256-GCM** (`EncryptionService.java`). Provides authenticated encryption for data at rest.
  - **Note:** Now retrieves the master key from `SealManager`; cryptographic operations are blocked if the vault is sealed.
- **Storage:**
  - **Defined:** JSON format (`EncryptedData.java`) for persistent storage (version, Base64 nonce/ciphertext, timestamp).
  - **Implemented:** Basic persistence layer via `FileSystemStorageBackend`, storing encrypted JSON blobs on local disk. Configurable path via properties.
- **Sealing:**
  - **Implemented:** Core seal/unseal logic (`SealManager`). Vault starts `SEALED` by default.
  - **Implemented:** Automatic unseal attempt on startup using `mssm.master.key.b64` configuration property/environment variable.
  - **Implemented:** Cryptographic operations via `EncryptionService` are blocked with `VaultSealedException` when sealed.
- **API:**
  - **Implemented:** Basic HTTP server setup using Spring Boot Web (embedded Tomcat). Listens on configured port (e.g., 8081).
  - **Implemented:** `RootController` created in `tech.yump.vault.api`.
  - **Implemented:** Basic `GET /` endpoint available, returning a simple JSON status message.
  - **Implemented:** `GET /sys/seal-status` endpoint available, returning the current seal status (`{"sealed": true/false}`).
- **Authentication/Authorization:** *Not Implemented*
- **Secrets Engines:** *Not Implemented*

## Security Considerations

- **Encryption at Rest:** Core data is encrypted using AES-256-GCM (`EncryptionService`) and stored persistently as JSON files via the `FileSystemStorageBackend` (NFR-SEC-100, F-CORE-100). Encryption requires the vault to be unsealed.
- **Encryption in Transit:** API communication will be secured via TLS 1.2+ (NFR-SEC-110). *(Planned)*
- **Sealing:** The master encryption key will not be persisted directly. An unseal mechanism will be required to load the key into memory (F-CORE-140). *(Planned)*
  - **Implemented:** The core `SealManager` controls the loading/unloading of the master key into memory. The vault starts sealed and blocks crypto operations.
  - **Initial Unseal:** Currently relies on providing the master key via the `mssm.master.key.b64` configuration property (e.g., environment variable) for automatic unseal on startup. **Securing this initial key value is critical.**
- ~~Temporary Key:~~ The hardcoded key in `EncryptionService` has been removed and replaced by the dynamic key retrieval from `SealManager`.

## Getting Started

*(Instructions for building/running will go here later)*

**Running (with Auto-Unseal):**
1. Generate a 32-byte AES key and Base64 encode it: `openssl rand 32 | base64`
2. Set the environment variable: `export MSSM_MASTER_KEY_B64="YOUR_GENERATED_BASE64_KEY_HERE"`
3. Run the application (e.g., via `mvn spring-boot:run` or from your IDE). The application should log that it has successfully unsealed and the server has started.
4. Access the root endpoint (assuming port 8081): `curl http://localhost:8081/`
5. Check the seal status: `curl http://localhost:8081/sys/seal-status` (Should return `{"sealed":false}`)

**Running (Sealed):**
1. Ensure the `MSSM_MASTER_KEY_B64` environment variable is **not** set or is invalid.
2. Run the application. It should log that it remains sealed.
3. Check the seal status: `curl http://localhost:8081/sys/seal-status` (Should return `{"sealed":true}`)

## Project Roadmap (Atomic Tasks - Phase 1)

Based on `project/mssm-atomic-tasks-v1-0.md`:

- [x] **Task 1:** Initialize Project & Basic Structure
- [x] **Task 2:** Implement Core Encryption/Decryption Logic (AES-GCM)
- [x] **Task 3:** Define Encrypted Storage Format
- [x] **Task 4:** Implement Basic File System Storage Backend
- [x] **Task 5:** Implement Core Seal/Unseal Logic
- [x] **Task 6:** Set Up Minimal HTTP Server & Routing
- [x] **Task 7:** Create `/sys/seal-status` API Endpoint
- [ ] **Task 8:** Configure Basic TLS for API Server
- [ ] **Task 9:** Implement Basic Configuration Loading
- [ ] **Task 10:** Write Unit Tests for Encryption & Storage

*(Keep other sections like Contributing, License etc. if you have them)*

 ---