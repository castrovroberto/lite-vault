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
  - **Implemented:** Basic HTTP server setup using Spring Boot Web (embedded Tomcat). Listens on configured HTTPS port (e.g., `8443`).
  - **Implemented:** Basic TLS (HTTPS) enabled using a self-signed certificate (`litevault-keystore.p12`) for development.
  - **Implemented:** `RootController` created in `tech.yump.vault.api`.
  - **Implemented:** Basic `GET /` endpoint available, returning a simple JSON status message.
  - **Implemented:** `GET /sys/seal-status` endpoint available, returning the current seal status (`{"sealed": true/false}`).
- **Authentication/Authorization:** *Not Implemented*
- **Secrets Engines:** *Not Implemented*

## Security Considerations

- **Encryption at Rest:** Core data is encrypted using AES-256-GCM (`EncryptionService`) and stored persistently as JSON files via the `FileSystemStorageBackend` (NFR-SEC-100, F-CORE-100). Encryption requires the vault to be unsealed.
- **Encryption in Transit:** **Implemented (Basic):** API communication secured via TLS 1.2+ using a self-signed certificate (NFR-SEC-110). **Note:** This self-signed certificate is suitable only for local development and testing. Production deployments require a certificate signed by a trusted Certificate Authority (CA).
- **Keystore Security:** The password for the development keystore (`litevault-keystore.p12`) must be provided via the `MSSM_KEYSTORE_PASSWORD` environment variable at runtime.
- **Sealing:** The master encryption key will not be persisted directly. An unseal mechanism will be required to load the key into memory (F-CORE-140).
  - **Implemented:** The core `SealManager` controls the loading/unloading of the master key into memory. The vault starts sealed and blocks crypto operations.
  - **Initial Unseal:** Currently relies on providing the master key via the `mssm.master.key.b64` configuration property (e.g., environment variable) for automatic unseal on startup. **Securing this initial key value is critical.**
- ~~Temporary Key:~~ The hardcoded key in `EncryptionService` has been removed and replaced by the dynamic key retrieval from `SealManager`.

## Getting Started

*(Instructions for building/running will go here later)*

**Running (with Auto-Unseal):**
1.  **Generate Keystore (if not present):** Run the `key-gen.sh` script from the project root (or use the `keytool` command directly) to create `src/main/resources/litevault-keystore.p12`.
2.  **Set Keystore Password:** Set the environment variable to match the password used in `key-gen.sh`.
    