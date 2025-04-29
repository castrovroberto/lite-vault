# Minimal Secure Secrets Manager (MSSM) - LiteVault

**Version:** 0.1.0 (Unreleased changes targeting v0.2.0)

A minimal implementation of a secure secrets manager inspired by HashiCorp Vault, focusing on core security primitives and essential features like dynamic secrets and key rotation. Built with Java 21 and Spring Boot.

## Project Goal

To provide a secure, centralized system for managing dynamic database credentials, JWT key rotation, and secure storage of static secrets (like password peppers), reducing risks associated with hardcoded or statically managed sensitive information.

*(Keep Introduction, Scope, etc. if you have them)*

## Current Status & Features (In Progress)

- **Project Setup:** Maven project initialized with Java 21 and Spring Boot. Basic directory structure and `.gitignore` in place.
- **Dependencies:** Includes Spring Boot starters for Web, Validation, Security. Includes Lombok and BouncyCastle.
- **Core Encryption:**
  - **Implemented:** Foundational cryptographic layer using **AES-256-GCM** (`EncryptionService.java`). Provides authenticated encryption for data at rest.
  - **Note:** Now retrieves the master key from `SealManager`; cryptographic operations are blocked if the vault is sealed.
- **Storage:**
  - **Defined:** JSON format (`EncryptedData.java`) for persistent storage (version, Base64 nonce/ciphertext, timestamp).
  - **Implemented:** Basic persistence layer via `FileSystemStorageBackend`, storing encrypted JSON blobs on local disk. Configurable path via type-safe properties.
- **Sealing:**
  - **Implemented:** Core seal/unseal logic (`SealManager`). Vault starts `SEALED` by default.
  - **Implemented:** Automatic unseal attempt on startup using `mssm.master.b64` configuration property/environment variable (loaded via type-safe properties).
  - **Implemented:** Cryptographic operations via `EncryptionService` are blocked with `VaultSealedException` when sealed.
- **API:**
  - **Implemented:** Basic HTTP server setup using Spring Boot Web (embedded Tomcat). Listens on configured HTTPS port (e.g., `8443`).
  - **Implemented:** Basic TLS (HTTPS) enabled using a self-signed certificate (`litevault-keystore.p12`) for development.
  - **Implemented:** `RootController` created in `tech.yump.vault.api`.
  - **Implemented:** Basic `GET /` endpoint available, returning a simple JSON status message.
  - **Implemented:** `GET /sys/seal-status` endpoint available, returning the current seal status (`{"sealed": true/false}`).
  - **Implemented (KV v1):** CRUD endpoints for the static Key/Value secrets engine under `/v1/kv/data/{path}` (Task 13):
    - `PUT /v1/kv/data/{path}`: Write/update secrets (JSON body `{ "key": "value", ... }`). Requires authentication.
    - `GET /v1/kv/data/{path}`: Read secrets (returns JSON map or 404). Requires authentication.
    - `DELETE /v1/kv/data/{path}`: Delete secrets. Requires authentication.
- **Authentication/Authorization:**
  - **Implemented (Basic):** Static Token Authentication (Task 11). API requests (except `/` and `/sys/seal-status`) require a valid `X-Vault-Token` header matching a token configured in `mssm.auth.static-tokens.tokens` when enabled. Uses Spring Security for enforcement. (F-CORE-110)
- **Secrets Engines:**
  - **Implemented (KV v1):** A static Key/Value secrets engine (`FileSystemKVSecretEngine`) is implemented. It stores arbitrary key-value pairs at logical paths, encrypting the entire map as a single blob before persisting it using the configured `StorageBackend`. (Task 12)
- **Configuration:**
  - **Implemented:** Type-safe configuration loading using `@ConfigurationProperties` (`MssmProperties`) with startup validation for required `mssm.*` settings.
  - **Implemented:** Configuration for static authentication tokens (`mssm.auth.static-tokens`) with conditional validation (tokens required only if enabled).
- **Testing:**
  - **Implemented:** Unit tests for `EncryptionService` and `FileSystemStorageBackend` covering core functionality, edge cases, and error handling.

## Security Considerations

- **Encryption at Rest:** Core data is encrypted using AES-256-GCM (`EncryptionService`) and stored persistently as JSON files via the `FileSystemStorageBackend` (NFR-SEC-100, F-CORE-100). Encryption requires the vault to be unsealed. KV secrets are stored using this mechanism.
- **Encryption in Transit:** **Implemented (Basic):** API communication secured via TLS 1.2+ using a self-signed certificate (NFR-SEC-110). **Note:** This self-signed certificate is suitable only for local development and testing. Production deployments require a certificate signed by a trusted Certificate Authority (CA).
- **Keystore Security:** The password for the development keystore (`litevault-keystore.p12`) must be provided via the `MSSM_KEYSTORE_PASSWORD` environment variable at runtime.
- **Sealing:** The master encryption key will not be persisted directly. An unseal mechanism will be required to load the key into memory (F-CORE-140).
  - **Implemented:** The core `SealManager` controls the loading/unloading of the master key into memory. The vault starts sealed and blocks crypto operations.
  - **Initial Unseal:** Currently relies on providing the master key via the `mssm.master.b64` configuration property (e.g., environment variable) for automatic unseal on startup. **Securing this initial key value is critical.**
- **Authentication:** API access (including the new `/v1/kv/data/**` endpoints) is protected by static tokens when enabled (`mssm.auth.static-tokens.enabled=true`). Clients must provide a valid token in the `X-Vault-Token` header. These tokens should be treated as sensitive credentials.
- **Configuration Validation:** The application now performs basic validation on required configuration properties at startup (e.g., master key, storage path) and will fail to start if they are missing or invalid. Also includes conditional validation for static tokens (tokens required only if enabled).

## Getting Started

*(Instructions for building/running will go here later)*

**Running (with Auto-Unseal):**
1.  **Generate Keystore (if not present):** Run the `generate-keystore.sh` script (or `key-gen.sh` if not renamed) from the project root (or use the `keytool` command directly) to create `src/main/resources/litevault-keystore.p12` (or `dev-keystore.p12` if using the parameterized script defaults).
2.  **Set Keystore Password:** Set the environment variable `MSSM_KEYSTORE_PASSWORD` to match the password used when generating the keystore.
3.  **Set Master Key:** Securely generate a Base64 encoded AES-256 key and set the environment variable `MSSM_MASTER_B64`. Example (Linux/macOS): `export MSSM_MASTER_B64=$(openssl rand -base64 32)`
4.  **Configure Static Token (Optional but needed for KV API):** If `mssm.auth.static-tokens.enabled=true` in `application.yml` or `application-dev.yml`, set the token(s) via environment variable or configuration. Example: `export MSSM_AUTH_STATIC__TOKENS_TOKENS=my-secret-token`. You will need this token in the `X-Vault-Token` header to use the KV endpoints.
5.  **Build & Run:** Use Maven: `mvn spring-boot:run` (or build a JAR `mvn package` and run `java -jar target/*.jar`).

*(Add more detailed instructions as needed)*