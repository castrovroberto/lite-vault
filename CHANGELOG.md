# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Basic TLS Configuration (Task 8):**
  - Generated a self-signed certificate and keystore (`litevault-keystore.p12`) using `keytool` for local development.
  - Configured `application-dev.yml` to enable HTTPS via `server.ssl.*` properties:
    - `enabled: true`
    - `key-store: classpath:litevault-keystore.p12`
    - `key-store-password: ${MSSM_KEYSTORE_PASSWORD}` (Requires env var)
    - `key-store-type: PKCS12`
    - `key-alias: litevault`
  - Restricted enabled TLS protocols to `TLSv1.3,TLSv1.2` (NFR-SEC-110).
  - Added `*.p12` pattern to `.gitignore`.
- **Seal Status API Endpoint (Task 7):**
  - Implemented `GET /sys/seal-status` endpoint in `RootController`.
  - Injects `SealManager` to query the current seal state.
  - Returns a JSON response indicating the seal status: `{"sealed": true}` or `{"sealed": false}`.
- **Minimal HTTP Server & Routing (Task 6):**
  - Integrated `spring-boot-starter-web` to enable embedded Tomcat server.
  - Created `api` package (`tech.yump.vault.api`) for REST controllers.
  - Implemented `RootController` (`@RestController`) with a basic `GET /` endpoint.
  - The root endpoint returns a simple JSON status message (`{"message": "...", "status": "OK"}`).
- **Core Seal/Unseal Mechanism (Task 5):**
  - Introduced `SealStatus` enum (`SEALED`, `UNSEALED`) in `tech.yump.vault.core`.
  - Added `VaultSealedException` thrown when operations requiring the master key are attempted while sealed.
  - Implemented `SealManager` service (`@Service`) in `tech.yump.vault.core`:
    - Manages the vault's seal status (`SEALED` by default).
    - Holds the master `SecretKey` in memory *only* when unsealed (using `AtomicReference`).
    - Provides `seal()`, `unseal(base64Key)`, `isSealed()`, `getSealStatus()`, and `getMasterKey()` methods.
    - Attempts automatic unseal on startup (`@PostConstruct`) using a Base64 encoded AES-256 key provided via the `mssm.master.key.b64` configuration property (or environment variable).
- **File System Storage Backend (Task 4):**
  - Defined `StorageBackend` interface for persistence operations (`put`, `get`, `delete`).
  - Implemented `FileSystemStorageBackend` as a Spring `@Component`.
  - Stores/Retrieves `EncryptedData` DTOs as JSON files on the local filesystem.
  - Uses Jackson `ObjectMapper` for JSON serialization/deserialization.
  - Implements path resolution with sanitization and validation to prevent traversal.
  - Base storage path configurable via `mssm.storage.filesystem.path` property (defaults to `./vault-data`).
  - Includes `@PostConstruct` validation for base path existence and permissions.
  - Added custom `StorageException` for storage-related errors.
- **Encrypted Storage Format Definition (Task 3):**
  - Defined a JSON structure for storing encrypted data (`nonce`, `ciphertext`, `version`, `timestamp`).
  - Created `EncryptedData.java` DTO in `tech.yump.vault.storage` package to represent this format.
  - Uses Base64 encoding for nonce and ciphertext within the JSON structure.
  - Added convenience methods in `EncryptedData` for Base64 encoding/decoding.
  - Leverages Jackson (via Spring Boot Web) for future JSON serialization/deserialization.
- **Core Encryption Service (Task 2):**
  - Implemented `EncryptionService.java` providing core cryptographic operations.
  - Uses **AES-256-GCM** for authenticated encryption (AEAD), fulfilling NFR-SEC-100.
  - Generates a unique 12-byte nonce per encryption operation.
  - Handles nonce extraction and GCM tag verification during decryption.
  - Added custom `EncryptionService.EncryptionException` for cryptographic errors.
  - Registered BouncyCastle security provider (`bcprov-jdk18on`) for JCE operations.
  - Added basic SLF4j logging to the service.
- **Project Setup (Task 1):**
  - Initialized project structure with Maven and Spring Boot parent.
  - Configured `pom.xml` with Java 21, Spring Boot dependencies (Web, Test), Lombok, and BouncyCastle.
  - Added standard `.gitignore` file.
  - Created basic `src/main/java` and `src/test/java` directory structures.
  - Added placeholder `LiteVaultApplication` and `LiteVaultApplicationTest`.

### Changed
- **API Server:** Now runs on HTTPS using the configured port (`8443` in `application-dev.yml`). HTTP is disabled by default when SSL is enabled this way.
- **Encryption Service:**
  - Removed the temporary, hardcoded AES key.
  - Now depends on `SealManager` via constructor injection.
  - Retrieves the master key dynamically using `sealManager.getMasterKey()` before performing encryption or decryption.
  - Propagates `VaultSealedException` if cryptographic operations are attempted while the vault is sealed.
- **Root Controller:**
  - Injected `SealManager` via constructor.

### Security
- **Encryption in Transit:** API communication is now encrypted using TLS 1.2/1.3 (NFR-SEC-110). **Note:** Uses a self-signed certificate suitable only for development/testing.
- **Keystore Password:** The keystore password must be provided via the `MSSM_KEYSTORE_PASSWORD` environment variable at runtime.
- **Master Key Management:** The master encryption key is no longer hardcoded in `EncryptionService`. It is now managed by `SealManager` and loaded into memory only when the vault is unsealed.
- **Initial Unseal:** The initial unseal process relies on the `mssm.master.key.b64` configuration property (typically set via an environment variable). **Securing this initial key value is critical.** The vault remains sealed if this key is not provided or is invalid. Future work will involve implementing a more robust unseal mechanism (e.g., Shamir's Secret Sharing).

 ---