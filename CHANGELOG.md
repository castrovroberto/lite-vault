# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **KV v1 API Endpoints (Task 13):**
  - Created `KVController` under `/v1/kv/data`.
  - Implemented `PUT /{*path}` endpoint to write/update secrets (JSON body).
  - Implemented `GET /{*path}` endpoint to read secrets (returns JSON map or 404).
  - Implemented `DELETE /{*path}` endpoint to delete secrets.
  - Endpoints require authentication via `X-Vault-Token` (Task 11).
  - Added basic exception handling (`@ExceptionHandler`) mapping engine errors to HTTP status codes (400, 404, 500, 503).
- **Static Secrets Engine (KV v1 - Task 12):**
  - Defined `KVSecretEngine` interface (`read`, `write`, `delete`) in `tech.yump.vault.secrets.kv`.
  - Implemented `FileSystemKVSecretEngine` using `StorageBackend`, `EncryptionService`, and `ObjectMapper`.
  - Serializes `Map<String, String>` secrets to JSON, encrypts the JSON blob, and stores the resulting `EncryptedData` via `StorageBackend` using the logical path as the key.
  - Decrypts the blob and deserializes JSON back to a map on read.
  - Added `KVEngineException` for engine-specific errors.
  - Registered `FileSystemKVSecretEngine` as a Spring `@Service`.
- **Basic Static Token Authentication (Task 11):**
  - Added `spring-boot-starter-security` dependency.
  - Updated `MssmProperties` to include `mssm.auth.static-tokens` configuration (nested records `AuthProperties`, `StaticTokenAuthProperties` with `enabled` flag, `Set<String> tokens`).
  - Implemented custom validation (`@ValidStaticTokenConfig`, `StaticTokenConfigValidator`) to require tokens only if static auth is enabled.
  - Implemented `StaticTokenAuthFilter` to read the `X-Vault-Token` header, validate against configured tokens, and set authentication context (`UsernamePasswordAuthenticationToken` with `ROLE_TOKEN_AUTH`) using `SecurityContextHolder`. Includes `shouldNotFilter` optimization.
  - Implemented `SecurityConfig` using `@EnableWebSecurity`:
    - Configured stateless session management (`SessionCreationPolicy.STATELESS`).
    - Disabled CSRF, form login, logout.
    - Added `StaticTokenAuthFilter` bean and included it in the filter chain.
    - Configured authorization rules: `/sys/seal-status` and `/` are public (`permitAll`), all other requests (including `/v1/**`) require authentication (`authenticated`).
    - Added conditional logic to apply security only if `mssm.auth.static-tokens.enabled=true`.
  - Added example static token configuration to `application-dev.yml`.
- **Unit Tests (Task 10):**
  - Implemented unit tests for `EncryptionService` using JUnit 5 and Mockito.
    - Verified encrypt/decrypt round trip.
    - Tested behavior when vault is sealed (using mocked `SealManager`).
    - Tested handling of tampered data (invalid GCM tag).
    - Tested handling of null/invalid inputs.
  - Implemented unit tests for `FileSystemStorageBackend` using JUnit 5 and `@TempDir`.
    - Verified `put`, `get`, `delete` operations.
    - Tested handling of non-existent keys and overwrites.
    - Tested validation against path traversal keys.
    - Tested handling of null/empty inputs.
- **Type-Safe Configuration Loading (Task 9):**
  - Introduced `@ConfigurationProperties` class (`MssmProperties`) for structured access to `mssm.*` settings.
  - Used nested records (`MasterKeyProperties`, `StorageProperties`, `FileSystemProperties`, `AuthProperties`, `StaticTokenAuthProperties`) for organization.
  - Added `spring-boot-starter-validation` dependency.
  - Implemented startup validation (`@Validated`, `@NotBlank`) for required properties (`mssm.master.b64`, `mssm.storage.filesystem.path`).
  - Enabled the properties class via `@EnableConfigurationProperties` in `LiteVaultApplication`.
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
    - Attempts automatic unseal on startup (`@PostConstruct`) using a Base64 encoded AES-256 key provided via the `mssm.master.b64` configuration property (or environment variable).
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
  - Configured `pom.xml` with Java 21, Spring Boot dependencies (Web, Validation, Test), Lombok, and BouncyCastle.
  - Added standard `.gitignore` file.
  - Created basic `src/main/java` and `src/test/java` directory structures.
  - Added placeholder `LiteVaultApplication` and `LiteVaultApplicationTest`.

### Changed
- **API Access:** Most API endpoints (including `/v1/**`) now require authentication via the `X-Vault-Token` header when static token auth is enabled. `/` and `/sys/seal-status` remain public.
- **Configuration Usage:** Refactored `SealManager` and `FileSystemStorageBackend` to inject and use type-safe `MssmProperties` instead of `@Value` or direct property reading.
- **Configuration Structure:** Adjusted `application-dev.yml` to match the structure expected by `MssmProperties` (e.g., `mssm.master.b64` instead of `mssm.master.key.b64`).
- **API Server:** Now runs on HTTPS using the configured port (`8443` in `application-dev.yml`). HTTP is disabled by default when SSL is enabled this way.
- **Encryption Service:**
  - Removed the temporary, hardcoded AES key.
  - Now depends on `SealManager` via constructor injection.
  - Retrieves the master key dynamically using `sealManager.getMasterKey()` before performing encryption or decryption.
  - Propagates `VaultSealedException` if cryptographic operations are attempted while the vault is sealed.
- **Root Controller:**
  - Injected `SealManager` via constructor.

### Fixed
- **Security Config:** Removed an outdated comment regarding null checks and accessor usage in `SecurityConfig.java`.
- **KV Secret Engine:** Corrected the interaction between `FileSystemKVSecretEngine` and `EncryptionService`/`EncryptedData`.
  - `write`: Now correctly splits the `nonce || ciphertext` byte array returned by `EncryptionService.encrypt` into separate `nonce` and `ciphertext` byte arrays before constructing the `EncryptedData` object for storage via `StorageBackend`.
  - `read`: Now correctly retrieves separate `nonce` and `ciphertext` byte arrays from the `EncryptedData` object (via `getNonceBytes`/`getCiphertextBytes`), combines them into the `nonce || ciphertext` format expected by `EncryptionService.decrypt`, and passes the combined array for decryption.
- **Configuration:** Corrected nested record type references (`MssmProperties.AuthProperties.StaticTokenAuthProperties`) in `StaticTokenAuthFilter` and `SecurityConfig`.
- **Testing:** Updated `FileSystemStorageBackendTest` to correctly instantiate `MssmProperties` with the new required `AuthProperties` argument.
- **JSON Serialization:** Added `@JsonIgnore` to `getNonceBytes()` and `getCiphertextBytes()` methods in `EncryptedData` to prevent them from being incorrectly included in the JSON output by Jackson during storage, resolving `UnrecognizedPropertyException` during deserialization.

### Security
- **API Authentication (F-CORE-110):** Implemented basic static token authentication. Requests to protected endpoints (including `/v1/**`) without a valid `X-Vault-Token` will be rejected (typically with HTTP 401/403). Static tokens configured in `mssm.auth.static-tokens.tokens` must be kept secret.
- **Configuration Validation:** Added startup validation for required configuration properties. The application now fails fast if `mssm.master.b64` or `mssm.storage.filesystem.path` are missing or invalid. Also added conditional validation for static tokens.
- **Encryption in Transit:** API communication is now encrypted using TLS 1.2/1.3 (NFR-SEC-110). **Note:** Uses a self-signed certificate suitable only for development/testing.
- **Keystore Password:** The keystore password must be provided via the `MSSM_KEYSTORE_PASSWORD` environment variable at runtime.
- **Master Key Management:** The master encryption key is no longer hardcoded in `EncryptionService`. It is now managed by `SealManager` and loaded into memory only when the vault is unsealed.
- **Initial Unseal:** The initial unseal process relies on the `mssm.master.b64` configuration property (typically set via an environment variable). **Securing this initial key value is critical.** The vault remains sealed if this key is not provided or is invalid. Future work will involve implementing a more robust unseal mechanism (e.g., Shamir's Secret Sharing).

---