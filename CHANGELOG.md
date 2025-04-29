# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Policy Structure Definition (Task 14):**
  - Defined data structures (`PolicyDefinition`, `PolicyRule`, `PolicyCapability`) in `tech.yump.vault.auth.policy` for representing ACLs.
  - Defined `StaticTokenPolicyMapping` record to link tokens to policy names.
  - Added `mssm.policies` section to `MssmProperties` and `application-dev.yml` for defining named policies.
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
  - Implemented `StaticTokenAuthFilter` to read the `X-Vault-Token` header and validate tokens.
  - Implemented `SecurityConfig` using `@EnableWebSecurity` to integrate the filter and define basic authorization rules (public vs. authenticated).
  - Added example static token configuration to `application-dev.yml`.
- **Unit Tests (Task 10):**
  - Implemented unit tests for `EncryptionService` and `FileSystemStorageBackend`.
- **Type-Safe Configuration Loading (Task 9):**
  - Introduced `@ConfigurationProperties` class (`MssmProperties`) for structured access to `mssm.*` settings.
  - Added `spring-boot-starter-validation` and implemented startup validation for required properties.
- **Basic TLS Configuration (Task 8):**
  - Configured `application-dev.yml` to enable HTTPS via `server.ssl.*` properties using a self-signed certificate.
- **Seal Status API Endpoint (Task 7):**
  - Implemented `GET /sys/seal-status` endpoint.
- **Minimal HTTP Server & Routing (Task 6):**
  - Integrated `spring-boot-starter-web`.
  - Implemented `RootController` with `GET /`.
- **Core Seal/Unseal Mechanism (Task 5):**
  - Implemented `SealManager` service and `VaultSealedException`.
  - Added automatic unseal attempt via `mssm.master.b64` property.
- **File System Storage Backend (Task 4):**
  - Defined `StorageBackend` interface.
  - Implemented `FileSystemStorageBackend` using Jackson and storing JSON files.
- **Encrypted Storage Format Definition (Task 3):**
  - Defined `EncryptedData.java` DTO.
- **Core Encryption Service (Task 2):**
  - Implemented `EncryptionService.java` using AES-256-GCM.
- **Project Setup (Task 1):**
  - Initialized project structure with Maven and Spring Boot.

### Changed
- **Static Token Configuration (Task 14):**
  - Updated `mssm.auth.static-tokens` configuration in `MssmProperties` and `application-dev.yml` to use a `mappings` list (`List<StaticTokenPolicyMapping>`) instead of the old `tokens` set. This links tokens directly to a list of policy names.
- **Authentication Filter (Task 14):**
  - Updated `StaticTokenAuthFilter` to read the new `mappings` structure.
  - Upon successful token validation, the filter now extracts the associated policy names and stores them as `GrantedAuthority` objects (prefixed with `POLICY_`) in the `SecurityContext`. This prepares the context for ACL enforcement in Task 15.
- **API Access:** Most API endpoints (including `/v1/**`) now require authentication via the `X-Vault-Token` header when static token auth is enabled. `/` and `/sys/seal-status` remain public.
- **Configuration Usage:** Refactored components to use type-safe `MssmProperties`.
- **Configuration Structure:** Adjusted `application-dev.yml` to match `MssmProperties`.
- **API Server:** Runs on HTTPS.
- **Encryption Service:** Depends on `SealManager` for the master key.

### Fixed
- **Storage Path Traversal Check:** Normalized the `basePath` in `FileSystemStorageBackend` constructor to prevent false positive path traversal errors when comparing against normalized resolved paths.
- **Security Config:** Removed an outdated comment regarding null checks and accessor usage in `SecurityConfig.java`.
- **KV Secret Engine:** Corrected the interaction between `FileSystemKVSecretEngine` and `EncryptionService`/`EncryptedData` regarding nonce/ciphertext handling.
- **Configuration:** Corrected nested record type references in `StaticTokenAuthFilter` and `SecurityConfig` (before Task 14 changes).
- **Testing:** Updated `FileSystemStorageBackendTest` instantiation.
- **JSON Serialization:** Added `@JsonIgnore` to `EncryptedData` byte array getters.

### Removed
- **Custom Token Validator (Task 14):** Removed the custom validation annotation (`@ValidStaticTokenConfig`) and its validator (`StaticTokenConfigValidator`) as standard bean validation (`@NotEmpty`, `@Valid`) on the new `mappings` list provides equivalent checks.

### Security
- **API Authentication (F-CORE-110):** Implemented basic static token authentication. Tokens are now linked to named policies (Task 14), although enforcement is pending (Task 15).
- **Configuration Validation:** Added startup validation for required configuration properties, including token mappings if static auth is enabled.
- **Encryption in Transit:** API communication encrypted using TLS 1.2/1.3 (NFR-SEC-110) via self-signed cert for dev.
- **Keystore Password:** Required via `MSSM_KEYSTORE_PASSWORD` env var.
- **Master Key Management:** Managed by `SealManager`, loaded only when unsealed via `mssm.master.b64`.
- **Initial Unseal:** Relies on `mssm.master.b64` property.

---