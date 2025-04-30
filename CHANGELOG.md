# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Integrate Audit Logging into API Flow (Task 17):**
  - Injected `AuditBackend` into `StaticTokenAuthFilter`, `PolicyEnforcementFilter`, and `KVController`.
  - Audit events are now logged (as JSON via `LogAuditBackend`) for:
    - Authentication attempts (success/failure) in `StaticTokenAuthFilter`.
    - Authorization decisions (granted/denied) in `PolicyEnforcementFilter`.
    - KV operations (read/write/delete success/failure/not found) in `KVController` and its exception handlers.
  - Added a unique request ID to each request (via `StaticTokenAuthFilter`) and included it in audit events for correlation.
  - This fulfills the requirement for recording security-relevant events (F-CORE-130).
- **Basic Audit Logging Backend (Task 16):**
  - Defined `AuditEvent` record structure to represent audit log entries (timestamp, type, action, outcome, auth, request, response, data). Includes nested records for `AuthInfo`, `RequestInfo`, `ResponseInfo`.
  - Defined `AuditBackend` interface with a `logEvent(AuditEvent event)` method.
  - Implemented `LogAuditBackend` service using SLF4j. This implementation serializes `AuditEvent` objects to JSON and logs them at the INFO level with an "AUDIT_EVENT:" prefix.
  - Added Jackson `JavaTimeModule` for correct `Instant` serialization.
  - This provides the foundational mechanism for recording security-relevant events (F-CORE-130).
- **Basic ACL Enforcement (Task 15):**
  - Implemented `PolicyRepository` to load and cache policy definitions from configuration.
  - Created `PolicyEnforcementFilter` which runs after `StaticTokenAuthFilter`.
  - The filter retrieves the authenticated token's associated policy names (via `POLICY_` authorities).
  - It loads the corresponding `PolicyDefinition`s from the `PolicyRepository`.
  - It checks if any rule within the user's policies grants the required capability (READ, WRITE, DELETE based on HTTP method) for the requested API path (using basic prefix/wildcard matching).
  - If access is not granted by any policy rule, the filter returns a 403 Forbidden response.
  - Integrated the `PolicyEnforcementFilter` into `SecurityConfig`.
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
- **Unit Tests (Task 10, Task 19):**
  - Implemented unit tests for `EncryptionService` and `FileSystemStorageBackend`.
  - Implemented unit tests for `StaticTokenAuthFilter` and `PolicyEnforcementFilter`.
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
- **Security Configuration:** `SecurityConfig` now includes `PolicyEnforcementFilter` in the filter chain, placed after `StaticTokenAuthFilter`.
- **Static Token Configuration (Task 14):**
  - Updated `mssm.auth.static-tokens` configuration in `MssmProperties` and `application-dev.yml` to use a `mappings` list (`List<StaticTokenPolicyMapping>`) instead of the old `tokens` set. This links tokens directly to a list of policy names.
- **Authentication Filter (Task 14):**
  - Updated `StaticTokenAuthFilter` to read the new `mappings` structure.
  - Upon successful token validation, the filter now extracts the associated policy names and stores them as `GrantedAuthority` objects (prefixed with `POLICY_`) in the `SecurityContext`. This prepares the context for ACL enforcement in Task 15.
- **API Access:** Most API endpoints (including `/v1/**`) now require authentication via the `X-Vault-Token` header when static token auth is enabled. `/` and `/sys/seal-status` remain public. Access to authenticated endpoints is now further restricted by ACL policies (Task 15).
- **Configuration Usage:** Refactored components to use type-safe `MssmProperties`.
- **Configuration Structure:** Adjusted `application-dev.yml` to match `MssmProperties`.
- **API Server:** Runs on HTTPS.
- **Encryption Service:** Depends on `SealManager` for the master key.
- **Testing:** Updated `lite-vault-cli.sh` to include tests specifically for policy enforcement scenarios using different tokens.

### Fixed
- **Testing:** Fixed test failures in `PolicyEnforcementFilterTest` related to Mockito `UnnecessaryStubbingException` errors (by using `lenient()`) and an incorrect assertion comparing empty lists.
- **Policy Path Matching:** Corrected the wildcard (`/*`) matching logic in `PolicyEnforcementFilter.pathMatches` to correctly handle paths like `kv/data/myapp/config` when the policy path is `kv/data/*`. (Fixes incorrect denials for root/wildcard policies).
- **JSON Serialization (Instant):** Corrected `ObjectMapper` usage in `PolicyEnforcementFilter` by injecting the Spring-managed bean instead of creating a new one, ensuring the `JavaTimeModule` (for `java.time.Instant`) is registered and preventing `InvalidDefinitionException` when generating 403 error responses.
- **Configuration Binding:** Corrected structure in `application-dev.yml` under `mssm.policies` to prevent `ConverterNotFoundException` during startup (removed incomplete entry, fixed rule structure).
- **Configuration Consistency:** Ensured policy names referenced in `mssm.auth.static-tokens.mappings` match those defined in `mssm.policies` in `application-dev.yml`.
- **Storage Path Traversal Check:** Normalized the `basePath` in `FileSystemStorageBackend` constructor to prevent false positive path traversal errors when comparing against normalized resolved paths.
- **Security Config:** Removed an outdated comment regarding null checks and accessor usage in `SecurityConfig.java`.
- **KV Secret Engine:** Corrected the interaction between `FileSystemKVSecretEngine` and `EncryptionService`/`EncryptedData` regarding nonce/ciphertext handling.
- **Configuration:** Corrected nested record type references in `StaticTokenAuthFilter` and `SecurityConfig` (before Task 14 changes).
- **Testing:** Updated `FileSystemStorageBackendTest` instantiation.
- **JSON Serialization:** Added `@JsonIgnore` to `EncryptedData` byte array getters.

### Removed
- **Custom Token Validator (Task 14):** Removed the custom validation annotation (`@ValidStaticTokenConfig`) and its validator (`StaticTokenConfigValidator`) as standard bean validation (`@NotEmpty`, `@Valid`) on the new `mappings` list provides equivalent checks.

### Security
- **Audit Logging (F-CORE-130):** **Implemented.** Audit events are now logged for authentication attempts, authorization decisions, and KV operations via the `LogAuditBackend` (Task 16, Task 17). Events are structured JSON including timestamp, principal, source IP, request details, outcome, and relevant metadata. Sensitive data (e.g., secret values) is excluded.
- **Authorization (F-CORE-120):** Implemented basic ACL enforcement (Task 15). Access to API endpoints (like `/v1/kv/data/**`) is now controlled by policies defined in the configuration (`mssm.policies`) and linked to static tokens (`mssm.auth.static-tokens.mappings`). The `PolicyEnforcementFilter` denies access (403 Forbidden) if no applicable policy rule grants the required capability (READ, WRITE, DELETE) for the requested path. Path matching logic, including wildcards, is now correctly implemented.
- **API Authentication (F-CORE-110):** Implemented basic static token authentication. Tokens are now linked to named policies (Task 14), and these policies are enforced (Task 15).
- **Configuration Validation:** Added startup validation for required configuration properties, including token mappings if static auth is enabled.
- **Encryption in Transit:** API communication encrypted using TLS 1.2/1.3 (NFR-SEC-110) via self-signed cert for dev.
- **Keystore Password:** Required via `MSSM_KEYSTORE_PASSWORD` env var.
- **Master Key Management:** Managed by `SealManager`, loaded only when unsealed via `mssm.master.b64`.
- **Initial Unseal:** Relies on `mssm.master.b64` property.

---