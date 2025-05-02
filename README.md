# Minimal Secure Secrets Manager (MSSM) - LiteVault

**Version:** 0.4.0 # Updated version

A minimal implementation of a secure secrets manager inspired by HashiCorp Vault, focusing on core security primitives and essential features like dynamic secrets and key rotation. Built with Java 21 and Spring Boot.

## Project Goal

To provide a secure, centralized system for managing dynamic database credentials, JWT key rotation, and secure storage of static secrets (like password peppers), reducing risks associated with hardcoded or statically managed sensitive information.

*(Keep Introduction, Scope, etc. if you have them)*

## Current Status & Features (As of v0.4.0)

- **Project Setup:** Maven project initialized with Java 21 and Spring Boot. Basic directory structure and `.gitignore` in place.
- **Dependencies:** Includes Spring Boot starters for Web, Validation, Security, JDBC, Test. Includes Lombok, BouncyCastle, Jackson Datatype JSR310, PostgreSQL driver, and JWT libraries (`jjwt`, `nimbus-jose-jwt`).
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
    - `PUT /v1/kv/data/{path}`: Write/update secrets (JSON body `{ "key": "value", ... }`). Requires authentication and authorization.
    - `GET /v1/kv/data/{path}`: Read secrets (returns JSON map or 404). Requires authentication and authorization.
    - `DELETE /v1/kv/data/{path}`: Delete secrets. Requires authentication and authorization.
  - **Implemented (DB v1 - PostgreSQL):** Endpoint for generating dynamic database credentials (Task 27):
    - `GET /v1/db/creds/{roleName}`: Request new, temporary credentials for a configured PostgreSQL role. Requires authentication and authorization (`READ` capability on `db/creds/{roleName}`). Returns a JSON response (`DbCredentialsResponse`) containing the generated `username`, `password`, `leaseId`, and `leaseDurationSeconds`.
+ - **Implemented (JWT v1):** Endpoints for managing and using JWT signing keys (Tasks 35, 36, 37):
+   - `POST /v1/jwt/sign/{keyName}`: Sign a JWT using the current version of the specified key. Requires authentication and authorization (`WRITE` capability on `jwt/sign/{keyName}`). Accepts JSON claims, returns signed JWT.
+   - `GET /v1/jwt/jwks/{keyName}`: Retrieve the public keys (JWK Set) for the specified key name. Publicly accessible.
+   - `POST /v1/jwt/rotate/{keyName}`: Manually trigger rotation for the specified key. Requires authentication and authorization (`WRITE` capability on `jwt/rotate/{keyName}`).
- **Authentication/Authorization:**
  - **Implemented (Basic Auth):** Static Token Authentication (Task 11). API requests (except `/`, `/sys/seal-status`, `/v1/jwt/jwks/**`) require a valid `X-Vault-Token` header.
  - **Defined (Policy Structure - Task 14):**
    - Data structures for policies (`PolicyDefinition`, `PolicyRule`, `PolicyCapability`) are defined.
    - Static tokens are now linked to one or more named policies via configuration (`mssm.auth.static-tokens.mappings` and `mssm.policies`).
    - The authentication filter (`StaticTokenAuthFilter`) now identifies the policies associated with a valid token and stores them (as authorities like `POLICY_kv-reader`) in the security context.
  - **Implemented (ACL Enforcement - Task 15):**
    - A new `PolicyEnforcementFilter` runs after authentication.
    - It uses the policies associated with the authenticated token (identified by the `POLICY_` authorities) to check if the request (HTTP method + path) is permitted.
    - It consults the `PolicyRepository` (which loads policies from configuration) and evaluates the rules based on path (prefix/wildcard match) and required capability (READ, WRITE, DELETE).
    - Access is denied with HTTP 403 Forbidden if no matching policy rule grants the necessary capability.
    - **Fixed:** Path matching logic for wildcards (`/*`) now correctly evaluates policies.
- **Secrets Engines:**
  - **Defined (Core Interfaces - Task 21):**
    - Foundational interfaces (`SecretsEngine`, `DynamicSecretsEngine`) and data structures (`Lease` record) have been defined to establish a common contract for all secrets engines.
    - This prepares the architecture for implementing dynamic secrets engines (e.g., PostgreSQL) alongside the existing static KV engine.
    - Base exception classes for secrets engines (`SecretsEngineException`, etc.) were also added.
  - **Implemented (KV v1):** A static Key/Value secrets engine (`FileSystemKVSecretEngine`) is implemented. It stores arbitrary key-value pairs at logical paths, encrypting the entire map as a single blob before persisting it using the configured `StorageBackend`. (Task 12)
    - **Updated (Task 21):** The `KVSecretEngine` interface now implements the base `SecretsEngine` interface for consistency.
  - **Implemented (PostgreSQL Core - Task 22, 24, 25 & 26):**
    - Added the basic structure (`PostgresSecretsEngine.java` in `tech.yump.vault.secrets.db`) for the dynamic PostgreSQL secrets engine. Implements `DynamicSecretsEngine`.
    - Includes necessary JDBC dependencies (`postgresql`, `spring-boot-starter-jdbc`).
    - **Connection Management (Task 24):** Configured connection management using Spring Boot's primary `DataSource` (auto-configured via `spring.datasource.*` properties in `application-dev.yml`, which reference `mssm.secrets.db.postgres.*`) and injected the auto-configured `JdbcTemplate`. Includes a startup check (`@PostConstruct`) to verify target DB connection.
    - **Credential Generation (Task 25):** Implemented the core logic in `generateCredentials` to look up role configurations, generate unique usernames/passwords, execute configured SQL creation statements against the target database using `JdbcTemplate`, and create a `Lease` object containing the generated credentials and metadata. Includes error handling and avoids logging passwords.
    - **Lease Management & Revocation (Task 26):** Implemented basic in-memory lease tracking using a `ConcurrentHashMap`. Leases are stored upon generation. The `revokeLease` method is now implemented to look up the lease, retrieve the username, prepare and execute the configured SQL `revocationStatements` against the target database using `JdbcTemplate`, and remove the lease from tracking upon successful revocation. Includes error handling for missing leases/roles and DB errors.
+ - **Implemented (JWT v1 - Tasks 31, 33, 34):**
+   - Added `JwtSecretsEngine.java` in `tech.yump.vault.secrets.jwt` implementing `SecretsEngine`.
+   - Implements generation and secure storage of RSA and EC key pairs based on configuration.
+   - Private keys are encrypted using `EncryptionService` before being stored via `StorageBackend`.
+   - Manages key versions, storing metadata about the current signing version.
- **Auditing:**
  - **Implemented (Task 16 & 17):** Audit logging is integrated into the API flow. The `LogAuditBackend` logs structured JSON events via SLF4j for authentication attempts (`StaticTokenAuthFilter`), authorization decisions (`PolicyEnforcementFilter`), and KV operations (`KVController`). Events include timestamp, principal, source IP, request ID, outcome, and relevant metadata. Sensitive data (e.g., secret values) is excluded.
  - **(Task 28):** Audit logging now also covers dynamic PostgreSQL credential operations:
    - Credential generation requests (`GET /v1/db/creds/{roleName}`) log success (with lease ID, role) or failure (with role, error).
    - Internal lease creation events are logged by the engine upon success.
    - Lease revocation attempts (internal engine logic) log success or failure (with lease ID, error).
    - Generated passwords are **never** logged.
+ - **(Task 38):** Audit logging now also covers JWT operations:
+   - Key generation/rotation requests (`POST /v1/jwt/rotate/{keyName}`) log success or failure (with key name, versions).
+   - JWT signing requests (`POST /v1/jwt/sign/{keyName}`) log success or failure (with key name, version).
+   - JWKS endpoint access (`GET /v1/jwt/jwks/{keyName}`) logs success or failure.
- **Configuration:**
  - **Implemented:** Type-safe configuration loading using `@ConfigurationProperties` (`MssmProperties`) with startup validation for required `mssm.*` settings.
  - **Implemented:** Configuration for static authentication tokens (`mssm.auth.static-tokens`) now uses a `mappings` list to link tokens to policy names (`StaticTokenPolicyMapping`). Conditional validation ensures mappings exist if auth is enabled. (Task 14)
  - **Implemented:** Configuration section `mssm.policies` for defining named policies and their rules (`PolicyDefinition`, `PolicyRule`). (Task 14)
  - **Implemented (PostgreSQL - Task 23):** Added configuration structure under `mssm.secrets.db.postgres` in `MssmProperties` and `application-dev.yml`. This allows configuring:
    - Connection details (URL, admin username, admin password) for LiteVault to connect to the target PostgreSQL database. **The admin password should be provided securely, e.g., via the `MSSM_DB_POSTGRES_PASSWORD` environment variable.**
    - Role definitions (a map of logical role names to SQL `creationStatements`, `revocationStatements` using `{{username}}`/`{{password}}` placeholders, and a `defaultTtl`).
    - Includes validation for these properties. See `application-dev.yml` for examples.
  - **Implemented (DataSource - Task 24):** Added standard `spring.datasource.*` properties in `application-dev.yml` to configure the primary DataSource (connection pool) used by the PostgreSQL engine, referencing the `mssm.secrets.db.postgres.*` values.
+ - **Implemented (JWT - Task 32):** Added configuration structure under `mssm.secrets.jwt.keys` in `MssmProperties` and `application-dev.yml`. Allows defining named keys with type (RSA/EC), size/curve, and optional rotation period. Includes validation.
- **Testing:**
  - **Implemented:** Unit tests for `EncryptionService` and `FileSystemStorageBackend` covering core functionality, edge cases, and error handling.
  - **Implemented:** Unit tests for `StaticTokenAuthFilter` and `PolicyEnforcementFilter` verifying authentication logic and basic ACL enforcement decisions. (Task 19)
+ - **Implemented (Task 39):** Unit tests for `JwtSecretsEngine` covering key generation, storage, versioning, and signing logic.
- **Implemented:** Integration tests (`KVControllerIntegrationTest.java`) using `@SpringBootTest` and `MockMvc` to verify the end-to-end functionality of the KV API (`/v1/kv/data/**`). These tests validate authentication, authorization (policy enforcement), CRUD operations, and behavior when the vault is sealed, ensuring components work together correctly. (Task 20)
+ - **Implemented (Task 40):** Integration tests (`JwtControllerIntegrationTest.java`, `JwtControllerAuthorizationTest.java`) using `@SpringBootTest` and `MockMvc` to verify the end-to-end functionality of the JWT API (`/v1/jwt/**`). Tests validate signing, JWKS retrieval, rotation, authentication, authorization, and error handling.
- **Fixed:** Resolved failures in `PolicyEnforcementFilterTest` related to Mockito stubbing and assertions.
- **Fixed (Task 24):** Corrected `MssmProperties` instantiation in `FileSystemStorageBackendTest` to align with recent configuration changes.
- **Updated:** `lite-vault-cli.sh` script enhanced to test policy enforcement scenarios.

## Security Considerations

- **Encryption at Rest:** Core data is encrypted using AES-256-GCM (`EncryptionService`) and stored persistently as JSON files via the `FileSystemStorageBackend` (NFR-SEC-100, F-CORE-100). Encryption requires the vault to be unsealed. KV secrets and **JWT private keys** are stored using this mechanism.
- **Encryption in Transit:** **Implemented (Basic):** API communication secured via TLS 1.2+ using a self-signed certificate (NFR-SEC-110). **Note:** This self-signed certificate is suitable only for local development and testing. Production deployments require a certificate signed by a trusted Certificate Authority (CA).
- **Keystore Security:** The password for the development keystore (`litevault-keystore.p12`) must be provided via the `MSSM_KEYSTORE_PASSWORD` environment variable at runtime.
- **Sealing:** The master encryption key will not be persisted directly. An unseal mechanism will be required to load the key into memory (F-CORE-140).
  - **Implemented:** The core `SealManager` controls the loading/unloading of the master key into memory. The vault starts sealed and blocks crypto operations.
  - **Initial Unseal:** Currently relies on providing the master key via the `mssm.master.b64` configuration property (e.g., environment variable) for automatic unseal on startup. **Securing this initial key value is critical.**
- **Authentication:** API access (including `/v1/kv/data/**`, `/v1/db/creds/**`, `/v1/jwt/sign/**`, `/v1/jwt/rotate/**`) is protected by static tokens when enabled (`mssm.auth.static-tokens.enabled=true`). Clients must provide a valid token in the `X-Vault-Token` header. These tokens are now linked to named policies defined in the configuration (`mssm.policies` and `mssm.auth.static-tokens.mappings`). The `/v1/jwt/jwks/**` endpoint is public. (Task 11, Task 14)
- **Authorization:** **Implemented (F-CORE-120):** Basic Access Control List (ACL) enforcement is implemented via the `PolicyEnforcementFilter` (Task 15). After successful authentication, this filter checks if the policies associated with the token grant the required capability (e.g., READ, WRITE, DELETE based on HTTP method) for the requested API path. Path matching logic, including wildcards (`/*`), is now correctly implemented, ensuring policies work as intended. If access is not explicitly granted by a policy rule, the request is denied with a 403 Forbidden status. Specific policies are required for JWT signing (`jwt/sign/*`) and rotation (`jwt/rotate/*`).
- **Auditing:** **Implemented (F-CORE-130):**
  - Audit events are now logged for authentication attempts, authorization decisions, and KV operations via the `LogAuditBackend` (Task 16, Task 17). Events are structured JSON including timestamp, principal, source IP, request ID, outcome, and relevant metadata. Sensitive data (e.g., secret values) is excluded.
  - **(Task 28):** Audit logging now also covers dynamic PostgreSQL credential operations:
    - Credential generation requests (`GET /v1/db/creds/{roleName}`) log success (with lease ID, role) or failure (with role, error).
    - Internal lease creation events are logged by the engine upon success.
    - Lease revocation attempts (internal engine logic) log success or failure (with lease ID, error).
    - Generated passwords are **never** logged.
+ - **(Task 38):** Audit logging now also covers JWT operations:
+   - Key generation/rotation requests (`POST /v1/jwt/rotate/{keyName}`) log success or failure (with key name, versions).
+   - JWT signing requests (`POST /v1/jwt/sign/{keyName}`) log success or failure (with key name, version).
+   - JWKS endpoint access (`GET /v1/jwt/jwks/{keyName}`) logs success or failure.
- **Configuration Validation:** The application performs validation on required configuration properties at startup (e.g., master key, storage path, token mappings if enabled, DB connection details if configured, JWT key definitions) and will fail to start if they are missing or invalid.
- **Database Admin Credentials:** **(Task 23)** The PostgreSQL secrets engine requires credentials (`mssm.secrets.db.postgres.username` and `password`) for a user in the *target* database with privileges to manage roles (CREATE/DROP ROLE, GRANT). **The password (`mssm.secrets.db.postgres.password`) is highly sensitive and must NOT be hardcoded in configuration files for production.** Use environment variables (e.g., `MSSM_DB_POSTGRES_PASSWORD`) or other secure injection methods. This password is also used for the primary `spring.datasource` configuration (Task 24).
- **Password Security:** **(Task 25)** Dynamically generated database passwords are created using `java.security.SecureRandom` and are **not logged** by LiteVault. They are returned within the `Lease` object to the requesting client via the API (Task 27).
- **Lease Revocation:** **(Task 26)** The `revokeLease` implementation attempts to execute configured SQL statements (e.g., `DROP ROLE`) in the target database to clean up credentials. Successful revocation depends on correctly configured `revocationStatements` and sufficient privileges for the admin user LiteVault connects with. If revocation fails (e.g., DB error), the lease remains tracked internally, but the credential might persist in the database. *(Note: An API endpoint for revocation is not part of Task 27 but may be added later or for testing)*.
- **Testing:** Unit tests cover core components like encryption, storage, authentication, authorization logic, and secrets engines (KV, JWT). Integration tests (Task 20, Task 40) validate the KV and JWT APIs end-to-end, ensuring authentication, authorization, and the secrets engines work together correctly. *(Note: DB API integration tests are planned for a future version)*.

## Getting Started

*(Instructions for building/running will go here later)*

**Running (with Auto-Unseal):**
1.  **Generate Keystore (if not present):** Run the `generate-keystore.sh` script (or `key-gen.sh` if not renamed) from the project root (or use the `keytool` command directly) to create `src/main/resources/litevault-keystore.p12` (or `dev-keystore.p12` if using the parameterized script defaults).
2.  **Set Keystore Password:** Set the environment variable `MSSM_KEYSTORE_PASSWORD` to match the password used when generating the keystore.
3.  **Set Master Key:** Securely generate a Base64 encoded AES-256 key and set the environment variable `MSSM_MASTER_B64`. Example (Linux/macOS): `export MSSM_MASTER_B64=$(openssl rand -base64 32)`
4.  **Configure Target Database (for DB Secrets Engine):**
*   Ensure you have a target PostgreSQL database running.
*   Update the `mssm.secrets.db.postgres.connection-url` (and consequently `spring.datasource.url`) in `application-dev.yml` to point to your database.
*   Create a user in the target database that LiteVault can use to manage roles (e.g., `litevault_admin`). This user needs `CREATE ROLE`, `DROP ROLE`, and relevant `GRANT` privileges.
*   Update `mssm.secrets.db.postgres.username` (and `spring.datasource.username`) in `application-dev.yml` to this user.
*   **Set the password for this database user securely** via the environment variable `MSSM_DB_POSTGRES_PASSWORD`. Example: `export MSSM_DB_POSTGRES_PASSWORD='your_db_admin_password'`
*   Review and adjust the example SQL statements under `mssm.secrets.db.postgres.roles` in `application-dev.yml` to match your database schema and desired permissions. Ensure the `creationStatements` (using `{{username}}`/`{{password}}`) and `revocationStatements` (using `{{username}}`) are correct for your environment.
5.  **Configure JWT Keys (for JWT Secrets Engine):**
*   Review and adjust the example key definitions under `mssm.secrets.jwt.keys` in `application-dev.yml` (e.g., `api-signing-key-rsa`, `api-signing-key-ec`).
6.  **Configure Policies and Static Tokens:**
*   Ensure `mssm.auth.static-tokens.enabled=true` in `application.yml` or `application-dev.yml`.
*   Define desired access policies under the `mssm.policies:` section. Ensure policies exist for accessing dynamic DB secrets (e.g., `path: "db/creds/*"` with `READ`), JWT signing (e.g., `path: "jwt/sign/*"` with `WRITE`), and JWT rotation (e.g., `path: "jwt/rotate/*"` with `WRITE`).
*   Define token-to-policy mappings under `mssm.auth.static-tokens.mappings:`. Example configuration is present in `application-dev.yml`.
7.  **Build:** `mvn clean package`
8.  **Run:** `java -jar target/lite-vault-*.jar` (Use the actual JAR name generated in the `target` directory)
9.  **Verify Connection (Task 24):** Check the application startup logs for messages indicating successful connection to the target PostgreSQL database (e.g., `Successfully established connection...` from `PostgresSecretsEngine`). Also check for HikariCP pool startup messages.

The server should start on `https://localhost:8443`. You can test API endpoints using `curl` or the provided `lite-vault-cli.sh` script (remember to use `-k` for the self-signed certificate and provide the `X-Vault-Token` header).

## API Documentation

This project uses `springdoc-openapi` to generate interactive API documentation using the OpenAPI v3 specification.

Once the application is running (e.g., using the `dev` profile):

*   **Swagger UI:** https://localhost:8443/swagger-ui.html
  *   Provides a web interface to browse, understand, and test the API endpoints.
  *   For protected endpoints, use the "Authorize" button (top right) and provide a valid `X-Vault-Token` (e.g., from `application-dev.yml`).
*   **OpenAPI Spec (JSON):** https://localhost:8443/v3/api-docs
  *   The raw OpenAPI specification in JSON format.
*   **OpenAPI Spec (YAML):** https://localhost:8443/v3/api-docs.yaml
  *   The raw OpenAPI specification in YAML format.

*(Note: URLs assume the application is running locally with the `dev` profile configuration: HTTPS on port 8443. Adjust if necessary.)*


**Example API Calls:**
*   **KV Read:** `curl -k -H "X-Vault-Token: {token}" https://localhost:8443/v1/kv/data/path/to/secret`
*   **DB Credential Generation:** `curl -k -H "X-Vault-Token: {token}" https://localhost:8443/v1/db/creds/{role_name}`
+ *   **JWT Sign:** `curl -k -X POST -H "X-Vault-Token: {signing_token}" -H "Content-Type: application/json" -d '{"sub":"user123", "scope":"read"}' https://localhost:8443/v1/jwt/sign/{key_name}`
+ *   **JWKS Get:** `curl -k https://localhost:8443/v1/jwt/jwks/{key_name}`
+ *   **JWT Rotate:** `curl -k -X POST -H "X-Vault-Token: {admin_token}" https://localhost:8443/v1/jwt/rotate/{key_name}`