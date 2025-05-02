# Minimal Secure Secrets Manager (MSSM) v0.4.0

## Atomic Tasks Roadmap: Phase 4 - JWT Key Rotation

> **Goal:** Implement a secrets engine for managing cryptographic keys used for signing JWTs, including key generation, versioning, and rotation, fulfilling requirements F-JWT-*.

---

### Phase 4 Atomic Tasks (31-40)

#### 31. [x] Implement JWT Secrets Engine Core
- **Description:**
    - Create `JwtSecretsEngine.java` implementing `SecretsEngine` (or a more specific interface if applicable).
    - Add necessary dependencies if any (e.g., libraries for JWT creation like `jjwt`).
    - Implement basic structure, constructor injection for dependencies (`EncryptionService`, `StorageBackend`, configuration).
- **Rationale:**
    - Creates the component responsible for JWT key management.

#### 32. [x] Configure JWT Engine via Properties
- **Description:**
    - Update `MssmProperties` to include configuration for the JWT engine:
        - Define named key configurations (e.g., `mssm.jwt.keys.my_api_key: { type: RSA, size: 2048, rotation_period: "7d" }`).
        - Allow configuration of key type, size/curve, and potentially rotation period (though rotation might be manual initially).
    - Add validation for these properties.
    - Update `application-dev.yml` with example key configurations.
- **Rationale:**
    - Allows defining different keys for different purposes with specific parameters (F-JWT-300).

#### 33. [x] Implement Key Generation and Secure Storage
- **Description:**
    - Implement logic within `JwtSecretsEngine` to generate cryptographic key pairs (e.g., RSA, EC) based on configuration.
    - Encrypt the *private key* using `EncryptionService` before storing it.
    - Store the encrypted private key and the public key using the `StorageBackend`. Use a structured key path (e.g., `jwt/keys/{key_name}/versions/{version_number}`).
- **Rationale:**
    - Securely generates and persists cryptographic keys (F-JWT-300). Ensures private keys are encrypted at rest.

#### 34. [x] Implement Key Versioning Logic
- **Description:**
    - Implement logic to manage multiple versions of a key (e.g., `current`, `next`, `previous`).
    - When a new key is generated (initially or during rotation), assign it a new version number.
    - Store metadata indicating the current signing key version using `StorageBackend` (e.g., at `jwt/keys/{key_name}/config`).
- **Rationale:**
    - Supports graceful key rotation by allowing verification using older keys (F-JWT-310).

#### 35. [x] Implement JWT Signing API Endpoint
- **Description:**
    - Implement a `JwtController` (e.g., under `/v1/jwt`).
    - Create endpoint `POST /sign/{key_name}` that accepts a JSON body containing claims.
    - Inject `JwtSecretsEngine`. Retrieve the *current* signing key version for the specified `key_name`.
    - Decrypt the private key.
    - Sign the provided claims using the private key and appropriate algorithm.
    - Return the generated JWT string.
    - Protect this endpoint using Auth/ACLs.
- **Rationale:**
    - Provides the core functionality of signing JWTs using managed keys (F-JWT-320).

#### 36. [x] Implement JWKS Public Key Endpoint
- **Description:**
    - Create endpoint `GET /jwks/{key_name}` in `JwtController`.
    - Retrieve the *public* keys for the specified `key_name` (e.g., current and possibly previous versions needed for verification).
    - Format the public keys according to the JWK Set (JWKS) standard (RFC 7517).
    - Return the JWKS JSON response. This endpoint is typically public (no auth needed).
- **Rationale:**
    - Allows external services to retrieve public keys for verifying JWT signatures (F-JWT-330).

#### 37. [x] Implement Manual Key Rotation API Endpoint
- **Description:**
    - Create an admin-only endpoint `POST /rotate/{key_name}` in `JwtController`.
    - Trigger the `JwtSecretsEngine` to:
        - Generate a new key pair (Task 33).
        - Store the new key pair with an incremented version number.
        - Update the metadata to mark the new key as the `current` signing key.
        - Potentially mark the previous `current` key as `previous` for a transition period.
    - Protect this endpoint with strict ACLs (admin capability).
- **Rationale:**
    - Allows administrators to trigger key rotation on demand (F-JWT-340).

#### 38. [x] Integrate Audit Logging for JWT Actions
- **Description:**
    - Inject the `AuditBackend`.
    - Log audit events for:
        - Key generation/rotation requests (success/failure, key name, authenticated admin).
        - JWT signing requests (success/failure, key name used, authenticated user).
        - JWKS endpoint access (optional, might be noisy).
- **Rationale:**
    - Provides audit trail for key management and usage (F-CORE-130).

#### 39. [x] Write Unit Tests for JWT Engine
- **Description:**
    - Write unit tests for `JwtSecretsEngine`.
    - Test key generation logic for different types/sizes.
    - Test encryption/decryption of stored private keys (mocking `EncryptionService`).
    - Test key versioning and retrieval logic (mocking `StorageBackend`).
    - Test JWT signing logic (using known keys).
- **Rationale:**
    - Verifies the engine's internal logic for key management and signing.

#### 40. [x] Write Integration Tests for JWT API
- **Description:**
    - Write Spring Boot integration tests (`@SpringBootTest`).
    - Configure JWT keys via properties.
    - Send authenticated requests to `POST /v1/jwt/sign/{key_name}` and verify the resulting JWT structure/signature (using the JWKS endpoint).
    - Send requests to `GET /v1/jwt/jwks/{key_name}` and verify the JWKS structure.
    - Send authenticated admin requests to `POST /v1/jwt/rotate/{key_name}` and verify that the signing key changes and JWKS updates.
    - Test ACL enforcement.
- **Rationale:**
    - Validates the end-to-end flow for JWT signing, verification key retrieval, and rotation.

---

## Result After Phase 4 Completion

- A functional secrets engine for managing JWT signing keys is implemented.
- Applications can request JWTs signed with centrally managed, versioned keys.
- External services can retrieve public keys via a standard JWKS endpoint for verification.
- Administrators can manually trigger key rotation via an API.
- Key management and usage events are audited.
- Unit and integration tests validate the engine and API.

---

## Suggested Improvements for Next Steps (Phase 5 / v0.5.0)

- **Polish & Hardening:** Focus on stability, comprehensive testing, and documentation for v1.0.0.
- **Lease Revocation/Renewal:** Implement robust revocation and renewal for DB leases.
- **Audit Logging Enhancements:** Implement a more durable audit backend.
- **Performance Testing:** Establish baseline performance metrics.

---