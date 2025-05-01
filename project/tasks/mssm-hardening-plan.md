Okay, here is the implementation plan for the JWT Secrets Engine testing strategy, formatted using Markdown:

# Implementation Plan for JWT Secrets Engine Testing Strategy

Okay, let's break down the implementation of the `mssm-jwt-testing-strategy.md` into atomic tasks, considering the existing code structure.

## Overall Approach:

1.  **Configuration Tests:** Verify and potentially enhance existing tests.
2.  **JWKS Implementation:** Implement the missing JWKS logic in the engine and controller.
3.  **Unit Tests:** Create `JwtSecretsEngineTest.java` and implement tests method-by-method, mocking dependencies.
4.  **Integration Test Setup:** Prepare the test environment (`application-test.yml`, base test class).
5.  **Integration Tests:** Implement the lifecycle scenarios, security, and error handling tests.

## Phase 1: Configuration Validation (Review & Enhance)

* **Task 1.1:** **Review `ConfigurationValidationTest.java`**. Compare existing JWT-related tests against all scenarios listed in `mssm-jwt-testing-strategy.md` under "Configuration Validation Tests".
* **Task 1.2:** **Add missing test cases** to `ConfigurationValidationTest.java` for any JWT configuration scenarios not currently covered (if any identified in Task 1.1).
* **Task 1.3:** **Ensure existing JWT validation tests have specific assertions** matching the expected validation error messages as defined in `MssmProperties.java` record constraints.

## Phase 2: JWKS Endpoint Implementation

* **Task 2.1:** **Implement the public key reconstruction logic** (e.g., a `reconstructPublicKey` helper method) within `JwtSecretsEngine.java` using `X509EncodedKeySpec`.
* **Task 2.2:** **Implement the `getJsonWebKeySet`** (or similar name like `getJwks`) method logic within `JwtSecretsEngine.java`.
    * Read key config.
    * Determine which versions to include (e.g., current, maybe previous N versions or based on a time window - **Decision:** Start with just current, then enhance to include previous if needed).
    * Loop through relevant versions:
        * Call `getStoredKeyMaterial`.
        * Decode public key Base64 string.
        * Call `reconstructPublicKey`.
        * Convert the `PublicKey` object into a JWK Map structure (RFC 7517). This requires mapping fields based on key type (RSA: `kty`, `use`, `kid`, `alg`, `n`, `e`; EC: `kty`, `use`, `kid`, `alg`, `crv`, `x`, `y`). Use a library like `nimbus-jose-jwt` or implement manually.
        * Assign `kid` (e.g., `{keyName}-{version}`).
        * Assign `alg` based on type/curve/size.
        * Assemble the list of JWK maps into the final JWK Set structure: `{"keys": [...]}`.
    * Handle errors gracefully (e.g., skip a version if its material is missing/corrupt).
    * Add internal audit logging for JWKS retrieval success/failure within the engine method.
* **Task 2.3:** **Add a `GET /v1/jwt/jwks/{keyName}` endpoint** to `JwtController.java`.
    * This endpoint should call the `jwtSecretsEngine.getJwks(keyName)` method.
    * Return the resulting JWK Set Map as JSON with a 200 OK status.
    * Ensure this endpoint does not require authentication (typically public).
    * Add appropriate exception handlers in the controller (or ensure existing ones cover `getJwks` calls) for `JwtKeyNotFoundException`, `VaultSealedException`, `SecretsEngineException`.
    * Add HTTP-level audit logging for the JWKS endpoint access in the controller.

## Phase 3: Unit Tests (`JwtSecretsEngineTest.java`)

* **Task 3.1:** **Setup**
    * Create `JwtSecretsEngineTest.java`.
    * Add Mockito and JUnit 5 dependencies.
    * Define mocks using `@Mock`: `MssmProperties`, `EncryptionService`, `StorageBackend`, `SealManager`, `AuditHelper`, `ObjectMapper`.
    * Inject mocks into the test subject using `@InjectMocks`: `JwtSecretsEngine`.
    * Set up basic mock behaviors in a `@BeforeEach` (e.g., `when(sealManager.isSealed()).thenReturn(false);`).
* **Task 3.2:** **`generateAndStoreKeyPair` Tests**
    * Test successful RSA key generation: Mock properties to return RSA config, **verify** `KeyPairGenerator` params, `encryptionService.encrypt` calls (private key, bundle), `storageBackend.put` call (path, data structure), `auditHelper.logInternalEvent` call.
    * Test successful EC key generation: Mock properties to return EC config, **verify** `KeyPairGenerator` params, `encryptionService.encrypt` calls, `storageBackend.put` call, `auditHelper.logInternalEvent` call.
    * Test `VaultSealedException`: Mock `sealManager.isSealed()` to return `true`, **assert** exception.
    * Test `EncryptionException` propagation: Mock `encryptionService.encrypt` to throw, **assert** `SecretsEngineException`.
    * Test `StorageException` propagation: Mock `storageBackend.put` to throw, **assert** `SecretsEngineException`.
    * Test `JsonProcessingException` propagation: Mock `objectMapper.writeValueAsBytes` to throw, **assert** `SecretsEngineException`.
    * **(Optional/Difficult)** Test private key byte clearing (may require advanced mocking or reflection, potentially skip).
* **Task 3.3:** **`readKeyConfig`/`writeKeyConfig` Tests**
    * Test `readKeyConfig` success: Mock `storageBackend.get` returning valid `EncryptedData`, mock `encryptionService.decrypt`, mock `objectMapper.readValue`, **verify** result.
    * Test `readKeyConfig` not found: Mock `storageBackend.get` returning `Optional.empty()`, **verify** `Optional.empty()` result.
    * Test `readKeyConfig` exceptions: Mock underlying methods (`get`, `decrypt`, `readValue`) to throw `StorageException`, `VaultSealedException`, `EncryptionException`, `IOException`, **assert** `SecretsEngineException` or `VaultSealedException`.
    * Test `writeKeyConfig` success: Mock `objectMapper.writeValueAsBytes`, `encryptionService.encrypt`, `storageBackend.put`, **verify** `put` args and `auditHelper.logInternalEvent` call.
    * Test `writeKeyConfig` exceptions: Mock underlying methods (`writeValueAsBytes`, `encrypt`, `put`) to throw `JsonProcessingException`, `VaultSealedException`, `EncryptionException`, `StorageException`, **assert** `SecretsEngineException` or `VaultSealedException`.
* **Task 3.4:** **`getStoredKeyMaterial` Tests**
    * Test success: Mock `storageBackend.get` returning valid `EncryptedData`, mock `encryptionService.decrypt`, mock `objectMapper.readValue`, **verify** result.
    * Test not found: Mock `storageBackend.get` returning `Optional.empty()`, **assert** `JwtKeyNotFoundException`.
    * Test exceptions: Mock underlying methods (`get`, `decrypt`, `readValue`) to throw `StorageException`, `VaultSealedException`, `EncryptionException`, `IOException`, **assert** `SecretsEngineException` or `VaultSealedException`.
* **Task 3.5:** **`reconstructPrivateKey`/`reconstructPublicKey` Tests**
    * Test `reconstructPrivateKey` RSA: Provide valid PKCS8 bytes, **verify** `KeyFactory.getInstance("RSA")` and `generatePrivate` called.
    * Test `reconstructPrivateKey` EC: Provide valid PKCS8 bytes, **verify** `KeyFactory.getInstance("EC")` and `generatePrivate` called.
    * Test `reconstructPrivateKey` throws `SecretsEngineException` on `InvalidKeySpecException`.
    * Test `reconstructPublicKey` RSA: Provide valid X509 bytes, **verify** `KeyFactory.getInstance("RSA")` and `generatePublic` called. (Requires Task 2.1 done).
    * Test `reconstructPublicKey` EC: Provide valid X509 bytes, **verify** `KeyFactory.getInstance("EC")` and `generatePublic` called. (Requires Task 2.1 done).
    * Test `reconstructPublicKey` throws `SecretsEngineException` on `InvalidKeySpecException`. (Requires Task 2.1 done).
* **Task 3.6:** **`signJwt` Tests**
    * Test success: Mock `readKeyConfig`, `getStoredKeyMaterial`, `encryptionService.decrypt` (for private key), `reconstructPrivateKey`. **Verify** `Jwts.builder().signWith()` is called with the correct key. **Verify** `auditHelper.logInternalEvent` (success).
    * Test `JwtKeyNotFoundException` (config missing): Mock `readKeyConfig` returns empty `Optional`.
    * Test `JwtKeyNotFoundException` (key material missing): Mock `readKeyConfig` returns config, mock `getStoredKeyMaterial` throws `JwtKeyNotFoundException`.
    * Test `VaultSealedException`: Mock `sealManager.isSealed()` to return `true` at the start.
    * Test `SecretsEngineException` from decrypt: Mock `encryptionService.decrypt` (for private key) throws. **Verify** `auditHelper.logInternalEvent` (failure).
    * Test `SecretsEngineException` from reconstructPrivateKey: Mock `reconstructPrivateKey` throws. **Verify** `auditHelper.logInternalEvent` (failure).
* **Task 3.7:** **`rotateKey` Tests**
    * Test success: Mock `readKeyConfig` returning existing config, mock `generateAndStoreKeyPair` (**verify** call), mock `writeKeyConfig` (**verify** call with updated version/timestamp). **Verify** `auditHelper.logInternalEvent` (rotation success).
    * Test `JwtKeyNotFoundException` (config missing): Mock `readKeyConfig` returns empty `Optional`.
    * Test `VaultSealedException`: Mock `sealManager.isSealed()` to return `true` at the start.
    * Test failure propagation from `generateAndStoreKeyPair`: Mock `generateAndStoreKeyPair` throws `SecretsEngineException`. **Verify** `auditHelper.logInternalEvent` (rotation failure).
    * Test failure propagation from `writeKeyConfig`: Mock `writeKeyConfig` throws `SecretsEngineException`. **Verify** `auditHelper.logInternalEvent` (rotation failure).
* **Task 3.8:** **`getJwks` Tests** (Requires Phase 2 done)
    * Test success (RSA, single key): Mock config/material, **verify** `reconstructPublicKey`, **verify** JWK structure/content. **Verify** audit log.
    * Test success (EC, single key): Mock config/material, **verify** `reconstructPublicKey`, **verify** JWK structure/content. **Verify** audit log.
    * Test success (multiple keys): Mock config/material for v1, v2. **Verify** JWK Set contains both.
    * Test `JwtKeyNotFoundException` (config missing).
    * Test handling missing key material for one version (e.g., mock `getStoredKeyMaterial` throws for v1, returns for v2 - **expect** JWKS with only v2).
    * Test `VaultSealedException`.

## Phase 4: Integration Test Setup (`JwtControllerIntegrationTest.java`)

* **Task 4.1:** **Create `JwtControllerIntegrationTest.java`**.
* **Task 4.2:** **Annotate** with `@SpringBootTest`, `@AutoConfigureMockMvc`, `@ActiveProfiles("test")`.
* **Task 4.3:** **Create `src/test/resources/application-test.yml`**.
* **Task 4.4:** **Define `mssm.master.b64`** in `application-test.yml` (or use `@DynamicPropertySource`).
* **Task 4.5:** **Define `mssm.storage.filesystem.path`** using `@TempDir` and `@DynamicPropertySource`.
* **Task 4.6:** **Define JWT key configurations** in `application-test.yml`:
    * `mssm.jwt.keys.api-signing-key-rsa` (Type RSA, size 2048)
    * `mssm.jwt.keys.api-signing-key-ec` (Type EC, curve P-256)
* **Task 4.7:** **Define policies** in `application-test.yml`:
    * `jwt-sign`: path: `jwt/sign/*`, capabilities: [`UPDATE`] (or CREATE)
    * `jwt-rotate`: path: `jwt/rotate/*`, capabilities: [`UPDATE`]
    * `jwt-jwks`: path: `jwt/jwks/*`, capabilities: [`READ`] (though endpoint should be public)
    * **(Optional)** `admin`: Include above paths/capabilities if needed for an admin token.
* **Task 4.8:** **Define static tokens** in `application-test.yml`:
    * `signing-token`: maps to `jwt-sign` policy.
    * `admin-token`: maps to `jwt-rotate` policy (and potentially others).
* **Task 4.9:** **Inject `MockMvc`, `SealManager`, `ObjectMapper`**.
* **Task 4.10:** **Implement `@BeforeEach`** to unseal the vault using `sealManager.unseal(...)`.
* **Task 4.11:** **(Optional) Implement `@MockBean`** for `AuditHelper` if choosing to verify audits via mock interactions rather than log parsing.

## Phase 5: Integration Tests (`JwtControllerIntegrationTest.java`)

* **Task 5.1:** **Initial State / First Rotation / Signing (RSA)**
    * **Test** `GET /v1/jwt/jwks/api-signing-key-rsa` -> **Expect** 404 (or empty `{"keys":[]}` if JWKS implemented).
    * **Test** `POST /v1/jwt/sign/api-signing-key-rsa` (signing token, empty claims) -> **Expect** 404.
    * **Test** `POST /v1/jwt/rotate/api-signing-key-rsa` (admin token) -> **Expect** 204.
    * **Verify** storage files (`config.json`, `versions/1.json`) exist in temp dir.
    * **Test** `GET /v1/jwt/jwks/api-signing-key-rsa` -> **Expect** 200, **validate** JWKS has one RSA key (v1). Extract public key.
    * **Test** `POST /v1/jwt/sign/api-signing-key-rsa` (signing token, valid claims) -> **Expect** 200. Get JWT.
    * **Decode** JWT: **Verify** header (`kid=api-signing-key-rsa-1`, `alg=RS256`), **verify** payload claims.
    * **Verify** JWT signature using the extracted public key (v1).
* **Task 5.2:** **Second Rotation / Post-Rotation Signing & Verification (RSA)**
    * **Test** `POST /v1/jwt/rotate/api-signing-key-rsa` (admin token) -> **Expect** 204.
    * **Verify** storage file `versions/2.json` exists.
    * **Test** `GET /v1/jwt/jwks/api-signing-key-rsa` -> **Expect** 200, **validate** JWKS has two RSA keys (v1, v2). Extract both public keys.
    * **Test** `POST /v1/jwt/sign/api-signing-key-rsa` (signing token, valid claims) -> **Expect** 200. Get JWT (v2).
    * **Decode** JWT (v2): **Verify** header (`kid=api-signing-key-rsa-2`, `alg=RS256`).
    * **Verify** JWT (v2) signature using the extracted public key (v2).
    * **Verify** JWT (v1, from Task 5.1) signature using the JWKS containing v1 & v2. **Assert:** Verification should PASS.
* **Task 5.3:** **Repeat Lifecycle for EC Key**
    * Repeat relevant steps from Task 5.1 and 5.2 for the `api-signing-key-ec` key (**expect** `alg=ES256`).
* **Task 5.4:** **Security Tests**
    * Call `/sign/{key}` without token -> **Expect** 401.
    * Call `/rotate/{key}` without token -> **Expect** 401.
    * Call `/sign/{key}` with invalid token -> **Expect** 401/403.
    * Call `/rotate/{key}` with invalid token -> **Expect** 401/403.
    * Call `/rotate/{key}` with `signing-token` -> **Expect** 403.
    * Call `/sign/{key}` with `admin-token` -> **Expect** 403 (if policy doesn't allow).
    * Call `/jwks/{key}` without token -> **Expect** 200.
* **Task 5.5:** **Error Handling Tests**
    * Seal vault (`sealManager.seal()`).
    * Call `POST /sign/{key}` -> **Expect** 503.
    * Call `POST /rotate/{key}` -> **Expect** 503.
    * Call `GET /jwks/{key}` -> **Expect** 503.
    * Unseal vault (`sealManager.unseal(...)`).
    * Call `POST /sign/non-existent-key` -> **Expect** 404.
    * Call `POST /rotate/non-existent-key` -> **Expect** 404.
    * Call `GET /jwks/non-existent-key` -> **Expect** 404.
    * Call `POST /sign/{key}` with malformed JSON body -> **Expect** 400.
* **Task 5.6:** **Audit Log Verification**
    * If using `@MockBean AuditHelper`: Add `verify(auditHelper).logHttpEvent(...)` or `verify(auditHelper).logInternalEvent(...)` calls within the relevant integration tests to check type, action, outcome, status, principal (if available), and key data points for major operations (sign success/fail, rotate success/fail, jwks access).
    * If parsing logs: Ensure test logging is configured correctly and add assertions to check for expected log lines after specific operations.

This detailed plan breaks the strategy into manageable, ordered tasks, addressing implementation gaps (like JWKS) and covering the different testing layers.