# Comprehensive Testing Strategy for JWT Secrets Engine

Let's outline a comprehensive testing strategy for the JWT Secrets Engine lifecycle, combining configuration validation, unit tests, and integration tests.

## The JWT Lifecycle Stages to Test:

1.  **Configuration:** Loading and validating JWT key definitions (`mssm.jwt.keys.*`).
2.  **Initialization/First Use:** Generating the first key pair for a defined key name (likely triggered by the first rotation or sign request if not pre-generated).
3.  **Signing:** Requesting a JWT signature using the current key version.
4.  **Verification Key Retrieval:** Fetching the public key(s) via the JWKS endpoint.
5.  **Verification (External Simulation):** Using the fetched public key(s) to validate a signed JWT.
6.  **Rotation:** Triggering the generation of a new key pair and updating the current version pointer.
7.  **Post-Rotation Signing:** Ensuring new signatures use the new key.
8.  **Post-Rotation Verification:** Ensuring the JWKS endpoint provides the new key (and potentially the old one) and that verification works for tokens signed with both old and new keys (during a transition).
9.  **Error Handling:** Vault sealed, key not found, invalid configuration, bad requests, auth/authz failures.
10. **Auditing:** Correct audit events logged for relevant actions.

## Testing Strategy:

### 1. Configuration Validation Tests (`ConfigurationValidationTest.java`)

* **Goal:** Ensure `MssmProperties` correctly validates the `mssm.jwt.*` section at startup.
* **Method:** Use `ApplicationContextRunner` as you already are.
* **Scenarios (You've covered these well, just confirming):**
    * **PASS:** Valid RSA config (type, size >= 2048).
    * **PASS:** Valid EC config (type, valid curve).
    * **PASS:** Optional `rotationPeriod` present/absent.
    * **PASS:** `mssm.jwt` section completely missing.
    * **FAIL:** RSA missing size.
    * **FAIL:** RSA size too small.
    * **FAIL:** RSA specifying curve.
    * **FAIL:** EC missing curve.
    * **FAIL:** EC specifying invalid curve.
    * **FAIL:** EC specifying size.
    * **FAIL:** Key missing type.
    * **FAIL:** Key specifying invalid type.
    * **FAIL:** `mssm.jwt.keys` map is present but empty (`mssm.jwt.keys=`). (Your test currently expects `ConverterNotFoundException`, which seems correct for an empty value assignment).

### 2. Unit Tests (`JwtSecretsEngineTest.java`)

* **Goal:** Isolate and test the logic within `JwtSecretsEngine`, mocking external dependencies.
* **Method:** Use Mockito (`@Mock`, `@InjectMocks`). Mock `MssmProperties`, `EncryptionService`, `StorageBackend`, `SealManager`, `AuditHelper`, `ObjectMapper`.
* **Scenarios:**
    * **`generateAndStoreKeyPair`:**
        * Verify correct `KeyPairGenerator` algorithm/params used based on config (RSA size, EC curve).
        * Verify `EncryptionService.encrypt` is called for the private key and the final bundle.
        * Verify `StorageBackend.put` is called with the correct path (`jwt/keys/{key_name}/versions/{version}`) and correctly structured `EncryptedData`.
        * Verify private key bytes are cleared (if possible to test).
        * Verify `AuditHelper.logInternalEvent` called on success.
        * Test `VaultSealedException` when sealed.
        * Test `EncryptionException` propagation.
        * Test `StorageException` propagation.
    * **`readKeyConfig`/`writeKeyConfig`:**
        * Verify correct `StorageBackend.get`/`put` calls with config path.
        * Verify `EncryptionService.decrypt`/`encrypt` calls.
        * Verify `ObjectMapper.readValue`/`writeValueAsBytes` calls.
        * Verify `AuditHelper.logInternalEvent` called on write success.
        * Test `VaultSealedException`, `StorageException`, `EncryptionException`, `IOException`.
    * **`getStoredKeyMaterial`:**
        * Verify `StorageBackend.get` call with versioned path.
        * Verify `EncryptionService.decrypt` call for the bundle.
        * Verify `ObjectMapper.readValue` call for `StoredJwtKeyMaterial`.
        * Test `JwtKeyNotFoundException` when storage returns empty `Optional`.
        * Test `VaultSealedException`, `StorageException`, `EncryptionException`, `IOException`.
    * **`reconstructPrivateKey`/`reconstructPublicKey`:**
        * Verify correct `KeyFactory` algorithm used.
        * Verify correct `KeySpec` used (`PKCS8`, `X509`).
        * Test `InvalidKeySpecException`.
    * **`signJwt`:**
        * Verify `readKeyConfig` is called.
        * Verify `getStoredKeyMaterial` is called with the current version from config.
        * Verify `EncryptionService.decrypt` is called for the encrypted private key bytes.
        * Verify `reconstructPrivateKey` is called.
        * Verify `Jwts.builder().signWith()` is called with the correct private key and algorithm.
        * Test `JwtKeyNotFoundException` if config or key material is missing.
        * Test `VaultSealedException`, `SecretsEngineException` from dependencies.
    * **`rotateKey`:**
        * Verify `readKeyConfig` is called (or handles missing config for initial generation).
        * Verify `generateAndStoreKeyPair` is called with the next version number.
        * Verify `writeKeyConfig` is called to update the `currentVersion` and `lastRotationTime`.
        * Verify `AuditHelper.logInternalEvent` called on success.
        * Test `VaultSealedException`, `JwtKeyNotFoundException` (if config is required but missing), propagation of errors from underlying calls.
    * **`getJwks`:**
        * Verify `readKeyConfig` is called.
        * Verify `getStoredKeyMaterial` is called for relevant versions (e.g., current, maybe previous).
        * Verify `reconstructPublicKey` is called.
        * Verify the generated JWK Set structure is correct (correct `kty`, `alg`, `use`, `kid`, `n`, `e` for RSA; `kty`, `alg`, `use`, `kid`, `crv`, `x`, `y` for EC).
        * Test with only one key version present.
        * Test with multiple key versions present.
        * Test `JwtKeyNotFoundException` if config is missing.
        * Test handling if key material is missing for a version.

### 3. Integration Tests (`JwtControllerIntegrationTest.java`)

* **Goal:** Test the full HTTP request/response lifecycle, including security, engine logic, storage, and encryption working together.
* **Method:** Use `@SpringBootTest`, `@AutoConfigureMockMvc`, Testcontainers (if DB needed for full context, otherwise maybe not strictly required just for JWT), `@ActiveProfiles("test")`, `@DynamicPropertySource` (for storage path), `@TempDir`.
* **Setup:**
    * Ensure `application-test.yml` defines JWT key configurations (`mssm.jwt.keys.*`) and relevant policies/tokens (e.g., a signing token, an admin token for rotation).
    * Use `@TempDir` and `@DynamicPropertySource` to point `mssm.storage.filesystem.path` to a temporary directory per test run.
    * Ensure the vault is unsealed in `@BeforeEach`.
* **Scenarios (Full Lifecycle Example):**
    1.  **Initial State Check (Optional):**
        * Call `GET /v1/jwt/jwks/api-signing-key-rsa`. Expect 404 or empty JWKS (as key doesn't exist yet).
        * Call `POST /v1/jwt/sign/api-signing-key-rsa` (with signing token). Expect 404 (key not found - this matches your cli.log error!).
    2.  **First Rotation (Initial Generation):**
        * Call `POST /v1/jwt/rotate/api-signing-key-rsa` (with admin token).
        * **Assert:** Expect 200 OK or 204 No Content.
        * **Verify:** Check the temporary storage directory: `jwt/keys/api-signing-key-rsa/config.json` and `jwt/keys/api-signing-key-rsa/versions/1.json` should exist and contain encrypted data.
        * **Verify:** Call `GET /v1/jwt/jwks/api-signing-key-rsa`. Expect 200 OK and a JWKS containing one public key (version 1). Extract the public key details.
    3.  **Signing (First Key):**
        * Call `POST /v1/jwt/sign/api-signing-key-rsa` (with signing token) and valid claims JSON body.
        * **Assert:** Expect 200 OK. Get the returned JWT string.
        * **Verify:** Decode the JWT (header/payload). Check `kid` header matches the key ID from JWKS (version 1). Verify claims.
        * **Verify Signature:** Using a JWT library (like jjwt) and the public key obtained from JWKS (step 2), verify the signature of the returned JWT.
    4.  **Second Rotation:**
        * Call `POST /v1/jwt/rotate/api-signing-key-rsa` (with admin token) again.
        * **Assert:** Expect 200 OK or 204 No Content.
        * **Verify:** Check storage: `jwt/keys/api-signing-key-rsa/versions/2.json` should now exist. `config.json` should be updated (check timestamp or decrypt if possible in test).
        * **Verify:** Call `GET /v1/jwt/jwks/api-signing-key-rsa`. Expect 200 OK and a JWKS containing two public keys (version 1 and version 2). Extract both public keys.
    5.  **Signing (Second Key):**
        * Call `POST /v1/jwt/sign/api-signing-key-rsa` (with signing token) again.
        * **Assert:** Expect 200 OK. Get the new JWT string.
        * **Verify:** Decode the JWT. Check `kid` header now matches the key ID for version 2.
        * **Verify Signature:** Verify the signature using the version 2 public key from JWKS.
    6.  **Verification (Post-Rotation):**
        * Take the JWT obtained in Step 3 (signed with v1 key). Verify its signature using the JWKS from Step 4 (which contains both v1 and v2 keys). **Assert:** Verification should PASS.
        * Take the JWT obtained in Step 5 (signed with v2 key). Verify its signature using the JWKS from Step 4. **Assert:** Verification should PASS.
    7.  **Security Tests:**
        * Call `/sign` and `/rotate` without a token (expect 403).
        * Call `/sign` and `/rotate` with an invalid token (expect 403).
        * Call `/rotate` with the signing token (expect 403 - policy denied).
        * Call `/sign` with the admin token (expect 403 if admin policy doesn't grant sign capability).
        * Call `/jwks` without a token (expect 200 OK - should be public).
    8.  **Error Handling Tests:**
        * Seal the vault (`sealManager.seal()`). Call `/sign` or `/rotate`. Expect 503 Service Unavailable. Unseal afterwards.
        * Call `/sign` or `/rotate` for a key-name not defined in `application-test.yml`. Expect 404 Not Found.
        * Call `/sign` with an invalid JSON body. Expect 400 Bad Request.
    9.  **Audit Log Verification (Optional but Recommended):**
        * Configure logging appropriately or mock `AuditHelper` bean (using `@MockBean` and `@Primary` if needed) to capture calls.
        * Verify that `logHttpEvent` or `logInternalEvent` is called with the correct type, action, outcome, principal, and data for successful/failed sign and rotate operations.

By following this multi-layered approach, you can gain high confidence in the correctness, security, and robustness of your JWT Secrets Engine implementation across its entire lifecycle. Remember to adapt the specific paths, key names, and token names based on your `application-test.yml`.