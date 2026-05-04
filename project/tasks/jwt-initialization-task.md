Okay, here is the implementation plan for initializing JWT keys on application startup, based on the provided plan and the context from your codebase.

## JWT Initialization Plan Implementation

This plan details how to implement the automatic initialization of JWT signing keys upon application startup in your `lite-vault` application, ensuring that necessary configuration and initial key material are persisted if they don't already exist.

**Goal:** Ensure that for each JWT key defined in `mssm.secrets.jwt.keys` within your configuration (`application-dev.yml`, `application-test.yml`, etc.), the application automatically creates and stores the initial configuration (`config.json`) and the first key version (`versions/1.json`) in the configured storage backend (`lite-vault-data`) during startup, but only if they aren't already present[cite: 15].

**Approach:** Use Spring's `@PostConstruct` annotation on a method within the `JwtSecretsEngine`[cite: 15]. This method will run once the `JwtSecretsEngine` bean is fully initialized with its dependencies (`MssmProperties`, `StorageBackend`, `EncryptionService`, `SealManager`)[cite: 15].

---

**Detailed Steps:**

1.  **Add `@PostConstruct` Method to `JwtSecretsEngine`**
    * **Action:** Create a public `void initializeKeys()` method within `JwtSecretsEngine.java`. Annotate this method with `@jakarta.annotation.PostConstruct`[cite: 16, 36].
    * **Context:** Spring Boot identifies the `@PostConstruct` annotation and executes this method after the `JwtSecretsEngine` bean has been created and all required dependencies (`@Autowired` or constructor-injected fields like `properties`, `sealManager`, `storageBackend`, `encryptionService`, `auditHelper`, `objectMapper`) are ready[cite: 15]. This guarantees that the necessary services are available for initialization logic. The `JwtSecretsEngine` is already defined as a `@Service`[cite: 35].
    * **Code Snippet:**
        ```java
        // Inside lite-vault/src/main/java/tech/yump/vault/secrets/jwt/JwtSecretsEngine.java
        import jakarta.annotation.PostConstruct; // Add this import
        // ... other imports

        @Service
        @Slf4j
        @RequiredArgsConstructor
        public class JwtSecretsEngine implements SecretsEngine {

            // ... existing fields ...

            @PostConstruct
            public void initializeKeys() {
                log.info("Checking JWT key initialization status...");
                // ... implementation from subsequent steps ...
            }

            // ... rest of existing methods ...
        }
        ```
      *[Source: `jwt_initalization_plan.txt` [cite: 16, 35, 36]]*

2.  **Check Vault Seal Status**
    * **Action:** The first step inside `initializeKeys()` must be to check if the vault is sealed using `sealManager.isSealed()`[cite: 16]. If it is sealed, log a warning and immediately return to prevent further processing[cite: 16, 37, 38].
    * **Context:** JWT key initialization involves generating keys and encrypting private keys using the `EncryptionService`[cite: 30]. The `EncryptionService` requires the master key, which is only available when the vault is unsealed (managed by `SealManager`)[cite: 16]. Attempting encryption while sealed would result in a `VaultSealedException`. Checking upfront avoids this error and logs the reason for skipping initialization.
    * **Code Snippet:**
        ```java
        // Inside initializeKeys()
        if (sealManager.isSealed()) {
            log.warn("Cannot initialize JWT keys: Vault is sealed. Initialization will be skipped.");
            return;
        }
        // ... continue if unsealed ...
        ```
      *[Source: `jwt_initalization_plan.txt`[cite: 16, 37, 38], `lite-vault/src/main/java/tech/yump/vault/core/SealManager.java`, `lite-vault/src/main/java/tech/yump/vault/crypto/EncryptionService.java`]*
    * **Good Practice:** This "fail fast" approach ensures the application doesn't proceed with operations that are guaranteed to fail due to the vault's state.

3.  **Load Key Definitions from Properties**
    * **Action:** Retrieve the map of configured JWT keys using the injected `MssmProperties` bean: `properties.secrets().jwt().keys()`[cite: 17]. Perform null checks for intermediate properties (`secrets()`, `jwt()`, `keys()`)[cite: 39]. If the configuration section or the `keys` map is missing or empty, log an informational message and return[cite: 18, 19, 39, 40, 42, 43].
    * **Context:** The `MssmProperties` record class uses Spring Boot's `@ConfigurationProperties` mechanism to bind values from `application.yml` (like `mssm.secrets.jwt.keys`) into a type-safe Java object[cite: 17]. This map provides the necessary definitions (like type, size, curve) for each key that needs to be initialized. The code already defines `JwtProperties` and `JwtKeyDefinition` records within `MssmProperties.java`.
    * **Code Snippet:**
        ```java
        // Inside initializeKeys(), after seal check
        Map<String, MssmProperties.JwtKeyDefinition> configuredKeys;
        try {
             // Defensive check for nested properties
            if (properties.secrets() == null || properties.secrets().jwt() == null || properties.secrets().jwt().keys() == null) {
                 log.info("JWT key configuration section (mssm.secrets.jwt.keys) is missing or empty. Skipping initialization.");
                 return;
            }
            configuredKeys = properties.secrets().jwt().keys();
        } catch (Exception e) {
            // Catch potential NullPointerException if validation is bypassed or structure is wrong
            log.error("Error accessing JWT key configuration from properties. Skipping initialization.", e);
            return;
        }

        if (configuredKeys.isEmpty()) {
            log.info("No JWT keys configured under mssm.secrets.jwt.keys. Skipping initialization.");
            return;
        }

        log.info("Found {} JWT key(s) configured. Checking initialization status...", configuredKeys.size());
        // ... loop through keys ...
        ```
      *[Source: `jwt_initalization_plan.txt`[cite: 17, 18, 19, 39, 40, 41, 42, 43], `lite-vault/src/main/java/tech/yump/vault/config/MssmProperties.java`]*
    * **Layered Approach:** Configuration is cleanly separated from the engine logic. The engine consumes the type-safe `MssmProperties` object.

4.  **Iterate Through Configured Keys**
    * **Action:** Loop through each entry (`keyName`, `keyDefinition`) in the `configuredKeys` map obtained in the previous step[cite: 20, 21, 44]. Wrap the logic for initializing each key within a `try-catch` block[cite: 21, 24].
    * **Context:** This ensures that an error during the initialization of one key (e.g., a storage error) does not prevent the application from attempting to initialize other configured keys[cite: 24]. The `catch` block should log the specific error and the key name it pertains to[cite: 23, 24, 57, 58]. If a `VaultSealedException` is caught during the loop, it's crucial to stop processing further keys, as subsequent attempts would also fail[cite: 22, 55]; the plan suggests using `break`[cite: 56].
    * **Code Snippet:**
        ```java
        // Inside initializeKeys(), after loading keys
        for (Map.Entry<String, MssmProperties.JwtKeyDefinition> entry : configuredKeys.entrySet()) {
            String keyName = entry.getKey();
            MssmProperties.JwtKeyDefinition keyProps = entry.getValue(); // Use keyProps as in plan

            try {
                // Step 5 & 6 logic here...
            } catch (VaultSealedException vse) {
                log.error("Vault became sealed during initialization check/attempt for key '{}'. Halting further JWT key initialization.", keyName, vse);
                break; // Stop processing further keys
            } catch (JwtKeyNotFoundException knfe) {
                 // This might occur if generateAndStoreKeyPair fails internally due to definition issues
                 log.error("Configuration definition issue for key '{}' during initialization attempt: {}. Skipping this key.", keyName, knfe.getMessage());
                 // Continue to the next key
            } catch (Exception e) {
                // Catch other exceptions like StorageException, EncryptionException, IOException
                log.error("Failed to initialize JWT key '{}' due to an unexpected error: {}. Skipping this key.", keyName, e.getMessage(), e);
                // Continue to the next key
            }
        }
        log.info("JWT key initialization check complete.");
        ```
      *[Source: `jwt_initalization_plan.txt` [cite: 20, 21, 22, 23, 24, 44, 45, 55, 56, 57, 58, 59]]*

5.  **Check for Existing Initialization**
    * **Action:** Inside the `try` block for each key, construct the expected storage paths for the configuration file (`jwt/keys/{keyName}/config.json`) and the version 1 key material file (`jwt/keys/{keyName}/versions/1.json`)[cite: 24, 25, 46]. Use the injected `storageBackend.get()` method to check if data exists at *both* these paths[cite: 26, 27, 46, 47].
    * **Context:** The `JwtSecretsEngine` already defines constants or format strings for these paths (e.g., `KEY_CONFIG_PATH_FORMAT`, `KEY_MATERIAL_PATH_FORMAT`)[cite: 25]. The `StorageBackend` interface has a `get(String key)` method returning an `Optional<EncryptedData>`[cite: 26]. The `FileSystemStorageBackend` implementation correctly resolves these logical keys to file paths (e.g., `./lite-vault-data/jwt/keys/my-key/config.json`)[cite: 26]. Checking for both files ensures a previous initialization attempt wasn't interrupted halfway[cite: 28].
    * **Code Snippet:**
        ```java
        // Inside the try block in the loop
        String configPath = getKeyConfigPath(keyName); // Existing helper method
        String initialKeyMaterialPath = String.format(KEY_MATERIAL_PATH_FORMAT, keyName, 1);

        // Check if both config and version 1 material exist
        Optional<EncryptedData> existingConfigData = storageBackend.get(configPath);
        Optional<EncryptedData> existingKeyV1Data = storageBackend.get(initialKeyMaterialPath);

        if (existingConfigData.isPresent() && existingKeyV1Data.isPresent()) {
            log.debug("JWT key '{}' appears to be already initialized (config and version 1 found). Skipping generation.", keyName);
            // Continue to next iteration of the loop
        } else {
            // Step 6: Perform Initialization here...
        }
        ```
      *[Source: `jwt_initalization_plan.txt`[cite: 24, 25, 26, 27, 28, 45, 46, 47, 48], `lite-vault/src/main/java/tech/yump/vault/secrets/jwt/JwtSecretsEngine.java`, `lite-vault/src/main/java/tech/yump/vault/storage/StorageBackend.java`, `lite-vault/src/main/java/tech/yump/vault/storage/FileSystemStorageBackend.java`]*

6.  **Perform Initialization (If Necessary)**
    * **Action:** If the check in Step 5 determines that either the config or version 1 material is missing (`else` block), proceed with initialization[cite: 29].
        1.  Log the intent: `log.info("Initializing JWT key '{}' (config or version 1 data missing)...", keyName);`[cite: 48].
        2.  Call the existing `generateAndStoreKeyPair(keyName, 1);` method[cite: 29, 49].
        3.  Create a `JwtKeyConfig` instance: Set `currentVersion = 1`, determine the `rotationPeriod` from `keyProps` (defaulting to `Duration.ZERO` if null), and set `lastRotationTime = Instant.now()`[cite: 30, 31, 32].
        4.  Call the existing `writeKeyConfig(keyName, initialConfig);` method[cite: 32, 33].
        5.  Log successful initialization: `log.info("Successfully initialized JWT key '{}' with version 1.", keyName);`[cite: 34, 54].
    * **Context:** This step leverages the already implemented core logic of the `JwtSecretsEngine`. `generateAndStoreKeyPair` handles key generation according to the definition, encryption of the private key, packaging into `StoredJwtKeyMaterial`, encrypting the package, and saving it to the correct path (`versions/1.json`) using `StorageBackend`[cite: 30]. `writeKeyConfig` handles serializing the `JwtKeyConfig` object, encrypting it, and saving it to the `config.json` path using `StorageBackend`[cite: 33]. Both methods also incorporate auditing via `AuditHelper`[cite: 30, 33].
    * **Code Snippet:**
        ```java
        // Inside the else block from Step 5
        log.info("Initializing JWT key '{}' (config or version 1 data missing)...", keyName);

        // 1. Generate and store version 1 key material
        generateAndStoreKeyPair(keyName, 1); // Reuses existing logic

        // 2. Create and store the initial configuration pointing to version 1
        Duration rotationPeriod = keyProps.rotationPeriod() != null ?
                keyProps.rotationPeriod() : Duration.ZERO;
        JwtKeyConfig initialConfig = new JwtKeyConfig(
                1, // Current version is 1
                rotationPeriod,
                Instant.now() // Set last rotation time to now
        );
        writeKeyConfig(keyName, initialConfig); // Reuses existing logic

        log.info("Successfully initialized JWT key '{}' with version 1.", keyName);
        ```
      *[Source: `jwt_initalization_plan.txt`[cite: 29, 30, 31, 32, 33, 34, 48, 49, 50, 51, 52, 53, 54], `lite-vault/src/main/java/tech/yump/vault/secrets/jwt/JwtSecretsEngine.java`]*
    * **Layered Approach:** The initialization orchestrates the core engine capabilities, which rely on the distinct Encryption, Storage, and Auditing layers.

7.  **Testing Strategy**
    * **Unit Tests:** Create tests in `JwtSecretsEngineTest.java` specifically for the `initializeKeys` method[cite: 33]. Mock `MssmProperties` to provide different key configurations. Mock `StorageBackend.get` to return various combinations (`Optional.empty()`, only config present, only v1 present, both present)[cite: 34]. Mock `SealManager.isSealed()` to return true/false. Verify that `generateAndStoreKeyPair` and `writeKeyConfig` are called (or not called) appropriately based on the mocked storage state and seal status[cite: 33, 34].
    * **Integration Tests:** Modify or add tests in `JwtControllerIntegrationTest.java`[cite: 34]. Use `@SpringBootTest` and configure `application-test.yml` with JWT keys. Ensure `@TempDir` is used for `mssm.storage.filesystem.path`. When the application context starts for the test, the `@PostConstruct` method should run. Verify that the expected files (`config.json`, `versions/1.json` for each key) are created in the temporary storage directory[cite: 34]. You can `@Autowired StorageBackend` into the test to `get()` the data and potentially decrypt/verify its basic structure[cite: 34]. After the application starts, run tests against the `/sign` endpoint; they should now succeed for the initialized keys[cite: 35].

---

This detailed implementation plan integrates the initialization logic into your existing application structure, leverages existing components, and outlines necessary testing. Remember to adapt code snippets based on the exact field names and method signatures in your `JwtSecretsEngine.java` and related classes.