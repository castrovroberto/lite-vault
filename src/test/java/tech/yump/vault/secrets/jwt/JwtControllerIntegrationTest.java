package tech.yump.vault.secrets.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
// import org.junit.jupiter.api.MethodOrderer; // Removed Step 1
import org.junit.jupiter.api.Nested;
// import org.junit.jupiter.api.Order; // Removed Step 1
import org.junit.jupiter.api.Test;
// import org.junit.jupiter.api.TestMethodOrder; // Removed Step 1
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.FileSystemUtils;
import tech.yump.vault.api.v1.JwtController;
import tech.yump.vault.core.SealManager;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.PublicKey;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static tech.yump.vault.auth.StaticTokenAuthFilter.createAuthenticationToken;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS) // Keep context for duration of all tests in this class
@Slf4j // Added logger
public class JwtControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SealManager sealManager;

    @Autowired
    private ObjectMapper objectMapper;

    @TempDir
    static Path staticTempDir; // Static TempDir persists across tests in the class

    @DynamicPropertySource
    static void configurePropertiesRevised(DynamicPropertyRegistry registry) {
        registry.add("mssm.storage.filesystem.path", () -> staticTempDir.toAbsolutePath().toString());
    }

    // --- Constants for tests ---
    private static final String RSA_KEY_NAME = "api-signing-key-rsa";
    private static final String EC_KEY_NAME = "api-signing-key-ec"; // Assumed defined in application-test.yml
    private static final String ADMIN_TOKEN = "test-root-token";
    private static final String RSA_SIGNING_TOKEN = "test-jwt-signer-token"; // Renamed for clarity
    private static final String EC_SIGNING_TOKEN = "test-ec-jwt-signer-token"; // Assumed defined in application-test.yml
    private static final String INVALID_TOKEN = "this-is-not-a-valid-token";

    private static final String JWKS_PATH_FORMAT = "/v1/jwt/jwks/%s";
    private static final String SIGN_PATH_FORMAT = "/v1/jwt/sign/%s";
    private static final String ROTATE_PATH_FORMAT = "/v1/jwt/rotate/%s";

    // --- Removed custom deleteDirectoryRecursively method ---

    // --- Enhanced Setup: Clean storage and Unseal Vault before EACH test method ---
    @BeforeEach
    void cleanStorageAndUnseal() throws Exception {
        log.info("===== Running @BeforeEach Cleanup and Unseal =====");

        // Clean specific key directories
        if (staticTempDir != null) {
            Path jwtKeysBaseDir = staticTempDir.resolve("jwt/keys");
            log.info("Attempting to clean storage within base: {}", jwtKeysBaseDir.toAbsolutePath());

            Path rsaKeyDir = jwtKeysBaseDir.resolve(RSA_KEY_NAME);
            Path ecKeyDir = jwtKeysBaseDir.resolve(EC_KEY_NAME);

            // Delete RSA key directory if it exists
            if (Files.exists(rsaKeyDir)) {
                log.info("Attempting deletion of {}", rsaKeyDir.toAbsolutePath());
                boolean rsaDeleted = FileSystemUtils.deleteRecursively(rsaKeyDir); // Use Spring's utility
                log.info("Deletion result for {}: {}", RSA_KEY_NAME, rsaDeleted);
                if (!rsaDeleted) {
                    log.warn("Failed to delete directory: {}", rsaKeyDir.toAbsolutePath());
                    // Optionally throw an exception if deletion failure is critical
                    // throw new IOException("Failed to delete RSA key directory: " + rsaKeyDir);
                }
            } else {
                log.info("Directory does not exist, skipping deletion: {}", rsaKeyDir.toAbsolutePath());
            }


            // Delete EC key directory if it exists
            if (Files.exists(ecKeyDir)) {
                log.info("Attempting deletion of {}", ecKeyDir.toAbsolutePath());
                boolean ecDeleted = FileSystemUtils.deleteRecursively(ecKeyDir); // Use Spring's utility
                log.info("Deletion result for {}: {}", EC_KEY_NAME, ecDeleted);
                if (!ecDeleted) {
                    log.warn("Failed to delete directory: {}", ecKeyDir.toAbsolutePath());
                    // Optionally throw an exception
                    // throw new IOException("Failed to delete EC key directory: " + ecKeyDir);
                }
            } else {
                log.info("Directory does not exist, skipping deletion: {}", ecKeyDir.toAbsolutePath());
            }


            // Create base jwt/keys dir if it doesn't exist (might be deleted by recursive calls)
            if (!Files.exists(jwtKeysBaseDir)) {
                try {
                    Files.createDirectories(jwtKeysBaseDir);
                    log.info("Recreated base directory: {}", jwtKeysBaseDir.toAbsolutePath());
                } catch(IOException e) {
                    log.error("Failed to recreate base directory: {}", jwtKeysBaseDir.toAbsolutePath(), e);
                    throw new RuntimeException("Failed to recreate base storage directory", e);
                }
            }

        } else {
            // This case should ideally not happen with @TempDir, but good practice to check
            log.error("!!! staticTempDir was null in @BeforeEach cleanup - Test setup likely failed! !!!");
            throw new IllegalStateException("staticTempDir cannot be null for cleanup");
        }

        // Ensure the SealManager is unsealed
        String dummyMasterKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        if (sealManager == null) {
            log.error("!!! SealManager was null in @BeforeEach setup - Test context issue? !!!");
            throw new IllegalStateException("SealManager cannot be null for unsealing");
        }

        if (sealManager.isSealed()) {
            log.info("Vault is SEALED, attempting unseal...");
            try {
                sealManager.unseal(dummyMasterKeyB64);
                log.info("Vault unseal attempt finished.");
            } catch (Exception e) {
                log.error("Failed to unseal vault during @BeforeEach setup", e);
                throw new RuntimeException("Failed to unseal vault during @BeforeEach setup", e);
            }
            if (sealManager.isSealed()) { // Double-check
                log.error("!!! Vault remained sealed after unseal attempt in @BeforeEach setup !!!");
                throw new RuntimeException("Vault remained sealed after unseal attempt in @BeforeEach setup");
            } else {
                log.info("Vault is now UNSEALED.");
            }
        } else {
            log.info("Vault already UNSEALED.");
        }
        log.info("===== @BeforeEach Cleanup and Unseal Finished =====");
    }


    // --- Phase 5: Integration Tests ---

    @Nested
    @DisplayName("RSA Key Lifecycle Tests")
            // @TestMethodOrder(MethodOrderer.OrderAnnotation.class) // Step 1: Removed ordering
    class RsaLifecycleTests {

        // Step 2: Removed static state variables
        // private static String jwtStringRsaV1;
        // private static PublicKey publicKeyRsaV1;

        @Test
        // Step 3: Renamed test method
        @DisplayName("Task 5.1: RSA Initial Rotation, Signing, Verification")
            // @Order(1) // Step 1: Removed ordering
        void testRsaInitialRotationAndSigningVerification() throws Exception { // Step 3: Renamed test method
            log.info(">>> Starting testRsaInitialRotationAndSigningVerification (RSA) <<<");
            // 1. Initial State Checks
            mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: JWT key configuration not found for name: No key versions found for key: " + RSA_KEY_NAME));

            mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(Collections.emptyMap())))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: JWT key configuration not found for name: " + RSA_KEY_NAME));

            // 2. First Rotation (Admin Token)
            log.info("Performing first rotation for {}", RSA_KEY_NAME);
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            Path configPath = staticTempDir.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("config.json");
            Path version1Path = staticTempDir.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("versions/1.json");
            assertThat(Files.exists(configPath)).as("Config file should exist after rotation").isTrue();
            assertThat(Files.exists(version1Path)).as("Version 1 file should exist after rotation").isTrue();
            log.info("Verified existence of config and version 1 files for {}", RSA_KEY_NAME);

            // 3. Fetch JWKS (Expect 1 RSA Key)
            log.info("Fetching JWKS for {} after first rotation", RSA_KEY_NAME);
            MvcResult jwksResult = mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys").isArray())
                    .andExpect(jsonPath("$.keys.length()").value(1))
                    .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                    .andExpect(jsonPath("$.keys[0].use").value("sig"))
                    .andExpect(jsonPath("$.keys[0].kid").value(RSA_KEY_NAME + "-1"))
                    .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                    .andExpect(jsonPath("$.keys[0].n").exists())
                    .andExpect(jsonPath("$.keys[0].e").exists())
                    .andReturn();
            log.info("JWKS fetch successful, found 1 key as expected.");

            String jwksJson = jwksResult.getResponse().getContentAsString();
            JWKSet jwkSet = JWKSet.parse(jwksJson);
            JWK jwk = jwkSet.getKeyByKeyId(RSA_KEY_NAME + "-1");
            assertThat(jwk).isNotNull().isInstanceOf(RSAKey.class);
            // Step 3: Use local variable
            PublicKey localPublicKeyRsaV1 = ((RSAKey) jwk).toPublicKey();
            assertThat(localPublicKeyRsaV1).isNotNull();
            log.info("Extracted PublicKey v1 for {}", RSA_KEY_NAME);

            // 4. Sign JWT (v1 - Signing Token)
            Map<String, Object> claims = Map.of("sub", "integration-test-user", "scope", "test");
            log.info("Signing JWT using key {} (v1)", RSA_KEY_NAME);
            MvcResult signResult = mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(claims)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.jwt").isString())
                    .andReturn();

            // Step 3: Use local variable
            String localJwtStringRsaV1 = objectMapper.readValue(signResult.getResponse().getContentAsString(), JwtController.JwtResponse.class).jwt();
            assertThat(localJwtStringRsaV1).isNotBlank();
            log.info("JWT signing successful (v1)");

            // 5. Verify JWT (v1) Signature & Header
            log.info("Verifying JWT signature (v1) using extracted public key");
            // Step 3: Use local variable
            JwtParser parser = Jwts.parser().verifyWith(localPublicKeyRsaV1).build();
            // Step 3: Use local variable
            Jws<Claims> jws = parser.parseSignedClaims(localJwtStringRsaV1);
            assertThat(jws.getHeader().getKeyId()).isEqualTo(RSA_KEY_NAME + "-1");
            assertThat(jws.getHeader().getAlgorithm()).isEqualTo("RS256");
            assertThat(jws.getPayload().getSubject()).isEqualTo("integration-test-user");
            assertThat(jws.getPayload().get("scope")).isEqualTo("test");
            assertThat(jws.getPayload().getIssuer()).isEqualTo("lite-vault");
            assertThat(jws.getPayload().getIssuedAt()).isNotNull();
            assertThat(jws.getPayload().getExpiration()).isNotNull();
            log.info("JWT verification successful (v1)");

            log.info("<<< Finished testRsaInitialRotationAndSigningVerification (RSA) >>>");
        }

        @Test
        // Step 4: Renamed test method
        @DisplayName("Task 5.2: RSA Full Rotation Lifecycle and Verification")
            // @Order(2) // Step 1: Removed ordering
        void testRsaFullRotationLifecycleAndVerification() throws Exception { // Step 4: Renamed test method
            log.info(">>> Starting testRsaFullRotationLifecycleAndVerification (RSA) <<<");

            // --- Start: Setup steps (Step 4: Add Setup Steps) ---
            log.info("Performing initial setup steps (first rotation, sign v1) within test");

            // 1. Perform First Rotation (Admin Token)
            log.info("Setup: Performing first rotation for {}", RSA_KEY_NAME);
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            Path version1Path = staticTempDir.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("versions/1.json");
            assertThat(Files.exists(version1Path)).as("Setup: Version 1 file must exist").isTrue();
            log.info("Setup: First rotation completed");

            // 2. Fetch JWKS (v1) and Extract Public Key v1
            log.info("Setup: Fetching JWKS for {} after first rotation", RSA_KEY_NAME);
            MvcResult jwksResultV1 = mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys.length()").value(1))
                    .andReturn();
            JWKSet jwkSetV1 = JWKSet.parse(jwksResultV1.getResponse().getContentAsString());
            JWK jwkRsaV1 = jwkSetV1.getKeyByKeyId(RSA_KEY_NAME + "-1");
            assertThat(jwkRsaV1).as("Setup: JWK v1 must exist").isNotNull().isInstanceOf(RSAKey.class);
            PublicKey localPublicKeyRsaV1 = ((RSAKey) jwkRsaV1).toPublicKey(); // Local variable for setup
            log.info("Setup: Fetched JWKS v1 and extracted PublicKey v1");

            // 3. Sign JWT (v1)
            Map<String, Object> claimsV1 = Map.of("sub", "integration-test-user", "scope", "test"); // Use original claims for v1
            log.info("Setup: Signing JWT using key {} (v1)", RSA_KEY_NAME);
            MvcResult signResultV1 = mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(claimsV1)))
                    .andExpect(status().isOk())
                    .andReturn();
            String localJwtStringRsaV1 = objectMapper.readValue(signResultV1.getResponse().getContentAsString(), JwtController.JwtResponse.class).jwt(); // Local variable for setup
            assertThat(localJwtStringRsaV1).as("Setup: JWT v1 string must not be blank").isNotBlank();
            log.info("Setup: Signed JWT v1");

            // 4. Verify JWT (v1) - Basic check to ensure setup worked
            log.info("Setup: Verifying JWT signature (v1) using extracted public key");
            JwtParser parserRsaV1 = Jwts.parser().verifyWith(localPublicKeyRsaV1).build();
            parserRsaV1.parseSignedClaims(localJwtStringRsaV1);
            log.info("Setup: Verified JWT v1 successfully");
            // --- End: Setup steps ---


            // Step 4: Removed checks for static variables
            // assertThat(jwtStringRsaV1).as("RSA JWT v1 from previous test is required").isNotNull();
            // assertThat(publicKeyRsaV1).as("RSA PublicKey v1 from previous test is required").isNotNull();
            // log.info("Static variables (jwtStringRsaV1, publicKeyRsaV1) from previous RSA test are present.");

            // Now, proceed with the original logic of the second test (adapted numbering)

            // 5. Second Rotation (Admin Token)
            log.info("Performing second rotation for {}", RSA_KEY_NAME);
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            Path version2Path = staticTempDir.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("versions/2.json");
            assertThat(Files.exists(version2Path)).isTrue();
            log.info("Verified existence of version 2 file for {}", RSA_KEY_NAME);

            // 6. Fetch JWKS (Expect 2 RSA Keys)
            log.info("Fetching JWKS for {} after second rotation", RSA_KEY_NAME);
            MvcResult jwksResultV1AndV2 = mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys.length()").value(2))
                    .andExpect(jsonPath("$.keys[?(@.kid == '%s')]", RSA_KEY_NAME + "-1").exists())
                    .andExpect(jsonPath("$.keys[?(@.kid == '%s')]", RSA_KEY_NAME + "-2").exists())
                    .andReturn();
            // Store the full JWKSet containing v1 and v2 for later verification
            final JWKSet jwkSetV1AndV2 = JWKSet.parse(jwksResultV1AndV2.getResponse().getContentAsString());
            assertThat(jwkSetV1AndV2.getKeys()).hasSize(2);
            JWK jwk2 = jwkSetV1AndV2.getKeyByKeyId(RSA_KEY_NAME + "-2");
            assertThat(jwk2).isNotNull().isInstanceOf(RSAKey.class);
            PublicKey publicKeyRsaV2 = ((RSAKey) jwk2).toPublicKey(); // Local variable for v2 key
            log.info("JWKS fetch successful, found 2 keys as expected. Extracted PublicKey v2.");

            // 7. Sign JWT (v2 - Signing Token)
            Map<String, Object> claimsV2 = Map.of("sub", "integration-test-user-v2", "scope", "admin");
            log.info("Signing JWT using key {} (v2 - latest)", RSA_KEY_NAME);
            MvcResult signResultV2 = mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(claimsV2)))
                    .andExpect(status().isOk())
                    .andReturn();
            String jwtStringRsaV2 = objectMapper.readValue(signResultV2.getResponse().getContentAsString(), JwtController.JwtResponse.class).jwt(); // Local variable for v2 jwt
            assertThat(jwtStringRsaV2).isNotBlank();
            log.info("JWT signing successful (v2)");

            // 8. Verify JWT (v2) Signature & Header (using only v2 key)
            log.info("Verifying JWT signature (v2) using extracted public key v2");
            JwtParser parserV2 = Jwts.parser().verifyWith(publicKeyRsaV2).build();
            Jws<Claims> jwsV2 = parserV2.parseSignedClaims(jwtStringRsaV2);
            assertThat(jwsV2.getHeader().getKeyId()).isEqualTo(RSA_KEY_NAME + "-2");
            assertThat(jwsV2.getHeader().getAlgorithm()).isEqualTo("RS256");
            assertThat(jwsV2.getPayload().getSubject()).isEqualTo("integration-test-user-v2");
            log.info("JWT verification successful (v2)");

            // 9. Verify Old JWT (v1) using New JWKS (containing v1 & v2)
            log.info("Verifying old JWT (v1 generated during setup) using JWKSet containing v1 & v2");
            // Use the jwkSetV1AndV2 fetched earlier
            final LocatorAdapter<Key> rsaKeyLocator = new LocatorAdapter<Key>() {
                @Override
                protected Key locate(JwsHeader header) {
                    String kid = header.getKeyId();
                    if (kid == null) {
                        log.warn("Key locator: JWT header missing 'kid'");
                        return null;
                    }
                    // Use the JWKSet fetched in step 6
                    JWK jwk = jwkSetV1AndV2.getKeyByKeyId(kid);
                    if (jwk instanceof RSAKey rsaKey) {
                        try {
                            log.debug("Key locator: Found RSA key for kid '{}'", kid);
                            return rsaKey.toPublicKey();
                        } catch (Exception e) {
                            log.error("Key locator: Error converting JWK to PublicKey for kid '{}'", kid, e);
                            return null;
                        }
                    }
                    log.warn("Key locator: No matching RSA key found for kid '{}'", kid);
                    return null;
                }
                public byte[] apply(JwsHeader header) { return null; } // Not needed for RSA verify
            };
            JwtParser parserV1UsingSet = Jwts.parser().keyLocator(rsaKeyLocator).build();
            try {
                // Step 4: Verify the localJwtStringRsaV1 generated during the setup phase
                Jws<Claims> jwsV1VerifiedWithSet = parserV1UsingSet.parseSignedClaims(localJwtStringRsaV1);
                assertThat(jwsV1VerifiedWithSet.getHeader().getKeyId()).isEqualTo(RSA_KEY_NAME + "-1");
                // Step 4: Check subject from v1 claims used during setup
                assertThat(jwsV1VerifiedWithSet.getPayload().getSubject()).isEqualTo("integration-test-user");
                log.info("Verification of old JWT (v1) using JWKSet successful.");
            } catch (Exception e) {
                fail("Verification of RSA JWT v1 using JWKSet containing v1 & v2 failed", e);
            }
            log.info("<<< Finished testRsaFullRotationLifecycleAndVerification (RSA) >>>");
        }
    }


    @Nested
    @DisplayName("EC Key Lifecycle Tests")
            // @TestMethodOrder(MethodOrderer.OrderAnnotation.class) // ---> REMOVED ORDERING
    class EcLifecycleTests {

        // Static vars are removed - no longer passing state between tests this way
        // private static String jwtStringEcV1; // ---> REMOVED
        // private static PublicKey publicKeyEcV1; // ---> REMOVED

        private static final String EC_EXPECTED_ALGORITHM = "ES256"; // As per task req

        @Test
        @DisplayName("Task 5.3a: EC Initial Rotation, Signing, Verification") // Renamed
            // @Order(1) // ---> REMOVED ORDER
        void testEcInitialRotationAndSigningVerification() throws Exception { // Renamed
            log.info(">>> Starting testEcInitialRotationAndSigningVerification (EC) <<<");
            // 1. Initial State Checks
            mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, EC_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isNotFound());

            mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, EC_KEY_NAME))
                            .with(authentication(createAuthenticationToken(EC_SIGNING_TOKEN, List.of("test-ec-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(Collections.emptyMap())))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: JWT key configuration not found for name: " + EC_KEY_NAME));
            log.info("Initial state checks passed for {}", EC_KEY_NAME);

            // 2. First Rotation (Admin Token)
            log.info("Performing first rotation for {}", EC_KEY_NAME);
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, EC_KEY_NAME))
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            Path version1EcPath = staticTempDir.resolve("jwt/keys").resolve(EC_KEY_NAME).resolve("versions/1.json");
            assertThat(Files.exists(version1EcPath)).isTrue();
            log.info("Verified existence of version 1 file for {}", EC_KEY_NAME);

            // 3. Fetch JWKS (Expect 1 EC Key)
            log.info("Fetching JWKS for {} after first rotation", EC_KEY_NAME);
            MvcResult jwksResult = mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, EC_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys.length()").value(1))
                    .andExpect(jsonPath("$.keys[0].kty").value("EC"))
                    .andExpect(jsonPath("$.keys[0].crv").value("P-256"))
                    .andExpect(jsonPath("$.keys[0].kid").value(EC_KEY_NAME + "-1"))
                    .andExpect(jsonPath("$.keys[0].alg").value(EC_EXPECTED_ALGORITHM))
                    .andReturn();
            JWKSet jwkSetEcV1 = JWKSet.parse(jwksResult.getResponse().getContentAsString());
            JWK jwkEcV1 = jwkSetEcV1.getKeyByKeyId(EC_KEY_NAME + "-1");
            assertThat(jwkEcV1).isNotNull().isInstanceOf(ECKey.class);
            // Use local variable for public key
            PublicKey localPublicKeyEcV1 = ((ECKey) jwkEcV1).toPublicKey();
            // publicKeyEcV1 = ((ECKey) jwkEcV1).toPublicKey(); // ---> REMOVED STATIC ASSIGNMENT
            log.info("JWKS fetch successful, found 1 EC key as expected. Extracted PublicKey v1.");

            // 4. Sign JWT (v1 - EC Signing Token)
            Map<String, Object> claims = Map.of("sub", "ec-test-user", "role", "tester");
            log.info("Signing JWT using key {} (v1)", EC_KEY_NAME);
            MvcResult signResult = mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, EC_KEY_NAME))
                            .with(authentication(createAuthenticationToken(EC_SIGNING_TOKEN, List.of("test-ec-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(claims)))
                    .andExpect(status().isOk())
                    .andReturn();
            // Use local variable for JWT string
            String localJwtStringEcV1 = objectMapper.readValue(signResult.getResponse().getContentAsString(), JwtController.JwtResponse.class).jwt();
            // jwtStringEcV1 = objectMapper.readValue(signResult.getResponse().getContentAsString(), JwtController.JwtResponse.class).jwt(); // ---> REMOVED STATIC ASSIGNMENT
            assertThat(localJwtStringEcV1).isNotBlank();
            log.info("JWT signing successful (v1)");

            // 5. Verify JWT (v1) Signature & Header
            log.info("Verifying JWT signature (v1) using extracted public key");
            // Use local variables for verification
            JwtParser parserEcV1 = Jwts.parser().verifyWith(localPublicKeyEcV1).build();
            Jws<Claims> jwsEcV1 = parserEcV1.parseSignedClaims(localJwtStringEcV1);
            assertThat(jwsEcV1.getHeader().getKeyId()).isEqualTo(EC_KEY_NAME + "-1");
            assertThat(jwsEcV1.getHeader().getAlgorithm()).isEqualTo(EC_EXPECTED_ALGORITHM);
            assertThat(jwsEcV1.getPayload().getSubject()).isEqualTo("ec-test-user");
            log.info("JWT verification successful (v1)");
            log.info("<<< Finished testEcInitialRotationAndSigningVerification (EC) >>>");
        }

        @Test
        @DisplayName("Task 5.3b: EC Full Rotation Lifecycle and Verification") // Renamed
            // @Order(2) // ---> REMOVED ORDER
        void testEcRotationLifecycleAndVerification() throws Exception { // Renamed
            log.info(">>> Starting testEcRotationLifecycleAndVerification (EC) <<<");

            // --- Start: Setup steps previously in @Order(1) test ---
            log.info("Performing initial setup steps (first rotation, sign v1) within test");

            // 1. Perform First Rotation (Admin Token)
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, EC_KEY_NAME))
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            Path version1EcPath = staticTempDir.resolve("jwt/keys").resolve(EC_KEY_NAME).resolve("versions/1.json");
            assertThat(Files.exists(version1EcPath)).as("Setup: Version 1 file must exist").isTrue();
            log.info("Setup: First rotation completed");

            // 2. Fetch JWKS (v1) and Extract Public Key v1
            MvcResult jwksResultV1 = mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, EC_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys.length()").value(1))
                    .andReturn();
            JWKSet jwkSetEcV1 = JWKSet.parse(jwksResultV1.getResponse().getContentAsString());
            JWK jwkEcV1 = jwkSetEcV1.getKeyByKeyId(EC_KEY_NAME + "-1");
            assertThat(jwkEcV1).as("Setup: JWK v1 must exist").isNotNull().isInstanceOf(ECKey.class);
            PublicKey localPublicKeyEcV1 = ((ECKey) jwkEcV1).toPublicKey(); // Local variable
            log.info("Setup: Fetched JWKS v1 and extracted PublicKey v1");

            // 3. Sign JWT (v1)
            Map<String, Object> claimsV1 = Map.of("sub", "ec-test-user", "role", "tester");
            MvcResult signResultV1 = mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, EC_KEY_NAME))
                            .with(authentication(createAuthenticationToken(EC_SIGNING_TOKEN, List.of("test-ec-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(claimsV1)))
                    .andExpect(status().isOk())
                    .andReturn();
            String localJwtStringEcV1 = objectMapper.readValue(signResultV1.getResponse().getContentAsString(), JwtController.JwtResponse.class).jwt(); // Local variable
            assertThat(localJwtStringEcV1).as("Setup: JWT v1 string must not be blank").isNotBlank();
            log.info("Setup: Signed JWT v1");

            // 4. Verify JWT (v1) - Basic check to ensure setup worked
            JwtParser parserEcV1 = Jwts.parser().verifyWith(localPublicKeyEcV1).build();
            parserEcV1.parseSignedClaims(localJwtStringEcV1);
            log.info("Setup: Verified JWT v1 successfully");
            // --- End: Setup steps ---


            // Ensure previous test ran and populated static vars ---> REMOVED these checks
            // assertThat(jwtStringEcV1).as("EC JWT v1 from previous test is required").isNotNull(); // ---> REMOVED
            // assertThat(publicKeyEcV1).as("EC PublicKey v1 from previous test is required").isNotNull(); // ---> REMOVED
            // log.info("Static variables (jwtStringEcV1, publicKeyEcV1) from previous test are present."); // ---> REMOVED

            // Now, proceed with the original logic of the second test

            // 5. Second Rotation (Admin Token)
            log.info("Performing second rotation for {}", EC_KEY_NAME);
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, EC_KEY_NAME))
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            Path version2EcPath = staticTempDir.resolve("jwt/keys").resolve(EC_KEY_NAME).resolve("versions/2.json");
            assertThat(Files.exists(version2EcPath)).isTrue();
            log.info("Verified existence of version 2 file for {}", EC_KEY_NAME);

            // 6. Fetch JWKS (Expect 2 EC Keys)
            log.info("Fetching JWKS for {} after second rotation", EC_KEY_NAME);
            MvcResult jwksResultV2 = mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, EC_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys.length()").value(2))
                    .andExpect(jsonPath("$.keys[?(@.kid == '%s')]", EC_KEY_NAME + "-1").exists())
                    .andExpect(jsonPath("$.keys[?(@.kid == '%s')]", EC_KEY_NAME + "-2").exists())
                    .andReturn();
            // Store the full JWKSet containing v1 and v2 for later verification
            final JWKSet jwkSetEcV1AndV2 = JWKSet.parse(jwksResultV2.getResponse().getContentAsString());
            assertThat(jwkSetEcV1AndV2.getKeys()).hasSize(2);
            JWK jwkEcV2 = jwkSetEcV1AndV2.getKeyByKeyId(EC_KEY_NAME + "-2");
            assertThat(jwkEcV2).isNotNull().isInstanceOf(ECKey.class);
            PublicKey publicKeyEcV2 = ((ECKey) jwkEcV2).toPublicKey();
            log.info("JWKS fetch successful, found 2 EC keys as expected. Extracted PublicKey v2.");

            // 7. Sign JWT (v2 - EC Signing Token)
            Map<String, Object> claimsV2 = Map.of("sub", "ec-test-user-v2", "scope", "read");
            log.info("Signing JWT using key {} (v2 - latest)", EC_KEY_NAME);
            MvcResult signResultV2 = mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, EC_KEY_NAME))
                            .with(authentication(createAuthenticationToken(EC_SIGNING_TOKEN, List.of("test-ec-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(claimsV2)))
                    .andExpect(status().isOk())
                    .andReturn();
            String jwtStringEcV2 = objectMapper.readValue(signResultV2.getResponse().getContentAsString(), JwtController.JwtResponse.class).jwt();
            assertThat(jwtStringEcV2).isNotBlank();
            log.info("JWT signing successful (v2)");

            // 8. Verify JWT (v2) Signature & Header (using only v2 key)
            log.info("Verifying JWT signature (v2) using extracted public key v2");
            JwtParser parserEcV2 = Jwts.parser().verifyWith(publicKeyEcV2).build();
            Jws<Claims> jwsEcV2 = parserEcV2.parseSignedClaims(jwtStringEcV2);
            assertThat(jwsEcV2.getHeader().getKeyId()).isEqualTo(EC_KEY_NAME + "-2");
            assertThat(jwsEcV2.getHeader().getAlgorithm()).isEqualTo(EC_EXPECTED_ALGORITHM);
            assertThat(jwsEcV2.getPayload().getSubject()).isEqualTo("ec-test-user-v2");
            log.info("JWT verification successful (v2)");

            // 9. Verify Old JWT (v1) using New JWKS (containing v1 & v2)
            log.info("Verifying old JWT (v1 generated during setup) using JWKSet containing v1 & v2");
            // Use the jwkSetEcV1AndV2 fetched earlier
            final LocatorAdapter<Key> ecKeyLocator = new LocatorAdapter<Key>() {
                @Override
                protected Key locate(JwsHeader header) {
                    String kid = header.getKeyId();
                    if (kid == null) {
                        log.warn("Key locator: JWT header missing 'kid'");
                        return null;
                    }
                    // Use the JWKSet fetched in step 6
                    JWK jwk = jwkSetEcV1AndV2.getKeyByKeyId(kid);
                    if (jwk instanceof ECKey ecKey) {
                        try {
                            log.debug("Key locator: Found EC key for kid '{}'", kid);
                            return ecKey.toPublicKey();
                        } catch (Exception e) {
                            log.error("Key locator: Error converting JWK to PublicKey for kid '{}'", kid, e);
                            return null;
                        }
                    }
                    log.warn("Key locator: No matching EC key found for kid '{}'", kid);
                    return null;
                }
                public byte[] apply(JwsHeader header) { return null; } // Not needed for EC verify
            };
            JwtParser parserEcV1UsingSet = Jwts.parser().keyLocator(ecKeyLocator).build();
            try {
                // Verify the localJwtStringEcV1 generated during the setup phase
                Jws<Claims> jwsEcV1VerifiedWithSet = parserEcV1UsingSet.parseSignedClaims(localJwtStringEcV1);
                assertThat(jwsEcV1VerifiedWithSet.getHeader().getKeyId()).isEqualTo(EC_KEY_NAME + "-1");
                assertThat(jwsEcV1VerifiedWithSet.getPayload().getSubject()).isEqualTo("ec-test-user"); // Check subject from v1 claims
                log.info("Verification of old JWT (v1) using JWKSet successful.");
            } catch (Exception e) {
                fail("Verification of EC JWT v1 using JWKSet containing v1 & v2 failed", e);
            }
            log.info("<<< Finished testEcRotationLifecycleAndVerification (EC) >>>");
        }
    }


    @Nested
    @DisplayName("Task 5.4: Security Tests")
    class SecurityTests {

        // Setup method to ensure at least one key exists for tests that need it
        @BeforeEach
        void ensureKeyExists() throws Exception {
            log.info(">>> Running @BeforeEach ensureKeyExists for SecurityTests <<<");
            // Check if the key's JWKS endpoint returns 200 OK (key exists) or 404 (key doesn't exist)
            MvcResult result = mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME))
                            .with(anonymous())) // Use anonymous as JWKS should be public
                    .andReturn();

            if (result.getResponse().getStatus() == HttpStatus.NOT_FOUND.value()) {
                log.info("Key '{}' does not exist, rotating once for SecurityTests.", RSA_KEY_NAME);
                mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME))
                                .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                        .andExpect(status().isNoContent());
                log.info("Key '{}' created.", RSA_KEY_NAME);
            } else if (result.getResponse().getStatus() == HttpStatus.OK.value()) {
                log.info("Key '{}' already exists for SecurityTests.", RSA_KEY_NAME);
            } else {
                log.warn("Unexpected status {} when checking for key '{}' existence.", result.getResponse().getStatus(), RSA_KEY_NAME);
            }
            log.info("<<< Finished @BeforeEach ensureKeyExists for SecurityTests >>>");
        }

        @Test
        @DisplayName("/sign POST without token returns 403 (Forbidden by Policy)")
        void signWithoutToken_shouldReturn403() throws Exception {
            log.info("Testing POST {} without token", String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME));
            mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}")
                            .with(anonymous()))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("/rotate POST without token returns 403") // Should be 403 due to policy check after auth filter
        void rotateWithoutToken_shouldReturn403() throws Exception {
            log.info("Testing POST {} without token", String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME));
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isForbidden()); // Expecting Forbidden due to policy check failure
        }

        @Test
        @DisplayName("/sign POST with invalid token returns 403")
        void signWithInvalidToken_shouldReturn403() throws Exception {
            log.info("Testing POST {} with invalid token", String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME));
            mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(INVALID_TOKEN, Collections.emptyList())))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isForbidden()); // Policy filter should deny
        }

        @Test
        @DisplayName("/rotate POST with invalid token returns 403")
        void rotateWithInvalidToken_shouldReturn403() throws Exception {
            log.info("Testing POST {} with invalid token", String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME));
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(INVALID_TOKEN, Collections.emptyList()))))
                    .andExpect(status().isForbidden()); // Policy filter should deny
        }

        @Test
        @DisplayName("/rotate POST with rsa-signing-token returns 403")
        void rotateWithSigningToken_shouldReturn403() throws Exception {
            log.info("Testing POST {} with signing token (should be forbidden)", String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME));
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy")))))
                    .andExpect(status().isForbidden()); // Policy check failure
        }

        @Test
        @DisplayName("/sign POST with admin-token returns 200 (Policy Allows)")
        void signWithAdminToken_shouldReturn200() throws Exception {
            log.info("Testing POST {} with admin token (should be allowed)", String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME));
            Map<String, Object> claims = Map.of("sub", "admin-signing-test");
            mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(claims)))
                    .andExpect(status().isOk()); // Policy check should pass based on test-root-policy
        }

        @Test
        @DisplayName("/jwks GET without token returns 200")
        void jwksWithoutToken_shouldReturn200() throws Exception {
            log.info("Testing GET {} without token (should be public)", String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME));
            // Assumes key RSA_KEY_NAME exists (from @BeforeEach)
            mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME))
                            .with(anonymous()))
                    .andExpect(status().isOk()); // Verifies permitAll() in SecurityConfig
        }
    }
    // Task 5.5 tests (Error Handling) will go here...
    // Task 5.6 tests (Audit) will go here...

}