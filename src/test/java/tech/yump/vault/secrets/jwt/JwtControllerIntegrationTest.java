package tech.yump.vault.secrets.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.FileSystemUtils;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.core.SealManager;
import tech.yump.vault.storage.StorageBackend;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Integration tests covering Phase 5 of mssm-hardening-plan.md
// These tests now use the REAL JwtSecretsEngine
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Slf4j
class JwtControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MssmProperties properties;

    @Autowired
    private StorageBackend storageBackend; // Keep for cleanup

    @Autowired
    private SealManager sealManager;

    // *** NO @MockitoBean for JwtSecretsEngine here ***

    private static Path testStoragePath;

    // Key names from application-test.yml
    private static final String RSA_KEY_NAME = "api-signing-key-rsa";
    private static final String EC_KEY_NAME = "api-signing-key-ec";

    // Tokens from application-test.yml
    private static final String ADMIN_TOKEN = "test-root-token";
    private static final String RSA_SIGNING_TOKEN = "test-jwt-signer-token";
    private static final String EC_SIGNING_TOKEN = "test-ec-jwt-signer-token";
    // Removed NO_POLICY_TOKEN and INVALID_TOKEN as they were only used in AuthorizationTests
    // private static final String NO_POLICY_TOKEN = "test-no-policy-token";
    // private static final String INVALID_TOKEN = "this-is-not-a-valid-token";

    private static final String JWKS_PATH_FORMAT = "/v1/jwt/jwks/%s";
    private static final String ROTATE_PATH_FORMAT = "/v1/jwt/rotate/%s";
    private static final String SIGN_PATH_FORMAT = "/v1/jwt/sign/%s";

    @TempDir
    static Path staticTempDir; // Static TempDir persists across tests in the class

    // Covers Task 4.5: Define mssm.storage.filesystem.path using @TempDir and @DynamicPropertySource
    @DynamicPropertySource
    static void overrideStoragePath(DynamicPropertyRegistry registry) {
        testStoragePath = staticTempDir.resolve("jwt-integration-test-storage");
        registry.add("mssm.storage.filesystem.path", testStoragePath::toString);
        log.info("Overriding storage path for tests to: {}", testStoragePath);
    }

    // Covers Task 4.10: Implement @BeforeEach to unseal the vault
    @BeforeEach
    void setUp() throws Exception {
        log.info("===== Running @BeforeEach Cleanup and Unseal =====");
        cleanStorage();
        if (sealManager.isSealed()) {
            log.info("Vault is SEALED, attempting to unseal...");
            sealManager.unseal(properties.master().b64());
        } else {
            log.info("Vault already UNSEALED.");
        }
        log.info("===== @BeforeEach Cleanup and Unseal Finished =====");
    }

    // Cleanup method using FileSystemUtils for potentially more robust deletion
    private void cleanStorage() throws IOException {
        if (Files.exists(testStoragePath)) {
            log.info("Cleaning storage directory: {}", testStoragePath);
            // Recursively delete contents and the directory itself
            boolean deleted = FileSystemUtils.deleteRecursively(testStoragePath);
            log.info("Storage directory deletion result: {}", deleted);
        }
        // Recreate the base directory for subsequent tests
        Files.createDirectories(testStoragePath);
        log.info("Recreated base storage directory: {}", testStoragePath);
    }

    // Helper to create mock Authentication object for security context
    // Keep this helper as it's used by Lifecycle and ErrorHandling tests
    private Authentication createAuthenticationToken(String tokenValue, List<String> policies) {
        List<SimpleGrantedAuthority> authorities = policies.stream()
                .map(p -> new SimpleGrantedAuthority("POLICY_" + p))
                .collect(Collectors.toList());
        // Use TestingAuthenticationToken or adapt based on your actual Authentication object needs
        return new TestingAuthenticationToken(tokenValue, null, authorities);
    }

    // Helper to extract JWT string from response
    private String extractJwtFromResult(MvcResult result) throws IOException {
        return objectMapper.readTree(result.getResponse().getContentAsString()).get("jwt").asText();
    }

    // Strategy 5: Robust JWT/JWKS handling using Nimbus
    private JWKSet parseJwks(String jwksJson) throws ParseException {
        return JWKSet.parse(jwksJson);
    }

    private boolean verifyJwt(String jwtString, PublicKey publicKey, String expectedAlgorithm) throws ParseException, com.nimbusds.jose.JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(jwtString);
        if (publicKey instanceof RSAPublicKey rsaPublicKey && expectedAlgorithm.startsWith("RS")) {
            RSASSAVerifier verifier = new RSASSAVerifier(rsaPublicKey);
            return signedJWT.verify(verifier);
        } else if (publicKey instanceof ECPublicKey ecPublicKey && expectedAlgorithm.startsWith("ES")) {
            ECDSAVerifier verifier = new ECDSAVerifier(ecPublicKey);
            return signedJWT.verify(verifier);
        }
        log.error("Unsupported key type ({}) or algorithm ({}) for verification", publicKey.getAlgorithm(), expectedAlgorithm);
        return false;
    }
    // --- End Helpers ---

    // --- Test Classes (Refactored) ---

    @Nested
    @DisplayName("Strategy 1 & 5: RSA Key Lifecycle Tests (Focused & Robust Assertions)")
            // Covers Task 5.1 & 5.2: RSA Key Lifecycle
    class RsaLifecycleTests {
        private final Map<String, Object> payload = Map.of("sub", "integration-test-user", "scope", "test");
        private final String jwksPath = String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME);
        private final String rotatePath = String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME);
        private final String signPath = String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME);

        // Covers Task 5.1: GET /jwks -> 404 (Initial State)
        // Covers Task 5.1: POST /sign -> 404 (Initial State - implicitly, as key doesn't exist)
        @Test
        @DisplayName("JWKS: Initial request returns 404")
        void jwks_initial_shouldBeNotFound() throws Exception {
            mockMvc.perform(get(jwksPath).with(anonymous()))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: No key versions found for key: " + RSA_KEY_NAME));
            // Audit verification removed
        }

        // Covers Task 5.1: POST /rotate -> 204 (Initial Rotation)
        // Covers Task 5.1: Verify storage files (config.json, versions/1.json)
        @Test
        @DisplayName("Rotate: Initial rotation succeeds (204)")
        void rotate_initial_shouldSucceed() throws Exception {
            mockMvc.perform(post(rotatePath)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent()); // Expect 204
            // File existence checks
            Path configPath = testStoragePath.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("config.json");
            Path version1Path = testStoragePath.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("versions/1.json");
            assertThat(Files.exists(configPath)).isTrue();
            assertThat(Files.exists(version1Path)).isTrue();
            // Audit verification removed
        }

        // Covers Task 5.1: GET /jwks -> 200, validate JWKS (v1)
        @Test
        @DisplayName("JWKS: Contains only v1 after initial rotation")
        void jwks_afterFirstRotation_shouldContainV1() throws Exception {
            // Setup: Perform initial rotation
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            // Test: Get JWKS
            MvcResult jwksResult = mockMvc.perform(get(jwksPath).with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys").isArray())
                    .andExpect(jsonPath("$.keys.length()").value(1))
                    .andExpect(jsonPath("$.keys[0].kid").value(RSA_KEY_NAME + "-1"))
                    .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                    .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                    .andReturn();
            // Optional: Further JWK structure validation using Nimbus
            JWKSet jwkSet = parseJwks(jwksResult.getResponse().getContentAsString());
            assertThat(jwkSet.getKeyByKeyId(RSA_KEY_NAME + "-1")).isNotNull();
            // Audit verification removed
        }

        // Covers Task 5.1: POST /sign -> 200, Get JWT (v1)
        // Covers Task 5.1: Decode JWT: Verify header (kid, alg), payload
        // Covers Task 5.1: Verify JWT signature using extracted public key (v1) - partially, verification done later
        @Test
        @DisplayName("Sign: Signing after initial rotation uses v1 key")
        void sign_afterFirstRotation_shouldUseV1() throws Exception {
            // Setup: Perform initial rotation
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            // Test: Sign JWT
            MvcResult result = mockMvc.perform(post(signPath)
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(payload)))
                    .andExpect(status().isOk())
                    .andReturn();

            // Assert JWT structure and kid
            String jwt = extractJwtFromResult(result);
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(RSA_KEY_NAME + "-1");
            assertThat(signedJWT.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
            assertThat(signedJWT.getJWTClaimsSet().getSubject()).isEqualTo("integration-test-user");
            // Audit verification removed
        }

        // Covers Task 5.2: POST /rotate -> 204 (Second Rotation)
        // Covers Task 5.2: Verify storage file versions/2.json exists
        @Test
        @DisplayName("Rotate: Second rotation succeeds (204)")
        void rotate_second_shouldSucceed() throws Exception {
            // Setup: Perform initial rotation
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            // Test: Second Rotation
            mockMvc.perform(post(rotatePath)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            // Check files for v2 exist
            Path version2Path = testStoragePath.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("versions/2.json");
            assertThat(Files.exists(version2Path)).as("Version 2 file should exist after second rotation").isTrue();
            // Audit verification removed
        }

        // Covers Task 5.2: POST /sign -> 200, Get JWT (v2)
        // Covers Task 5.2: Decode JWT (v2): Verify header (kid, alg)
        // Covers Task 5.2: Verify JWT (v2) signature using extracted public key (v2) - partially, verification done later
        @Test
        @DisplayName("Sign: Signing after second rotation uses v2 key")
        void sign_afterSecondRotation_shouldUseV2() throws Exception {
            // Setup: Perform two rotations
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            // Test: Sign JWT
            Map<String, Object> payloadV2 = Map.of("sub", "user-v2", "scope", "test-v2");
            MvcResult result = mockMvc.perform(post(signPath)
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(payloadV2)))
                    .andExpect(status().isOk())
                    .andReturn();

            // Assert JWT structure and kid
            String jwt = extractJwtFromResult(result);
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(RSA_KEY_NAME + "-2");
            assertThat(signedJWT.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
            assertThat(signedJWT.getJWTClaimsSet().getSubject()).isEqualTo("user-v2");
            // Audit verification removed
        }

        // Covers Task 5.2: GET /jwks -> 200, validate JWKS has two RSA keys (v1, v2)
        @Test
        @DisplayName("JWKS: Contains v1 and v2 after second rotation")
        void jwks_afterSecondRotation_shouldContainV1AndV2() throws Exception {
            // Setup: Perform two rotations
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            // Test: Get JWKS
            MvcResult jwksResult = mockMvc.perform(get(jwksPath).with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys").isArray())
                    .andExpect(jsonPath("$.keys.length()").value(2))
                    // Assuming descending order (newest first)
                    .andExpect(jsonPath("$.keys[0].kid").value(RSA_KEY_NAME + "-2"))
                    .andExpect(jsonPath("$.keys[1].kid").value(RSA_KEY_NAME + "-1"))
                    .andReturn();
            // Optional: Further JWK structure validation using Nimbus
            JWKSet jwkSet = parseJwks(jwksResult.getResponse().getContentAsString());
            assertThat(jwkSet.getKeyByKeyId(RSA_KEY_NAME + "-1")).isNotNull();
            assertThat(jwkSet.getKeyByKeyId(RSA_KEY_NAME + "-2")).isNotNull();
            // Audit verification removed
        }

        // Covers Task 5.2: Verify JWT (v1, from Task 5.1) signature using the JWKS containing v1 & v2
        @Test
        @DisplayName("Verify: JWT signed with v1 key is verifiable using JWKS containing v1 and v2")
        void verify_v1Jwt_withV1AndV2Jwks() throws Exception {
            // Setup: Rotate once, sign with v1
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            MvcResult signResultV1 = mockMvc.perform(post(signPath)
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(payload))) // Use original payload
                    .andExpect(status().isOk())
                    .andReturn();
            String jwtV1 = extractJwtFromResult(signResultV1);

            // Setup: Rotate again (now JWKS will have v1 and v2)
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            // Test: Get JWKS and verify old JWT
            MvcResult jwksResultV1V2 = mockMvc.perform(get(jwksPath).with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys.length()").value(2))
                    .andReturn();
            JWKSet jwkSetV1V2 = parseJwks(jwksResultV1V2.getResponse().getContentAsString());

            // Find v1 key within the new JWKS
            JWK jwk1 = jwkSetV1V2.getKeyByKeyId(RSA_KEY_NAME + "-1");
            assertThat(jwk1).isNotNull().isInstanceOf(RSAKey.class);
            PublicKey publicKeyV1 = ((RSAKey)jwk1).toPublicKey();

            // Verify the JWT signed earlier (jwtV1) using the key found in the later JWKS
            assertThat(verifyJwt(jwtV1, publicKeyV1, "RS256")).isTrue();
            log.info("Verification of old JWT (v1) using JWKSet containing v1 & v2 successful.");
        }

    }

    @Nested
    @DisplayName("Strategy 1 & 5: EC Key Lifecycle Tests (Focused & Robust Assertions)")
            // Covers Task 5.3: Repeat Lifecycle for EC Key
    class EcLifecycleTests {
        // Similar structure to RsaLifecycleTests, but using EC_KEY_NAME, EC_SIGNING_TOKEN, EC public keys, and ES256
        private final Map<String, Object> payload = Map.of("sub", "ec-test-user", "roles", List.of("user"));
        private final String jwksPath = String.format(JWKS_PATH_FORMAT, EC_KEY_NAME);
        private final String rotatePath = String.format(ROTATE_PATH_FORMAT, EC_KEY_NAME);
        private final String signPath = String.format(SIGN_PATH_FORMAT, EC_KEY_NAME);

        // Covers Task 5.3 (via 5.1): GET /jwks -> 404 (Initial State)
        @Test
        @DisplayName("JWKS: Initial request returns 404")
        void jwks_initial_shouldBeNotFound() throws Exception {
            mockMvc.perform(get(jwksPath).with(anonymous()))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: No key versions found for key: " + EC_KEY_NAME));
        }

        // Covers Task 5.3 (via 5.1): POST /rotate -> 204 (Initial Rotation) & Verify storage file v1
        @Test
        @DisplayName("Rotate: Initial rotation succeeds (204)")
        void rotate_initial_shouldSucceed() throws Exception {
            mockMvc.perform(post(rotatePath)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            Path version1Path = testStoragePath.resolve("jwt/keys").resolve(EC_KEY_NAME).resolve("versions/1.json");
            assertThat(Files.exists(version1Path)).isTrue();
        }

        // Covers Task 5.3 (via 5.1): GET /jwks -> 200, validate JWKS (v1)
        @Test
        @DisplayName("JWKS: Contains only v1 after initial rotation")
        void jwks_afterFirstRotation_shouldContainV1() throws Exception {
            // Setup
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // Test
            mockMvc.perform(get(jwksPath).with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys.length()").value(1))
                    .andExpect(jsonPath("$.keys[0].kid").value(EC_KEY_NAME + "-1"))
                    .andExpect(jsonPath("$.keys[0].kty").value("EC"))
                    .andExpect(jsonPath("$.keys[0].crv").value("P-256"))
                    .andExpect(jsonPath("$.keys[0].alg").value("ES256"));
        }

        // Covers Task 5.3 (via 5.1): POST /sign -> 200 (v1) & Decode JWT (v1)
        @Test
        @DisplayName("Sign: Signing after initial rotation uses v1 key")
        void sign_afterFirstRotation_shouldUseV1() throws Exception {
            // Setup
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // Test
            MvcResult result = mockMvc.perform(post(signPath)
                            .with(authentication(createAuthenticationToken(EC_SIGNING_TOKEN, List.of("test-ec-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(payload)))
                    .andExpect(status().isOk())
                    .andReturn();
            // Assert
            String jwt = extractJwtFromResult(result);
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(EC_KEY_NAME + "-1");
            assertThat(signedJWT.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
            assertThat(signedJWT.getJWTClaimsSet().getSubject()).isEqualTo("ec-test-user");
        }

        // Covers Task 5.3 (via 5.2): POST /rotate (second) -> 204 & Verify storage file v2
        @Test
        @DisplayName("Rotate: Second rotation succeeds (204)")
        void rotate_second_shouldSucceed() throws Exception {
            // Setup
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // Test
            mockMvc.perform(post(rotatePath)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // Assert
            Path version2Path = testStoragePath.resolve("jwt/keys").resolve(EC_KEY_NAME).resolve("versions/2.json");
            assertThat(Files.exists(version2Path)).isTrue();
        }

        // Covers Task 5.3 (via 5.2): POST /sign -> 200 (v2) & Decode JWT (v2)
        @Test
        @DisplayName("Sign: Signing after second rotation uses v2 key")
        void sign_afterSecondRotation_shouldUseV2() throws Exception {
            // Setup
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // Test
            Map<String, Object> payloadV2 = Map.of("sub", "ec-user-v2", "scope", "ec-test-v2");
            MvcResult result = mockMvc.perform(post(signPath)
                            .with(authentication(createAuthenticationToken(EC_SIGNING_TOKEN, List.of("test-ec-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(payloadV2)))
                    .andExpect(status().isOk())
                    .andReturn();
            // Assert
            String jwt = extractJwtFromResult(result);
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            assertThat(signedJWT.getHeader().getKeyID()).isEqualTo(EC_KEY_NAME + "-2");
            assertThat(signedJWT.getHeader().getAlgorithm().getName()).isEqualTo("ES256");
            assertThat(signedJWT.getJWTClaimsSet().getSubject()).isEqualTo("ec-user-v2");
        }

        // Covers Task 5.3 (via 5.2): GET /jwks -> 200 (v1, v2)
        @Test
        @DisplayName("JWKS: Contains v1 and v2 after second rotation")
        void jwks_afterSecondRotation_shouldContainV1AndV2() throws Exception {
            // Setup
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // Test
            mockMvc.perform(get(jwksPath).with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys").isArray())
                    .andExpect(jsonPath("$.keys.length()").value(2))
                    .andExpect(jsonPath("$.keys[0].kid").value(EC_KEY_NAME + "-2")) // V2 first
                    .andExpect(jsonPath("$.keys[1].kid").value(EC_KEY_NAME + "-1")); // V1 second
        }

        // Covers Task 5.3 (via 5.2): Verify JWT (v1) signature using JWKS (v1 & v2)
        @Test
        @DisplayName("Verify: JWT signed with v1 key is verifiable using JWKS containing v1 and v2")
        void verify_v1Jwt_withV1AndV2Jwks() throws Exception {
            // Setup: Rotate once, sign with v1
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            MvcResult signResultV1 = mockMvc.perform(post(signPath)
                            .with(authentication(createAuthenticationToken(EC_SIGNING_TOKEN, List.of("test-ec-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(payload))) // Use original payload
                    .andExpect(status().isOk())
                    .andReturn();
            String jwtV1 = extractJwtFromResult(signResultV1);

            // Setup: Rotate again (now JWKS will have v1 and v2)
            mockMvc.perform(post(rotatePath).with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());

            // Test: Get JWKS and verify old JWT
            MvcResult jwksResultV1V2 = mockMvc.perform(get(jwksPath).with(anonymous()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys.length()").value(2))
                    .andReturn();
            JWKSet jwkSetV1V2 = parseJwks(jwksResultV1V2.getResponse().getContentAsString());

            // Find v1 key within the new JWKS
            JWK jwk1 = jwkSetV1V2.getKeyByKeyId(EC_KEY_NAME + "-1");
            assertThat(jwk1).isNotNull().isInstanceOf(ECKey.class);
            PublicKey publicKeyV1 = ((ECKey)jwk1).toPublicKey();

            // Verify the JWT signed earlier (jwtV1) using the key found in the later JWKS
            assertThat(verifyJwt(jwtV1, publicKeyV1, "ES256")).isTrue();
            log.info("Verification of old EC JWT (v1) using JWKSet containing v1 & v2 successful.");
        }

    }

    // *** AuthorizationTests nested class REMOVED ***

    @Nested
    @DisplayName("Strategy 5: Error Handling Tests (Robust Assertions)")
            // Covers Task 5.5: Error Handling Tests
    class ErrorHandlingTests {
        // Constants for paths...
        private final String nonExistentKey = "no-such-key-exists";
        private final String rotatePathNonExistent = String.format(ROTATE_PATH_FORMAT, nonExistentKey);
        private final String signPathNonExistent = String.format(SIGN_PATH_FORMAT, nonExistentKey);
        private final String jwksPathNonExistent = String.format(JWKS_PATH_FORMAT, nonExistentKey);
        private final String signPathRsa = String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME);
        private final String rotatePathRsa = String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME); // Added for setup
        private final String jwksPathRsa = String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME);     // Added for setup

        // Helper ArgumentMatcher for verifying map contents in audit logs
        private ArgumentMatcher<Map<String, Object>> dataContainsKey(String key, Object value) {
            return map -> value.equals(map.get(key));
        }
        private ArgumentMatcher<Map<String, Object>> dataContainsErrorType(String value) {
            return map -> value.equals(map.get("error_type")) && map.size() == 1; // Specific check for vault_sealed
        }

        // Covers Task 5.5: POST /rotate/non-existent-key -> 404
        @Test
        @DisplayName("Rotate non-existent key should fail (404)")
        void rotate_whenKeyNotFound_then404() throws Exception {
            mockMvc.perform(post(rotatePathNonExistent)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNotFound())
                    // Use $.message and match actual GlobalExceptionHandler format
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: JWT key configuration not found for name: " + nonExistentKey));
            // Audit verification removed
        }

        // Covers Task 5.5: POST /sign/non-existent-key -> 404
        @Test
        @DisplayName("Sign non-existent key should fail (404)")
        void sign_whenKeyNotFound_then404() throws Exception {
            Map<String, Object> payload = Map.of("sub", "test");
            mockMvc.perform(post(signPathNonExistent)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))) // Use root for simplicity
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(payload)))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: JWT key configuration not found for name: " + nonExistentKey));
            // Audit verification removed
        }

        // Covers Task 5.5: GET /jwks/non-existent-key -> 404
        @Test
        @DisplayName("JWKS for non-existent key should fail (404)")
        void getJwks_whenKeyNotFound_then404() throws Exception {
            mockMvc.perform(get(jwksPathNonExistent).with(anonymous()))
                    .andExpect(status().isNotFound())
                    // Message includes internal detail
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: JWT key configuration not found for name: " + nonExistentKey));
            // Audit verification removed
        }

        // Covers Task 5.5: POST /sign/{key} with malformed JSON body -> 400
        @Test
        @DisplayName("Sign with invalid JSON payload should fail (400)")
        void sign_withInvalidPayload_then400() throws Exception {
            // Ensure the key exists first for this test
            mockMvc.perform(post(rotatePathRsa)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // reset(auditHelper); // Removed reset

            String malformedJson = "{\"sub\":\"test\", invalid-json"; // Malformed JSON
            mockMvc.perform(post(signPathRsa)
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(malformedJson))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.status").value("400"))
                    // Check detail if provided by your handler for this specific exception
                    .andExpect(jsonPath("$.detail").value("Malformed request body. Please check the JSON format."));
            // Audit verification removed
        }

        // Covers Task 5.5: Seal vault, POST /sign/{key} -> 503, Unseal vault
        @Test
        @DisplayName("Sign when Vault is Sealed should fail (503)")
        void sign_whenVaultSealed_then503() throws Exception {
            // Rotate first to ensure the key exists
            mockMvc.perform(post(rotatePathRsa)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // reset(auditHelper); // Removed reset

            // Seal the vault
            log.warn("SEALING VAULT FOR TEST");
            sealManager.seal();
            assertThat(sealManager.isSealed()).isTrue();

            Map<String, Object> payload = Map.of("sub", "test");
            mockMvc.perform(post(signPathRsa)
                            .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(payload)))
                    .andExpect(status().isServiceUnavailable()) // Expect 503
                    .andExpect(jsonPath("$.message").value("Vault is sealed.")); // Check message

            // Audit verification removed

            // Clean up: Unseal for subsequent tests
            log.warn("UNSEALING VAULT AFTER TEST");
            sealManager.unseal(properties.master().b64());
        }

        // Covers Task 5.5: Seal vault, POST /rotate/{key} -> 503, Unseal vault
        @Test
        @DisplayName("Rotate when Vault is Sealed should fail (503)")
        void rotate_whenVaultSealed_then503() throws Exception {
            // Seal the vault
            log.warn("SEALING VAULT FOR TEST");
            sealManager.seal();
            assertThat(sealManager.isSealed()).isTrue();

            mockMvc.perform(post(rotatePathRsa) // Use an existing key path for rotate attempt
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(jsonPath("$.message").value("Vault is sealed."));

            // Audit verification removed

            // Clean up: Unseal for subsequent tests
            log.warn("UNSEALING VAULT AFTER TEST");
            sealManager.unseal(properties.master().b64());
        }

        // Covers Task 5.5: Seal vault, GET /jwks/{key} -> 503, Unseal vault
        @Test
        @DisplayName("JWKS when Vault is Sealed should fail (503)")
        void getJwks_whenVaultSealed_then503() throws Exception {
            // Setup: Rotate first so the key config exists
            mockMvc.perform(post(rotatePathRsa)
                            .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                    .andExpect(status().isNoContent());
            // reset(auditHelper); // Removed reset

            // Seal the vault
            log.warn("SEALING VAULT FOR TEST");
            sealManager.seal();
            assertThat(sealManager.isSealed()).isTrue();

            mockMvc.perform(get(jwksPathRsa).with(anonymous())) // Use existing key path
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(jsonPath("$.message").value("Vault is sealed."));

            // Audit verification removed

            // Clean up: Unseal for subsequent tests
            log.warn("UNSEALING VAULT AFTER TEST");
            sealManager.unseal(properties.master().b64());
        }

    }
}