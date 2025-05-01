package tech.yump.vault.secrets.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import tech.yump.vault.api.v1.JwtController;
import tech.yump.vault.core.SealManager;
import tech.yump.vault.auth.StaticTokenAuthFilter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import org.springframework.security.test.context.support.WithMockUser; // Or specific token setup

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class JwtControllerIntegrationTest {

    // Task 4.9: Inject required beans
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private SealManager sealManager;

    @Autowired
    private ObjectMapper objectMapper; // Useful for request bodies

    // --- Revised Task 4.5 using static @TempDir ---
    @TempDir
    static Path staticTempDir; // Use static TempDir

    @DynamicPropertySource
    static void configurePropertiesRevised(DynamicPropertyRegistry registry) {
        registry.add("mssm.storage.filesystem.path", () -> staticTempDir.toAbsolutePath().toString());
    }
    // --- End Revised Task 4.5 ---

    // --- Constants for tests ---
    private static final String RSA_KEY_NAME = "api-signing-key-rsa";
    private static final String EC_KEY_NAME = "api-signing-key-ec"; // Defined in application-test.yml
    private static final String ADMIN_TOKEN = "test-root-token"; // From application-test.yml
    private static final String SIGNING_TOKEN = "test-jwt-signer-token"; // From application-test.yml
    private static final String AUTH_HEADER = "X-Vault-Token";

    private static final String JWKS_PATH_FORMAT = "/v1/jwt/jwks/%s";
    private static final String SIGN_PATH_FORMAT = "/v1/jwt/sign/%s";
    private static final String ROTATE_PATH_FORMAT = "/v1/jwt/rotate/%s";
    // --- End Constants ---


    // Task 4.10: Unseal vault before each test
    @BeforeEach
    void setUp() {
        String dummyMasterKeyB64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        if (sealManager.isSealed()) {
            try {
                sealManager.unseal(dummyMasterKeyB64);
            } catch (Exception e) {
                throw new RuntimeException("Failed to unseal vault during test setup", e);
            }
        }
        if (sealManager.isSealed()) {
            throw new RuntimeException("Vault remained sealed after unseal attempt in test setup");
        }
    }

    // --- Phase 5: Integration Tests ---

    @Nested
    @DisplayName("RSA Key Lifecycle Tests")
    class RsaLifecycleTests {

// Inside JwtControllerIntegrationTest.java -> RsaLifecycleTests

        @Test
        @DisplayName("Task 5.1: Initial State, First Rotation, Signing")
        void testInitialStateFirstRotationAndSigning() throws Exception {
            // --- 1. Initial State Checks ---
            // Test GET /v1/jwt/jwks/{key} -> Expect 404 (No auth needed for JWKS usually, but add anonymous() if security blocks it)
            mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME))
                            // If your security blocks unauthenticated access to JWKS add: .with(anonymous())
                    )
                    .andExpect(status().isNotFound()) // Key doesn't exist yet
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: JWT key configuration not found for name: " + RSA_KEY_NAME));

            // Test POST /v1/jwt/sign/{key} -> Expect 404 (Should fail because key not found, not due to auth)
            // Use anonymous() here because *any* authenticated user (even the wrong one like root)
            // might get a 403 if the policy check happens before the key-not-found check.
            // If anonymous users are denied by default, leading to 401/403, this expectation needs adjustment
            // OR ensure the JwtKeyNotFoundException check happens before policy enforcement for this path.
            // **Alternative:** If anonymous leads to 401/403, try performing this check *without* any auth explicitly set,
            // relying on the default behavior (which *should* be unauthenticated if no header/principal is set).
            // Or, accept that this specific check might be hard to isolate perfectly from authz.
            // Let's try asserting based on the behavior WITH the intended SIGNING_TOKEN, accepting 404.
            mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            .with(authentication(StaticTokenAuthFilter.createAuthenticationToken(SIGNING_TOKEN, Collections.singletonList("test-jwt-signer-policy")))) // Explicitly set auth
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(Collections.emptyMap()))) // Empty claims
                    .andExpect(status().isNotFound()) // Expect 404 (Key not found)
                    .andExpect(jsonPath("$.message").value("JWT key configuration or version not found: JWT key configuration not found for name: " + RSA_KEY_NAME));


            // --- 2. First Rotation (Initial Generation) ---
            // Test POST /v1/jwt/rotate/{key} -> Expect 204 (Use ADMIN token)
            mockMvc.perform(post(String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME))
                            // .header(AUTH_HEADER, ADMIN_TOKEN) // Keep header for completeness if desired
                            .with(authentication(StaticTokenAuthFilter.createAuthenticationToken(ADMIN_TOKEN, Collections.singletonList("test-root-policy")))) // Explicitly set auth
                    )
                    .andExpect(status().isNoContent()); // 204

            // ... (rest of the test: file checks, JWKS fetch) ...
            Path configPath = staticTempDir.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("config.json");
            Path version1Path = staticTempDir.resolve("jwt/keys").resolve(RSA_KEY_NAME).resolve("versions/1.json");
            assertThat(Files.exists(configPath)).isTrue();
            assertThat(Files.exists(version1Path)).isTrue();

            MvcResult jwksResult = mockMvc.perform(get(String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME)))
                    // .with(anonymous()) // Add if needed
                    .andExpect(status().isOk())
                    // ... other jwks assertions
                    .andReturn();
            // ... (Extract public key) ...
            String jwksJson = jwksResult.getResponse().getContentAsString();
            JWKSet jwkSet = JWKSet.parse(jwksJson);
            JWK jwk = jwkSet.getKeyByKeyId(RSA_KEY_NAME + "-1");
            assertThat(jwk).isNotNull();
            assertThat(jwk).isInstanceOf(RSAKey.class);
            PublicKey publicKeyV1 = ((RSAKey) jwk).toPublicKey();
            assertThat(publicKeyV1).isNotNull();


            // --- 3. Signing (First Key) ---
            // Test POST /v1/jwt/sign/{key} -> Expect 200 (Use SIGNING token)
            Map<String, Object> claims = Map.of("sub", "integration-test-user", "scope", "test");
            MvcResult signResult = mockMvc.perform(post(String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME))
                            // .header(AUTH_HEADER, SIGNING_TOKEN) // Keep header if desired
                            .with(authentication(StaticTokenAuthFilter.createAuthenticationToken(SIGNING_TOKEN, Collections.singletonList("test-jwt-signer-policy")))) // Explicitly set auth
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(claims)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.jwt").isString())
                    .andReturn();

            // ... (rest of JWT verification) ...
            String jwtStringV1 = objectMapper.readValue(signResult.getResponse().getContentAsString(), JwtController.JwtResponse.class).jwt();
            assertThat(jwtStringV1).isNotBlank();
            JwtParser parser = Jwts.parser().verifyWith(publicKeyV1).build();
            Claims parsedClaims = parser.parseSignedClaims(jwtStringV1).getPayload();
            JwsHeader parsedHeader = parser.parseSignedClaims(jwtStringV1).getHeader();
            // ... other JWT claims/header assertions ...

            System.out.println("Task 5.1 Completed Successfully!");
        }

        // Task 5.2 tests will go here...
    }

    // Task 5.3 tests (EC Lifecycle) will go here...
    // Task 5.4 tests (Security) will go here...
    // Task 5.5 tests (Error Handling) will go here...
    // Task 5.6 tests (Audit) will go here...

}