package tech.yump.vault.secrets.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest // Load full application context
@AutoConfigureMockMvc // Configure MockMvc
@ActiveProfiles("test") // Use the test profile
@Slf4j
public class JwtControllerAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // Declare the mock bean HERE, at the top level of THIS specific test class
    @MockitoBean
    private JwtSecretsEngine jwtSecretsEngine;

    // --- Constants needed for these tests ---
    private static final String RSA_KEY_NAME = "api-signing-key-rsa";
    // Add other constants (tokens, paths etc.) needed specifically for auth tests
    private static final String ADMIN_TOKEN = "test-root-token";
    private static final String RSA_SIGNING_TOKEN = "test-jwt-signer-token";
    private static final String NO_POLICY_TOKEN = "test-no-policy-token";
    private static final String INVALID_TOKEN = "this-is-not-a-valid-token";

    private static final String JWKS_PATH_FORMAT = "/v1/jwt/jwks/%s";
    private static final String ROTATE_PATH_FORMAT = "/v1/jwt/rotate/%s";
    private static final String SIGN_PATH_FORMAT = "/v1/jwt/sign/%s";

    private final String rotatePathRsa = String.format(ROTATE_PATH_FORMAT, RSA_KEY_NAME);
    private final String signPathRsa = String.format(SIGN_PATH_FORMAT, RSA_KEY_NAME);
    private final String jwksPathRsa = String.format(JWKS_PATH_FORMAT, RSA_KEY_NAME);
    private final Map<String, Object> payload = Map.of("sub", "auth-test-user");

    // --- Helper Methods (Copied from original) ---
    private Authentication createAuthenticationToken(String tokenValue, List<String> policies) {
        List<SimpleGrantedAuthority> authorities = policies.stream()
                .map(p -> new SimpleGrantedAuthority("POLICY_" + p))
                .collect(Collectors.toList());
        return new TestingAuthenticationToken(tokenValue, null, authorities);
    }

    // --- Mock Setup (Copied from original AuthorizationTests) ---
    @BeforeEach
    void setupMocks() {
        log.info(">>> Running @BeforeEach setupMocks for JwtControllerAuthorizationTest <<<");
        // Reset and configure the mock bean specific to THIS test class context
        reset(jwtSecretsEngine);

        lenient().doNothing().when(jwtSecretsEngine).rotateKey(anyString());
        lenient().when(jwtSecretsEngine.signJwt(anyString(), anyMap())).thenReturn("mocked.signed.jwt");

        Map<String, Object> dummyJwk = Map.of("kty", "RSA", "kid", RSA_KEY_NAME + "-1", "use", "sig", "alg", "RS256", "n", "...", "e", "AQAB");
        Map<String, Object> dummyJwks = Map.of("keys", List.of(dummyJwk));
        lenient().when(jwtSecretsEngine.getJwks(eq(RSA_KEY_NAME))).thenReturn(dummyJwks);

        log.info("<<< Finished @BeforeEach setupMocks for JwtControllerAuthorizationTest >>>");
    }

    // --- @Test methods moved from the original AuthorizationTests nested class ---

    // Covers Task 5.4: /rotate with admin-token -> 204 (Success case)
    @Test
    @DisplayName("/rotate POST with Root Token should succeed (204)")
    void rotate_withRootToken_shouldSucceed() throws Exception {
        mockMvc.perform(post(rotatePathRsa)
                        .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy")))))
                .andExpect(status().isNoContent()); // Expect 204 from controller

        // Verify the CONTROLLER called the MOCKED ENGINE
        verify(jwtSecretsEngine).rotateKey(eq(RSA_KEY_NAME));
        // Audit verification removed
    }

    // Covers Task 5.4: /rotate with wrong token (no policy) -> 403
    @Test
    @DisplayName("/rotate POST with wrong Token (no policy) should fail (403)")
    void rotate_withNoPolicyToken_shouldFail403() throws Exception {
        mockMvc.perform(post(rotatePathRsa)
                        .with(authentication(createAuthenticationToken(NO_POLICY_TOKEN, List.of("non-existent-policy")))))
                .andExpect(status().isForbidden());

        // Verify the CONTROLLER DID NOT call the ENGINE
        verify(jwtSecretsEngine, never()).rotateKey(anyString());
        // Audit verification removed
    }

    // Covers Task 5.4: /rotate without token -> 401/403
    @Test
    @DisplayName("/rotate POST without Token should fail (403 - Forbidden by Security Filter)")
    void rotate_withoutToken_shouldFail403() throws Exception {
        mockMvc.perform(post(rotatePathRsa).with(anonymous())) // Anonymous user
                .andExpect(status().isForbidden());

        // Verify the CONTROLLER DID NOT call the ENGINE
        verify(jwtSecretsEngine, never()).rotateKey(anyString());
        // Audit verification removed
    }

    // Covers Task 5.4: /rotate with invalid token -> 401/403
    @Test
    @DisplayName("/rotate POST with invalid token returns 403 (Forbidden by Policy)")
    void rotateWithInvalidToken_shouldReturn403() throws Exception {
        mockMvc.perform(post(rotatePathRsa)
                        .with(authentication(createAuthenticationToken(INVALID_TOKEN, Collections.emptyList()))))
                .andExpect(status().isForbidden()); // Policy filter should deny
        verify(jwtSecretsEngine, never()).rotateKey(anyString());
    }

    // Covers Task 5.4: /rotate with signing-token -> 403
    @Test
    @DisplayName("/rotate POST with rsa-signing-token returns 403 (Forbidden by Policy)")
    void rotateWithSigningToken_shouldReturn403() throws Exception {
        mockMvc.perform(post(rotatePathRsa)
                        .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy")))))
                .andExpect(status().isForbidden()); // Policy check failure
        verify(jwtSecretsEngine, never()).rotateKey(anyString());
    }

    // Covers Task 5.4: /sign with specific signer token -> 200 (Success case)
    @Test
    @DisplayName("/sign POST with specific Signer Token should succeed (200)")
    void sign_withSignerToken_shouldSucceed() throws Exception {
        mockMvc.perform(post(signPathRsa)
                        .with(authentication(createAuthenticationToken(RSA_SIGNING_TOKEN, List.of("test-jwt-signer-policy"))))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.jwt").value("mocked.signed.jwt")); // Expect mock value

        // Verify CONTROLLER called ENGINE
        verify(jwtSecretsEngine).signJwt(eq(RSA_KEY_NAME), eq(payload));
        // Audit verification removed
    }

    // Covers Task 5.4: /sign with admin-token -> 200 (policy allows)
    @Test
    @DisplayName("/sign POST with Root Token should succeed (200)")
    void sign_withRootToken_shouldSucceed() throws Exception {
        mockMvc.perform(post(signPathRsa)
                        .with(authentication(createAuthenticationToken(ADMIN_TOKEN, List.of("test-root-policy"))))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.jwt").value("mocked.signed.jwt"));

        // Verify CONTROLLER called ENGINE
        verify(jwtSecretsEngine).signJwt(eq(RSA_KEY_NAME), eq(payload));
        // Audit verification removed
    }

    // Covers Task 5.4: /sign with wrong token (no policy) -> 403
    @Test
    @DisplayName("/sign POST with wrong Token (no policy) should fail (403)")
    void sign_withNoPolicyToken_shouldFail403() throws Exception {
        mockMvc.perform(post(signPathRsa)
                        .with(authentication(createAuthenticationToken(NO_POLICY_TOKEN, List.of("non-existent-policy"))))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isForbidden());

        // Verify the CONTROLLER DID NOT call the ENGINE
        verify(jwtSecretsEngine, never()).signJwt(anyString(), anyMap());
        // Audit verification removed
    }

    // Covers Task 5.4: /sign without token -> 401/403
    @Test
    @DisplayName("/sign POST without Token should fail (403 - Forbidden by Security Filter)")
    void sign_withoutToken_shouldReturn403() throws Exception {
        mockMvc.perform(post(signPathRsa)
                        .with(anonymous())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(payload)))
                .andExpect(status().isForbidden());

        // Verify the CONTROLLER DID NOT call the ENGINE
        verify(jwtSecretsEngine, never()).signJwt(anyString(), anyMap());
        // Audit verification removed
    }

    // Covers Task 5.4: /sign with invalid token -> 401/403
    @Test
    @DisplayName("/sign POST with invalid token returns 403 (Forbidden by Policy)")
    void signWithInvalidToken_shouldReturn403() throws Exception {
        mockMvc.perform(post(signPathRsa)
                        .with(authentication(createAuthenticationToken(INVALID_TOKEN, Collections.emptyList())))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden()); // Policy filter should deny
        verify(jwtSecretsEngine, never()).signJwt(anyString(), anyMap());
    }


    // Covers Task 5.4: /jwks without token -> 200
    @Test
    @DisplayName("/jwks GET without token returns 200 OK (Public Endpoint)")
    void jwks_isPublic_shouldSucceed() throws Exception {
        mockMvc.perform(get(jwksPathRsa).with(anonymous()))
                .andExpect(status().isOk()) // Should now be 200 OK
                .andExpect(jsonPath("$.keys").isArray()) // Check basic structure
                .andExpect(jsonPath("$.keys[0].kid").value(RSA_KEY_NAME + "-1")); // Check content from mock

        // Verify the CONTROLLER called the MOCKED ENGINE
        verify(jwtSecretsEngine).getJwks(eq(RSA_KEY_NAME));
        // Audit verification removed
    }
}