package tech.yump.vault.api.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.core.SealManager;

import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
class TransitControllerIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgresContainer = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("testdb")
            .withUsername("testuser")
            .withPassword("testpassword");

    @TempDir
    static Path tempStorageDir;

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgresContainer::getJdbcUrl);
        registry.add("spring.datasource.username", postgresContainer::getUsername);
        registry.add("spring.datasource.password", postgresContainer::getPassword);
        registry.add("mssm.secrets.db.postgres.connection-url", postgresContainer::getJdbcUrl);
        registry.add("mssm.secrets.db.postgres.username", postgresContainer::getUsername);
        registry.add("mssm.secrets.db.postgres.password", postgresContainer::getPassword);
        registry.add("mssm.storage.filesystem.path", () -> tempStorageDir.toAbsolutePath().toString());
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired SealManager sealManager;
    @Autowired MssmProperties mssmProperties;

    private static final String ROOT_TOKEN = "test-root-token";
    private static final String NO_ACCESS_TOKEN = "test-no-policy-token";
    private static final String INVALID_TOKEN = "invalid-dummy-token";
    private static final String KEY_NAME = "global";

    @BeforeEach
    void setUp() {
        if (sealManager.isSealed()) {
            sealManager.unseal(mssmProperties.master().b64());
        }
    }

    @Test
    @DisplayName("Encrypt and decrypt roundtrip returns original plaintext")
    void encryptDecrypt_roundtrip_returnsOriginalPlaintext() throws Exception {
        String originalText = "Hello, Transit Engine!";
        String plaintextB64 = Base64.getEncoder().encodeToString(originalText.getBytes());

        // Encrypt
        String encryptResponse = mockMvc.perform(post("/v1/transit/encrypt/{key}", KEY_NAME)
                        .header("X-Vault-Token", ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("plaintext", plaintextB64))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ciphertext", notNullValue()))
                .andReturn().getResponse().getContentAsString();

        String ciphertextB64 = objectMapper.readTree(encryptResponse).get("ciphertext").asText();

        // Decrypt
        mockMvc.perform(post("/v1/transit/decrypt/{key}", KEY_NAME)
                        .header("X-Vault-Token", ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("ciphertext", ciphertextB64))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value(plaintextB64));
    }

    @Test
    @DisplayName("Encrypt with missing plaintext field returns 400")
    void encrypt_missingPlaintext_returns400() throws Exception {
        mockMvc.perform(post("/v1/transit/encrypt/{key}", KEY_NAME)
                        .header("X-Vault-Token", ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("wrong_field", "value"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Encrypt with invalid Base64 plaintext returns 400")
    void encrypt_invalidBase64_returns400() throws Exception {
        mockMvc.perform(post("/v1/transit/encrypt/{key}", KEY_NAME)
                        .header("X-Vault-Token", ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("plaintext", "not-valid-base64!!!"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Decrypt with tampered ciphertext returns 400")
    void decrypt_tamperedCiphertext_returns400() throws Exception {
        // A valid-looking Base64 blob but wrong content — GCM tag will fail
        byte[] garbage = new byte[64];
        String garbageB64 = Base64.getEncoder().encodeToString(garbage);

        mockMvc.perform(post("/v1/transit/decrypt/{key}", KEY_NAME)
                        .header("X-Vault-Token", ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("ciphertext", garbageB64))))
                .andExpect(status().isInternalServerError()); // EncryptionException → 500 via GlobalExceptionHandler
    }

    @Test
    @DisplayName("Encrypt without a valid token returns 401")
    void encrypt_invalidToken_returns401() throws Exception {
        mockMvc.perform(post("/v1/transit/encrypt/{key}", KEY_NAME)
                        .header("X-Vault-Token", INVALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("plaintext", Base64.getEncoder().encodeToString("test".getBytes())))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Encrypt with token lacking transit policy returns 403")
    void encrypt_noTransitPolicy_returns403() throws Exception {
        mockMvc.perform(post("/v1/transit/encrypt/{key}", KEY_NAME)
                        .header("X-Vault-Token", NO_ACCESS_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("plaintext", Base64.getEncoder().encodeToString("test".getBytes())))))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Transit endpoints return 503 when vault is sealed")
    void encrypt_vaultSealed_returns503() throws Exception {
        sealManager.seal();
        try {
            mockMvc.perform(post("/v1/transit/encrypt/{key}", KEY_NAME)
                            .header("X-Vault-Token", ROOT_TOKEN)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(
                                    Map.of("plaintext", Base64.getEncoder().encodeToString("test".getBytes())))))
                    .andExpect(status().isServiceUnavailable());
        } finally {
            sealManager.unseal(mssmProperties.master().b64());
        }
    }
}
