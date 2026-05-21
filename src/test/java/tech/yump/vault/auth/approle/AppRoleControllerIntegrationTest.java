package tech.yump.vault.auth.approle;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.yump.vault.auth.StaticTokenAuthFilter;
import tech.yump.vault.auth.approle.dto.CreateRoleRequest;
import tech.yump.vault.auth.approle.dto.LoginRequest;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.core.SealManager;

import java.nio.file.Path;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@Slf4j
class AppRoleControllerIntegrationTest {

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
        // Use JDBC backend so approle_credentials table is created
        registry.add("mssm.storage.backend", () -> "jdbc");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SealManager sealManager;

    @Autowired
    private MssmProperties mssmProperties;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private static final String ROOT_TOKEN = "test-root-token";
    private static final String APPROLE_ADMIN_TOKEN = "test-approle-admin-token";
    private static final String INVALID_TOKEN = "invalid-dummy-token";

    @BeforeEach
    void setUp() throws Exception {
        if (sealManager.isSealed()) {
            sealManager.unseal(mssmProperties.master().b64());
        }
        // Clean approle state between tests
        jdbcTemplate.update("DELETE FROM approle_credentials");
        jdbcTemplate.update("DELETE FROM vault_storage WHERE key_path LIKE 'auth/approle/roles/%'");
    }

    @Test
    @DisplayName("Create role with root token returns 204")
    void createRole_withRootToken_returns204() throws Exception {
        CreateRoleRequest req = new CreateRoleRequest(
                List.of("test-kv-reader-policy"), Duration.ofHours(1), Duration.ofHours(24), 1);

        mockMvc.perform(post("/v1/auth/approle/role/my-test-role")
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("Get role after creation returns 200 with definition")
    void getRole_existingRole_returns200() throws Exception {
        createTestRole("my-test-role", List.of("test-kv-reader-policy"));

        mockMvc.perform(get("/v1/auth/approle/role/my-test-role")
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roleName", is("my-test-role")))
                .andExpect(jsonPath("$.policyNames[0]", is("test-kv-reader-policy")));
    }

    @Test
    @DisplayName("Generate secret_id for existing role returns 200 with UUID")
    void generateSecretId_existingRole_returns200WithUuid() throws Exception {
        createTestRole("my-test-role", List.of("test-kv-reader-policy"));

        mockMvc.perform(post("/v1/auth/approle/role/my-test-role/secret-id")
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret_id", notNullValue()));
    }

    @Test
    @DisplayName("Login with valid credentials returns 200 with JWT")
    void login_withValidCredentials_returns200WithJwt() throws Exception {
        createTestRole("my-svc", List.of("test-approle-admin-policy"));
        String secretId = generateSecretId("my-svc");

        LoginRequest loginReq = new LoginRequest("my-svc", secretId);
        mockMvc.perform(post("/v1/auth/approle/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token", notNullValue()))
                .andExpect(jsonPath("$.ttl").value(3600L));
    }

    @Test
    @DisplayName("JWT from login can access protected KV resource")
    void useJwtToken_toAccessKV_returns200() throws Exception {
        createTestRole("my-svc", List.of("test-approle-admin-policy"));
        String secretId = generateSecretId("my-svc");

        String responseJson = mockMvc.perform(post("/v1/auth/approle/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("my-svc", secretId))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String jwt = objectMapper.readTree(responseJson).get("token").asText();

        // Pre-seed a KV secret with root token
        mockMvc.perform(put("/v1/kv/data/myapp/config")
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("env", "prod"))))
                .andExpect(status().isNoContent());

        // Access KV with AppRole JWT (test-approle-admin-policy has READ on kv/data/*)
        mockMvc.perform(get("/v1/kv/data/myapp/config")
                        .header("Authorization", "Bearer " + jwt))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.env", is("prod")));
    }

    @Test
    @DisplayName("Login with unknown secret_id returns 401")
    void login_withUnknownSecretId_returns401() throws Exception {
        createTestRole("my-svc", List.of("test-kv-reader-policy"));

        LoginRequest loginReq = new LoginRequest("my-svc", "00000000-0000-0000-0000-000000000000");
        mockMvc.perform(post("/v1/auth/approle/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Login with expired secret_id returns 401")
    void login_withExpiredSecretId_returns401() throws Exception {
        createTestRole("my-svc", List.of("test-kv-reader-policy"));
        String secretId = generateSecretId("my-svc");

        // Backdating expires_at to the past
        jdbcTemplate.update("UPDATE approle_credentials SET expires_at = ? WHERE secret_id = ?",
                Timestamp.from(Instant.now().minusSeconds(3600)), secretId);

        LoginRequest loginReq = new LoginRequest("my-svc", secretId);
        mockMvc.perform(post("/v1/auth/approle/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Single-use secret_id: second login returns 401")
    void login_singleUse_secondLoginReturns401() throws Exception {
        createTestRole("my-svc", List.of("test-kv-reader-policy"));
        String secretId = generateSecretId("my-svc");

        LoginRequest loginReq = new LoginRequest("my-svc", secretId);

        mockMvc.perform(post("/v1/auth/approle/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk());

        mockMvc.perform(post("/v1/auth/approle/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Delete role returns 204; subsequent GET returns 404")
    void deleteRole_returns204_getReturns404() throws Exception {
        createTestRole("to-delete", List.of("test-kv-reader-policy"));

        mockMvc.perform(delete("/v1/auth/approle/role/to-delete")
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/v1/auth/approle/role/to-delete")
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Get non-existent role returns 404")
    void getRole_nonExistent_returns404() throws Exception {
        mockMvc.perform(get("/v1/auth/approle/role/does-not-exist")
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Login without credentials returns 400")
    void login_missingFields_returns400() throws Exception {
        mockMvc.perform(post("/v1/auth/approle/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"role_id\":\"\",\"secret_id\":\"\"}"))
                .andExpect(status().isBadRequest());
    }

    // --- Helpers ---

    private void createTestRole(String roleName, List<String> policyNames) throws Exception {
        CreateRoleRequest req = new CreateRoleRequest(
                policyNames, Duration.ofHours(1), Duration.ofHours(24), 1);
        mockMvc.perform(post("/v1/auth/approle/role/" + roleName)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isNoContent());
    }

    private String generateSecretId(String roleName) throws Exception {
        String json = mockMvc.perform(post("/v1/auth/approle/role/" + roleName + "/secret-id")
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(json).get("secret_id").asText();
    }
}
