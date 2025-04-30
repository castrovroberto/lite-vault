package tech.yump.vault.api.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir; // Import TempDir
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry; // Import
import org.springframework.test.context.DynamicPropertySource; // Import
// import org.springframework.test.context.TestPropertySource; // REMOVE
import org.springframework.test.web.servlet.MockMvc;
// import org.springframework.util.FileSystemUtils; // REMOVE
import org.testcontainers.containers.PostgreSQLContainer; // Import
import org.testcontainers.junit.jupiter.Container; // Import
import org.testcontainers.junit.jupiter.Testcontainers; // Import
import tech.yump.vault.auth.StaticTokenAuthFilter;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.core.SealManager;

import java.io.IOException;
// import java.nio.file.Files; // REMOVE (or keep if needed for other file ops)
import java.nio.file.Path;
// import java.nio.file.Paths; // REMOVE

import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers // Enable Testcontainers support
@ActiveProfiles("test") // Use application-test.yml
// @TestPropertySource(...) // REMOVE - Handled by application-test.yml and @DynamicPropertySource
class KVControllerIntegrationTest {

    // --- Testcontainers Setup ---
    @Container // Manages the container lifecycle
    static PostgreSQLContainer<?> postgresContainer = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("testdb")
            .withUsername("testuser")
            .withPassword("testpassword");

    // Use static @TempDir for storage isolation, accessible in static @DynamicPropertySource
    @TempDir
    static Path tempStorageDir;

    // Inject dynamic properties from the container and TempDir into Spring context
    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        // DB properties (needed for full context startup)
        registry.add("spring.datasource.url", postgresContainer::getJdbcUrl);
        registry.add("spring.datasource.username", postgresContainer::getUsername);
        registry.add("spring.datasource.password", postgresContainer::getPassword);
        registry.add("mssm.secrets.db.postgres.connection-url", postgresContainer::getJdbcUrl);
        registry.add("mssm.secrets.db.postgres.username", postgresContainer::getUsername);
        registry.add("mssm.secrets.db.postgres.password", postgresContainer::getPassword);

        // Storage path
        registry.add("mssm.storage.filesystem.path", () -> tempStorageDir.toAbsolutePath().toString());
    }

    // --- Autowired Components ---
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SealManager sealManager;

    @Autowired
    private MssmProperties mssmProperties; // Can still be used to get the *effective* path if needed

    // private Path storagePath; // REMOVE - Handled by tempStorageDir

    // Tokens defined in application-test.yml
    private static final String ROOT_TOKEN = "test-root-token";
    private static final String READ_ONLY_TOKEN = "test-kv-readonly-token";
    private static final String WRITE_DELETE_TOKEN = "test-kv-myapp-write-token"; // Scoped to myapp/*
    private static final String NO_ACCESS_TOKEN = "test-no-policy-token"; // Linked to non-existent policy
    private static final String INVALID_TOKEN = "invalid-dummy-token";

    @BeforeEach
    void setUp() throws Exception {
        // Ensure vault is unsealed before each test
        if (sealManager.isSealed()) {
            // Use the dummy key provided via application-test.yml
            sealManager.unseal(mssmProperties.master().b64());
        }
        // Storage directory is created automatically by @TempDir
        // Files.createDirectories(storagePath); // REMOVE
        log.info("Using temporary storage directory: {}", tempStorageDir.toAbsolutePath());
    }

    @AfterEach
    void tearDown() throws IOException {
        // Clean up storage directory is handled automatically by @TempDir
        // if (Files.exists(storagePath)) { // REMOVE
        //     FileSystemUtils.deleteRecursively(storagePath); // REMOVE
        // } // REMOVE
        // Re-seal the vault if necessary (optional, depends on test isolation needs)
        // sealManager.seal();
    }

    // --- Test Data (remains the same) ---
    private final String testPath1 = "test/secret1";
    private final String testPathMyapp = "myapp/config";
    private final String testPathOther = "other/data";
    private final Map<String, String> secrets1 = Map.of("key1", "value1", "pass", "1234");
    private final Map<String, String> secretsUpdate = Map.of("key1", "valueUpdated", "newKey", "newValue");
    private final Map<String, String> secretsMyapp = Map.of("db_user", "app_user");
    private final Map<String, String> secretsOther = Map.of("api_key", "xyz789");

    // ========================================
    // Authentication Failure Tests (remain the same)
    // ========================================

    @Test
    @DisplayName("KV Write: Should return 403 Forbidden when no token provided")
    void writeSecret_whenNoToken_thenForbidden() throws Exception {
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isForbidden()); // Spring Security default denies anonymous
    }

    @Test
    @DisplayName("KV Read: Should return 403 Forbidden when invalid token provided")
    void readSecret_whenInvalidToken_thenForbidden() throws Exception {
        // Write data first with root token to ensure something exists
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isNoContent());

        // Attempt read with invalid token
        mockMvc.perform(get("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, INVALID_TOKEN))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("KV Delete: Should return 403 Forbidden when no token provided")
    void deleteSecret_whenNoToken_thenForbidden() throws Exception {
        // Write data first with root token
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isNoContent());

        // Attempt delete without token
        mockMvc.perform(delete("/v1/kv/data/" + testPath1))
                .andExpect(status().isForbidden());
    }

    // ========================================
    // Authorization Failure Tests (remain the same, use updated token names)
    // ========================================

    @Test
    @DisplayName("KV Write: Should return 403 Forbidden when token lacks WRITE capability")
    void writeSecret_whenReadOnlyToken_thenForbidden() throws Exception {
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, READ_ONLY_TOKEN) // Use test token
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("KV Delete: Should return 403 Forbidden when token lacks DELETE capability")
    void deleteSecret_whenReadOnlyToken_thenForbidden() throws Exception {
        // Write data first with root token
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isNoContent());

        // Attempt delete with read-only token
        mockMvc.perform(delete("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, READ_ONLY_TOKEN)) // Use test token
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("KV Read: Should return 403 Forbidden when token policy path doesn't match")
    void readSecret_whenWriteTokenWrongPath_thenForbidden() throws Exception {
        // Write data with root token to a path not covered by WRITE_DELETE_TOKEN's policy
        mockMvc.perform(put("/v1/kv/data/" + testPathOther)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secretsOther)))
                .andExpect(status().isNoContent());

        // Attempt read with WRITE_DELETE_TOKEN (scoped to myapp/*)
        mockMvc.perform(get("/v1/kv/data/" + testPathOther)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, WRITE_DELETE_TOKEN)) // Use test token
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("KV Write: Should return 403 Forbidden when token policy path doesn't match")
    void writeSecret_whenWriteTokenWrongPath_thenForbidden() throws Exception {
        // Attempt write with WRITE_DELETE_TOKEN (scoped to myapp/*) to a different path
        mockMvc.perform(put("/v1/kv/data/" + testPathOther)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, WRITE_DELETE_TOKEN) // Use test token
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secretsOther)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("KV Read: Should return 403 Forbidden when token linked to non-existent policy")
    void readSecret_whenNoAccessPolicyToken_thenForbidden() throws Exception {
        // Write data first with root token
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isNoContent());

        // Attempt read with token linked to a policy name not defined in mssm.policies
        mockMvc.perform(get("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, NO_ACCESS_TOKEN)) // Use test token
                .andExpect(status().isForbidden())
                // The message comes from PolicyEnforcementFilter when policies aren't found
                .andExpect(jsonPath("$.message", is("Access denied. Policy configuration error.")));
    }


    // ========================================
    // Successful CRUD Tests (Root Token - remains the same, uses updated token name)
    // ========================================

    @Test
    @DisplayName("KV CRUD: Full lifecycle with Root Token")
    void kvCrud_whenRootToken_thenSuccess() throws Exception {
        // 1. Write Initial Secret
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN) // Use test token
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isNoContent());

        // 2. Read Initial Secret
        mockMvc.perform(get("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)) // Use test token
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.key1", is("value1")))
                .andExpect(jsonPath("$.pass", is("1234")));

        // 3. Update Secret (Overwrite)
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN) // Use test token
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(secretsUpdate)))
                .andExpect(status().isNoContent());

        // 4. Read Updated Secret
        mockMvc.perform(get("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)) // Use test token
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.key1", is("valueUpdated")))
                .andExpect(jsonPath("$.newKey", is("newValue")))
                .andExpect(jsonPath("$.pass").doesNotExist()); // Old key should be gone

        // 5. Delete Secret
        mockMvc.perform(delete("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)) // Use test token
                .andExpect(status().isNoContent());

        // 6. Read Deleted Secret (Expect 404)
        mockMvc.perform(get("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)) // Use test token
                .andExpect(status().isNotFound());
    }

    // ========================================
    // Successful CRUD Tests (Scoped Tokens - remains the same, uses updated token names)
    // ========================================

    @Test
    @DisplayName("KV Read: Should succeed when ReadOnly Token has permission")
    void readSecret_whenReadOnlyToken_thenSuccess() throws Exception {
        // Write data first with root token
        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isNoContent());

        // Read with read-only token
        mockMvc.perform(get("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, READ_ONLY_TOKEN)) // Use test token
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.key1", is("value1")));
    }

    @Test
    @DisplayName("KV Write/Delete: Should succeed when WriteDelete Token has permission for specific path")
    void writeDeleteSecret_whenWriteTokenCorrectPath_thenSuccess() throws Exception {
        // 1. Write with WRITE_DELETE_TOKEN to allowed path (myapp/*)
        mockMvc.perform(put("/v1/kv/data/" + testPathMyapp)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, WRITE_DELETE_TOKEN) // Use test token
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secretsMyapp)))
                .andExpect(status().isNoContent());

        // 2. Read back (e.g., with root or read-only token) to verify write
        //    Using ROOT_TOKEN here for simplicity, as WRITE_DELETE_TOKEN also has read per application-test.yml
        mockMvc.perform(get("/v1/kv/data/" + testPathMyapp)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.db_user", is("app_user")));

        // 3. Delete with WRITE_DELETE_TOKEN from allowed path
        mockMvc.perform(delete("/v1/kv/data/" + testPathMyapp)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, WRITE_DELETE_TOKEN)) // Use test token
                .andExpect(status().isNoContent());

        // 4. Read back (expect 404)
        mockMvc.perform(get("/v1/kv/data/" + testPathMyapp)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isNotFound());
    }

    // ========================================
    // Vault Sealed Test (remains the same, uses updated token name)
    // ========================================
    @Test
    @DisplayName("KV Write: Should return 503 Service Unavailable when Vault is sealed")
    void writeSecret_whenVaultSealed_thenServiceUnavailable() throws Exception {
        // Ensure vault is sealed for this test
        sealManager.seal();

        mockMvc.perform(put("/v1/kv/data/" + testPath1)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN) // Use test token
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secrets1)))
                .andExpect(status().isServiceUnavailable()) // 503
                // The message comes from KVController's exception handler
                .andExpect(jsonPath("$.message", is("Vault is sealed.")));

        // Optional: Unseal again if other tests in the same run need it unsealed
        // sealManager.unseal(mssmProperties.master().b64());
    }

    // Add logging import if not present
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KVControllerIntegrationTest.class);

}