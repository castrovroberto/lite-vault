package tech.yump.vault.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.FileSystemUtils;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import tech.yump.vault.api.dto.DbCredentialsResponse;
import tech.yump.vault.auth.StaticTokenAuthFilter;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.core.SealManager;
// Import LeaseNotFoundException if needed for specific assertions, though handled by controller
// import tech.yump.vault.secrets.LeaseNotFoundException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers // Enable Testcontainers support
@ActiveProfiles("test") // Load application-test.yml
class DbControllerIntegrationTest {

    // --- Testcontainers Setup ---
    @Container // Manages the container lifecycle
    static PostgreSQLContainer<?> postgresContainer = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("testdb")
            .withUsername("testuser")
            .withPassword("testpassword");

    // Inject dynamic properties from the container into Spring context
    @DynamicPropertySource
    static void postgresProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgresContainer::getJdbcUrl);
        registry.add("spring.datasource.username", postgresContainer::getUsername);
        registry.add("spring.datasource.password", postgresContainer::getPassword);
        // Also override the MSSM specific properties
        registry.add("mssm.secrets.db.postgres.connection-url", postgresContainer::getJdbcUrl);
        registry.add("mssm.secrets.db.postgres.username", postgresContainer::getUsername);
        registry.add("mssm.secrets.db.postgres.password", postgresContainer::getPassword);
    }

    // --- Autowired Components ---
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SealManager sealManager;

    @Autowired
    private MssmProperties mssmProperties;

    @Autowired
    private JdbcTemplate jdbcTemplate; // To verify DB state

    // @Autowired // Optional: Inject engine if calling revokeLease directly
    // private PostgresSecretsEngine postgresSecretsEngine;

    private Path storagePath;

    // --- Tokens from application-test.yml ---
    private static final String ROOT_TOKEN = "test-root-token";
    private static final String DB_READER_TOKEN = "test-db-reader-token";
    private static final String DB_ADMIN_TOKEN = "test-db-admin-token"; // Used in application-test.yml, can be used if needed
    private static final String NO_DB_TOKEN = "test-no-db-token";
    private static final String INVALID_TOKEN = "invalid-dummy-token";

    // --- Test Roles from application-test.yml ---
    private static final String READ_ROLE = "test-read-role";
    private static final String ADMIN_ROLE = "test-admin-role";
    private static final String UNKNOWN_ROLE = "non-existent-role";


    @BeforeAll
    static void startContainer() {
        // Container starts automatically via @Container
        System.out.println("PostgreSQL Testcontainer started at: " + postgresContainer.getJdbcUrl());
    }

    @BeforeEach
    void setUp() throws Exception {
        // Ensure vault is unsealed
        if (sealManager.isSealed()) {
            // Use the dummy key from application-test.yml
            sealManager.unseal(mssmProperties.master().b64());
        }
        // Ensure storage directory exists
        storagePath = Paths.get(mssmProperties.storage().filesystem().path());
        Files.createDirectories(storagePath);
        // Optional: Clean DB state if needed (e.g., drop roles left over from failed tests)
        // jdbcTemplate.execute("DROP ROLE IF EXISTS ..."); // Example, adjust as needed
    }

    @AfterEach
    void tearDown() throws IOException {
        // Clean up storage
        if (Files.exists(storagePath)) {
            FileSystemUtils.deleteRecursively(storagePath);
        }
        // Optional: Clean DB state after each test
        // Example: Drop any roles starting with lv- to clean up potentially leaked roles
        // jdbcTemplate.execute("DO $$ DECLARE r RECORD; BEGIN FOR r IN (SELECT rolname FROM pg_roles WHERE rolname LIKE 'lv-%') LOOP EXECUTE 'DROP ROLE IF EXISTS ' || quote_ident(r.rolname); END LOOP; END $$;");
    }

    @AfterAll
    static void stopContainer() {
        // Container stops automatically
        System.out.println("PostgreSQL Testcontainer stopped.");
    }

    // --- Helper Method to Verify Role Existence ---
    private boolean doesRoleExist(String username) {
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM pg_catalog.pg_roles WHERE rolname = ?",
                Integer.class,
                username
        );
        return count != null && count > 0;
    }

    // ========================================
    // Authentication & Authorization Tests
    // ========================================

    @Test
    @DisplayName("GET /db/creds/{role}: Should return 403 Forbidden when no token provided")
    void generateCreds_whenNoToken_thenForbidden() throws Exception {
        mockMvc.perform(get("/v1/db/creds/" + READ_ROLE))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /db/creds/{role}: Should return 403 Forbidden when invalid token provided")
    void generateCreds_whenInvalidToken_thenForbidden() throws Exception {
        mockMvc.perform(get("/v1/db/creds/" + READ_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, INVALID_TOKEN))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /db/creds/{role}: Should return 403 Forbidden when token lacks READ capability for the path")
    void generateCreds_whenTokenLacksPermission_thenForbidden() throws Exception {
        mockMvc.perform(get("/v1/db/creds/" + READ_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, NO_DB_TOKEN)) // Token has no DB policy
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /db/creds/{role}: Should return 403 Forbidden when token policy doesn't match specific role path")
    void generateCreds_whenTokenPolicyWrongRole_thenForbidden() throws Exception {
        // DB_READER_TOKEN only has access to test-read-role and test-admin-role
        // Define a role that exists in config but isn't allowed by the policy
        String disallowedRole = "some-other-configured-role"; // Assume this role *could* be configured, but policy denies
        // We don't actually need to add it to application-test.yml for this test,
        // as the policy check happens before the role lookup in the engine.
        mockMvc.perform(get("/v1/db/creds/" + disallowedRole)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, DB_READER_TOKEN))
                .andExpect(status().isForbidden());
    }

    // ========================================
    // Input Validation / Not Found Tests
    // ========================================

    @Test
    @DisplayName("GET /db/creds/{role}: Should return 404 Not Found when role name is not configured")
    void generateCreds_whenRoleNotFound_thenNotFound() throws Exception {
        mockMvc.perform(get("/v1/db/creds/" + UNKNOWN_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)) // Use root token to bypass ACLs
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title", is("Role Not Found")))
                .andExpect(jsonPath("$.detail", containsString(UNKNOWN_ROLE)));
    }

    // ========================================
    // Success Case Tests
    // ========================================

    @Test
    @DisplayName("GET /db/creds/{role}: Should return 200 OK with credentials and create DB role on success")
    void generateCreds_whenValidRequest_thenOkAndCreateRole() throws Exception {
        // Act
        MvcResult result = mockMvc.perform(get("/v1/db/creds/" + READ_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, DB_READER_TOKEN)) // Use token with specific permission
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.leaseId", is(notNullValue(String.class))))
                .andExpect(jsonPath("$.username", startsWith("lv-test-read-role-")))
                .andExpect(jsonPath("$.password", is(notNullValue(String.class))))
                .andExpect(jsonPath("$.leaseDurationSeconds", is(60))) // Matches PT1M TTL
                .andReturn();

        // Assert Response Content
        String jsonResponse = result.getResponse().getContentAsString();
        DbCredentialsResponse responseDto = objectMapper.readValue(jsonResponse, DbCredentialsResponse.class);
        assertThat(responseDto.username()).isNotBlank();
        assertThat(responseDto.password()).isNotBlank();
        assertThat(responseDto.leaseId()).isNotNull();

        // Assert Database State
        assertThat(doesRoleExist(responseDto.username())).isTrue();

        // --- Optional: Test connecting with the generated credentials ---
        // try (java.sql.Connection conn = java.sql.DriverManager.getConnection(
        //         postgresContainer.getJdbcUrl(), responseDto.username(), responseDto.password())) {
        //     assertThat(conn.isValid(1)).isTrue();
        //     System.out.println("Successfully connected using generated credentials!");
        // } catch (java.sql.SQLException e) {
        //     org.junit.jupiter.api.Assertions.fail("Failed to connect using generated credentials", e);
        // }

        // --- Cleanup (Revoke the lease for isolation) ---
        // Option 1: Call engine directly (less integration-y)
        // postgresSecretsEngine.revokeLease(responseDto.leaseId());
        // Option 2: Call a temporary test endpoint (see Step 4)
        revokeLeaseViaApi(responseDto.leaseId()); // Assumes helper method calls the test endpoint
        assertThat(doesRoleExist(responseDto.username())).as("Role should be deleted after revocation").isFalse(); // Verify cleanup
    }

    @Test
    @DisplayName("GET /db/creds/{role}: Should succeed with root token (wildcard policy)")
    void generateCreds_whenRootToken_thenOkAndCreateRole() throws Exception {
        MvcResult result = mockMvc.perform(get("/v1/db/creds/" + ADMIN_ROLE) // Use a different role
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)) // Use root token
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", startsWith("lv-test-admin-role-")))
                .andExpect(jsonPath("$.leaseDurationSeconds", is(300))) // Matches PT5M TTL
                .andReturn();

        String jsonResponse = result.getResponse().getContentAsString();
        DbCredentialsResponse responseDto = objectMapper.readValue(jsonResponse, DbCredentialsResponse.class);
        assertThat(doesRoleExist(responseDto.username())).isTrue();

        // Cleanup
        revokeLeaseViaApi(responseDto.leaseId());
        assertThat(doesRoleExist(responseDto.username())).as("Role should be deleted after revocation").isFalse();
    }

    // ========================================
    // Vault Sealed Test
    // ========================================
    @Test
    @DisplayName("GET /db/creds/{role}: Should return 503 Service Unavailable when Vault is sealed")
    void generateCreds_whenVaultSealed_thenServiceUnavailable() throws Exception {
        // Arrange: Seal the vault
        sealManager.seal();
        assertThat(sealManager.isSealed()).isTrue();

        // Act & Assert
        mockMvc.perform(get("/v1/db/creds/" + READ_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, DB_READER_TOKEN))
                .andExpect(status().isServiceUnavailable()) // 503
                .andExpect(jsonPath("$.title", is("Vault Sealed")));

        // Optional: Unseal again if needed for subsequent tests in the same class run
        // sealManager.unseal(mssmProperties.master().b64());
    }

    // ========================================
    // Revocation Test (Requires Step 4)
    // ========================================

    // Helper method to call the temporary revocation endpoint
    private void revokeLeaseViaApi(UUID leaseId) throws Exception {
        // Use ROOT_TOKEN which has DELETE capability on db/leases/*
        mockMvc.perform(delete("/v1/db/leases/" + leaseId)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isNoContent());
    }

    // Test focusing specifically on the revocation endpoint (if added)
    @Test
    @DisplayName("DELETE /db/leases/{leaseId}: Should revoke lease and drop DB role")
    void revokeLease_whenValidLeaseId_thenNoContentAndDropRole() throws Exception {
        // 1. Generate credentials first (use root token for simplicity here)
        MvcResult genResult = mockMvc.perform(get("/v1/db/creds/" + READ_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        DbCredentialsResponse genResponse = objectMapper.readValue(genResult.getResponse().getContentAsString(), DbCredentialsResponse.class);
        UUID leaseIdToRevoke = genResponse.leaseId();
        String usernameToRevoke = genResponse.username();

        assertThat(doesRoleExist(usernameToRevoke)).as("Role should exist after generation").isTrue(); // Verify role exists initially

        // 2. Revoke using the API endpoint (helper uses ROOT_TOKEN)
        revokeLeaseViaApi(leaseIdToRevoke);

        // 3. Verify role is dropped
        assertThat(doesRoleExist(usernameToRevoke)).as("Role should NOT exist after revocation").isFalse();

        // 4. Verify lease is gone internally (try revoking again -> 404 expected from engine via handler)
        mockMvc.perform(delete("/v1/db/leases/" + leaseIdToRevoke)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isNotFound()) // Expect 404 from LeaseNotFoundException handler
                .andExpect(jsonPath("$.title", is("Lease Not Found")));
    }

    @Test
    @DisplayName("DELETE /db/leases/{leaseId}: Should return 404 for non-existent lease ID")
    void revokeLease_whenInvalidLeaseId_thenNotFound() throws Exception {
        UUID nonExistentLeaseId = UUID.randomUUID();
        mockMvc.perform(delete("/v1/db/leases/" + nonExistentLeaseId)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)) // Use token with permission
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title", is("Lease Not Found")));
    }

    @Test
    @DisplayName("DELETE /db/leases/{leaseId}: Should return 403 Forbidden when token lacks permission")
    void revokeLease_whenTokenLacksPermission_thenForbidden() throws Exception {
        // 1. Generate credentials first (use root token)
        MvcResult genResult = mockMvc.perform(get("/v1/db/creds/" + READ_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        DbCredentialsResponse genResponse = objectMapper.readValue(genResult.getResponse().getContentAsString(), DbCredentialsResponse.class);
        UUID leaseIdToRevoke = genResponse.leaseId();
        String usernameToRevoke = genResponse.username(); // Keep track for cleanup

        // 2. Attempt revoke with token lacking DELETE on db/leases/*
        mockMvc.perform(delete("/v1/db/leases/" + leaseIdToRevoke)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, DB_READER_TOKEN)) // This token cannot DELETE leases
                .andExpect(status().isForbidden());

        // 3. Verify role still exists (since revocation failed)
        assertThat(doesRoleExist(usernameToRevoke)).as("Role should still exist after failed revocation attempt").isTrue();

        // Cleanup needed as revocation failed
        revokeLeaseViaApi(leaseIdToRevoke); // Use root token to clean up
        assertThat(doesRoleExist(usernameToRevoke)).as("Role should be deleted after cleanup revocation").isFalse();
    }
}