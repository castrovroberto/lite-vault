# Task 30: Integration Tests for DB Credential API

Okay, let's tackle the final task for v0.3.0: Task 30 - Write Integration Tests for DB Credential API.This involves testing the GET /v1/db/creds/{role_name} endpoint end-to-end, including authentication, authorization, interaction with the PostgresSecretsEngine, and verifying effects on a real (but temporary) PostgreSQL database using Testcontainers.Here's a step-by-step guide:Phase 3: Task 30 - Write Integration Tests for DB Credential API1. Add Test Dependencies:•Ensure you have the necessary Testcontainers dependencies in your pom.xml.

<!-- pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
</dependency>
<!-- Testcontainers -->
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>junit-jupiter</artifactId>
    <scope>test</scope>
</dependency>
<dependency>
    <groupId>org.testcontainers</groupId>
    <artifactId>postgresql</artifactId>
    <scope>test</scope>
</dependency>
<!-- Ensure you have JDBC driver for tests too -->
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <scope>runtime</scope> <!-- Or test, if only needed for tests -->
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
    <!-- Scope might be default (compile) or test depending on usage -->
</dependency>

(Make sure versions are managed, possibly via spring-boot-dependencies or a testcontainers.version property).2. Create Test Configuration (application-test.yml):•Create a new configuration file: src/test/resources/application-test.yml.•This file will override properties for the test environment, especially database connection details, and define specific tokens/policies for testing.

# src/test/resources/application-test.yml
server:
  ssl:
    enabled: false # Disable SSL for simpler MockMvc tests

logging:
  level:
    tech.yump.vault: DEBUG
    org.springframework.jdbc.core: DEBUG
    com.zaxxer.hikari: INFO # Reduce noise unless debugging pool
    org.testcontainers: INFO

# --- Dummy Master Key for Testing ---
mssm:
  master:
    b64: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= # Dummy key for testing

  # --- Storage for Testing ---
  storage:
    filesystem:
      path: ./test-lite-vault-data # Use a dedicated test storage path

  # --- Auth/Policies for Testing ---
  auth:
    static-tokens:
      enabled: true
      mappings:
        - token: "test-root-token"
          policyNames: ["test-root-policy"]
        - token: "test-db-reader-token"
          policyNames: ["test-db-reader-policy"]
        - token: "test-db-admin-token" # For potential revocation endpoint later
          policyNames: ["test-db-admin-policy"]
        - token: "test-no-db-token"
          policyNames: ["test-kv-only-policy"] # A policy without DB access

  policies:
    - name: "test-root-policy"
      rules:
        - path: "kv/data/*"
          capabilities: [READ, WRITE, DELETE]
        - path: "db/creds/*" # Allow reading any DB creds
          capabilities: [READ]
        - path: "db/leases/*" # Allow deleting leases (for test revocation endpoint)
          capabilities: [DELETE]
    - name: "test-db-reader-policy"
      rules:
        - path: "db/creds/test-read-role" # Only this specific role
          capabilities: [READ]
        - path: "db/creds/test-admin-role" # And this one
          capabilities: [READ]
    - name: "test-db-admin-policy"
      rules:
        - path: "db/leases/*" # Allow deleting leases
          capabilities: [DELETE]
    - name: "test-kv-only-policy"
      rules:
        - path: "kv/data/app/*"
          capabilities: [READ]

  # --- Secrets Engine Config for Testing (Points to Testcontainers) ---
  secrets:
    db:
      postgres:
        # These will be overridden by @DynamicPropertySource using Testcontainers values
        connection-url: "jdbc:postgresql://localhost:5432/testdb"
        username: "testuser"
        password: "testpassword"

        # Define roles specifically for testing
        roles:
          "test-read-role":
            creation-statements:
              - "CREATE ROLE \"{{username}}\" WITH LOGIN PASSWORD '{{password}}';"
              - "GRANT CONNECT ON DATABASE testdb TO \"{{username}}\";"
              # Add a simple verifiable grant if needed, e.g., on a schema
              - "GRANT USAGE ON SCHEMA public TO \"{{username}}\";"
            revocation-statements:
              - "REVOKE USAGE ON SCHEMA public FROM \"{{username}}\";"
              - "REVOKE CONNECT ON DATABASE testdb FROM \"{{username}}\";"
              - "DROP ROLE IF EXISTS \"{{username}}\";"
            default-ttl: PT1M # Short TTL for tests

          "test-admin-role": # Another role for variety
            creation-statements:
              - "CREATE ROLE \"{{username}}\" WITH LOGIN PASSWORD '{{password}}' CREATEDB;" # Example different permission
              - "GRANT CONNECT ON DATABASE testdb TO \"{{username}}\";"
            revocation-statements:
              - "DROP ROLE IF EXISTS \"{{username}}\";"
            default-ttl: PT5M

# --- Spring Datasource Config for Testing (Points to Testcontainers) ---
spring:
  datasource:
    # These will be overridden by @DynamicPropertySource using Testcontainers values
    url: "jdbc:postgresql://localhost:5432/testdb"
    username: "testuser"
    password: "testpassword"
    driver-class-name: org.postgresql.Driver
    hikari:
      pool-name: TestPostgresPool
      maximum-pool-size: 5 # Smaller pool for tests

3. Create Integration Test Class:•Create src/test/java/tech/yump/vault/api/DbControllerIntegrationTest.java.•Set up Testcontainers for PostgreSQL.•Use @DynamicPropertySource to inject the dynamic container JDBC URL, username, and password into the Spring context before the DataSource and PostgresSecretsEngine beans are created.

// src/test/java/tech/yump/vault/api/DbControllerIntegrationTest.java
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
import tech.yump.vault.secrets.db.PostgresSecretsEngine; // For direct revocation if needed

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
    private static final String DB_ADMIN_TOKEN = "test-db-admin-token";
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
            sealManager.unseal(mssmProperties.master().b64());
        }
        // Ensure storage directory exists
        storagePath = Paths.get(mssmProperties.storage().filesystem().path());
        Files.createDirectories(storagePath);
        // Optional: Clean DB state if needed (e.g., drop roles left over from failed tests)
        // jdbcTemplate.execute("DROP ROLE IF EXISTS ...");
    }

    @AfterEach
    void tearDown() throws IOException {
        // Clean up storage
        if (Files.exists(storagePath)) {
            FileSystemUtils.deleteRecursively(storagePath);
        }
        // Optional: Clean DB state after each test
        // jdbcTemplate.execute("DROP ROLE IF EXISTS ...");
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
        mockMvc.perform(get("/v1/db/creds/some-other-configured-role") // Assume this role exists in config but policy denies
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
        // try (Connection conn = DriverManager.getConnection(
        //         postgresContainer.getJdbcUrl(), responseDto.username(), responseDto.password())) {
        //     assertThat(conn.isValid(1)).isTrue();
        //     System.out.println("Successfully connected using generated credentials!");
        // } catch (SQLException e) {
        //     fail("Failed to connect using generated credentials", e);
        // }

        // --- Cleanup (Revoke the lease for isolation) ---
        // Option 1: Call engine directly (less integration-y)
        // postgresSecretsEngine.revokeLease(responseDto.leaseId());
        // Option 2: Call a temporary test endpoint (see Step 4)
        revokeLeaseViaApi(responseDto.leaseId()); // Assumes helper method calls the test endpoint
        assertThat(doesRoleExist(responseDto.username())).isFalse(); // Verify cleanup
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
        assertThat(doesRoleExist(responseDto.username())).isFalse();
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
        mockMvc.perform(delete("/v1/db/leases/" + leaseId) // Assumes path from Step 4
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN)) // Use token with DELETE permission
                .andExpect(status().isNoContent());
    }

    // Test focusing specifically on the revocation endpoint (if added)
    @Test
    @DisplayName("DELETE /db/leases/{leaseId}: Should revoke lease and drop DB role")
    void revokeLease_whenValidLeaseId_thenNoContentAndDropRole() throws Exception {
        // 1. Generate credentials first
        MvcResult genResult = mockMvc.perform(get("/v1/db/creds/" + READ_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        DbCredentialsResponse genResponse = objectMapper.readValue(genResult.getResponse().getContentAsString(), DbCredentialsResponse.class);
        UUID leaseIdToRevoke = genResponse.leaseId();
        String usernameToRevoke = genResponse.username();

        assertThat(doesRoleExist(usernameToRevoke)).isTrue(); // Verify role exists initially

        // 2. Revoke using the API endpoint
        revokeLeaseViaApi(leaseIdToRevoke); // Uses the helper which calls DELETE

        // 3. Verify role is dropped
        assertThat(doesRoleExist(usernameToRevoke)).isFalse();

        // 4. Verify lease is gone internally (try revoking again -> 404 expected from engine)
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
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.title", is("Lease Not Found")));
    }

     @Test
    @DisplayName("DELETE /db/leases/{leaseId}: Should return 403 Forbidden when token lacks permission")
    void revokeLease_whenTokenLacksPermission_thenForbidden() throws Exception {
        // 1. Generate credentials first
        MvcResult genResult = mockMvc.perform(get("/v1/db/creds/" + READ_ROLE)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, ROOT_TOKEN))
                .andExpect(status().isOk())
                .andReturn();
        DbCredentialsResponse genResponse = objectMapper.readValue(genResult.getResponse().getContentAsString(), DbCredentialsResponse.class);
        UUID leaseIdToRevoke = genResponse.leaseId();

        // 2. Attempt revoke with token lacking DELETE on db/leases/*
        mockMvc.perform(delete("/v1/db/leases/" + leaseIdToRevoke)
                        .header(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, DB_READER_TOKEN)) // This token cannot DELETE leases
                .andExpect(status().isForbidden());

        // Cleanup needed as revocation failed
        revokeLeaseViaApi(leaseIdToRevoke);
    }

}

4. Add Temporary Revocation Endpoint (for Testing):•Since Task 26 implemented revokeLease in the engine but Task 27 didn't expose it via API, add a temporary endpoint in DbController solely for testing purposes. Add clear comments indicating its temporary nature.

// src/main/java/tech/yump/vault/api/DbController.java
package tech.yump.vault.api;

+import jakarta.servlet.http.HttpServletRequest; // Added
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
+import org.springframework.security.core.Authentication; // Added
+import org.springframework.security.core.GrantedAuthority; // Added
+import org.springframework.security.core.context.SecurityContextHolder; // Added
+import org.springframework.web.bind.annotation.DeleteMapping; // Added
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.dto.DbCredentialsResponse;
+import tech.yump.vault.audit.AuditBackend; // Added
+import tech.yump.vault.audit.AuditEvent; // Added
+import tech.yump.vault.auth.StaticTokenAuthFilter; // Added for REQUEST_ID_ATTR
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.Lease;
+import tech.yump.vault.secrets.LeaseNotFoundException; // Added
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.db.PostgresSecretsEngine; // Import the engine

+import java.time.Instant; // Added
import java.util.Map;
+import java.util.List; // Added
+import java.util.Optional; // Added
+import java.util.UUID; // Added

@RestController
@RequestMapping("/v1/db") // Base path for database secrets endpoints
@RequiredArgsConstructor
@Slf4j
public class DbController {

    private final PostgresSecretsEngine postgresSecretsEngine;
+   private final AuditBackend auditBackend; // Added
+   private final HttpServletRequest request; // Added

    /**
     * Generates dynamic credentials for a specified PostgreSQL role.
@@ -110,6 +113,41 @@
         }
     }

+   // --- START: Temporary Revocation Endpoint for Testing (Task 30) ---
+   // TODO: Remove or replace this endpoint with a proper lease management API later.
+   /**
+    * TEMPORARY endpoint for testing lease revocation.
+    * Requires authentication and authorization (e.g., DELETE capability on db/leases/{leaseId}).
+    *
+    * @param leaseId The UUID of the lease to revoke.
+    * @return ResponseEntity indicating success (204 No Content) or failure.
+    */
+   @DeleteMapping("/leases/{leaseId}")
+   public ResponseEntity<Void> revokeDbLease(@PathVariable UUID leaseId) {
+       log.info("Received request to revoke DB lease: {}", leaseId);
+       try {
+           postgresSecretsEngine.revokeLease(leaseId);
+           log.info("Successfully revoked DB lease: {}", leaseId);
+
+           // --- Audit Log for Success ---
+           logAuditEvent( // Use the same helper as generate
+                   "db_operation",
+                   "revoke_lease", // Different action
+                   "success",
+                   HttpStatus.NO_CONTENT.value(),
+                   null, // No error message
+                   null, // No role name directly associated with revoke request path
+                   leaseId // Include lease ID
+           );
+           return ResponseEntity.noContent().build();
+       } catch (LeaseNotFoundException e) {
+           log.warn("Lease revocation failed: Lease '{}' not found.", leaseId);
+           throw e; // Let handler deal with it
+       } catch (SecretsEngineException e) {
+           log.error("Lease revocation failed for lease '{}': {}", leaseId, e.getMessage(), e);
+           throw e; // Let handler deal with it
+       }
+   }
+   // --- END: Temporary Revocation Endpoint ---


    @ExceptionHandler(RoleNotFoundException.class)
@@ -130,6 +168,25 @@
         return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problemDetail);
     }

+   // Add handler for LeaseNotFoundException (for the revoke endpoint)
+   @ExceptionHandler(LeaseNotFoundException.class)
+   public ResponseEntity<ProblemDetail> handleLeaseNotFound(LeaseNotFoundException ex) {
+       UUID leaseId = extractLeaseIdFromPath(request.getRequestURI()); // Helper needed
+       ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
+       problemDetail.setTitle("Lease Not Found");
+       // --- Audit Log for Failure ---
+       logAuditEvent(
+               "db_operation",
+               "revoke_lease",
+               "failure",
+               HttpStatus.NOT_FOUND.value(),
+               ex.getMessage(),
+               null, // No role name
+               leaseId
+       );
+       return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problemDetail);
+   }
+
    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ProblemDetail> handleVaultSealed(VaultSealedException ex) {
        String roleName = extractRoleNameFromPath(request.getRequestURI());
@@ -140,7 +197,7 @@
        logAuditEvent(
                "db_operation",
                // Determine action based on path? Or keep generic?
-               "generate_credentials", // Or "db_operation_failed"
+               determineActionFromPath(request.getRequestURI()), // Helper needed
                "failure",
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                ex.getMessage(),
@@ -153,13 +210,14 @@
    @ExceptionHandler(SecretsEngineException.class)
    public ResponseEntity<ProblemDetail> handleSecretsEngineException(SecretsEngineException ex) {
        String roleName = extractRoleNameFromPath(request.getRequestURI());
+       UUID leaseId = extractLeaseIdFromPath(request.getRequestURI());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        problemDetail.setTitle("Secrets Engine Error");
        // --- Audit Log for Failure ---
        logAuditEvent(
                "db_operation",
-               "generate_credentials", // Or "db_operation_failed"
-               "failure",
+               determineActionFromPath(request.getRequestURI()),
+               "failure", // Or "error"?
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                ex.getMessage(),
                roleName,
@@ -172,6 +230,7 @@
     @ExceptionHandler(Exception.class)
     public ResponseEntity<ProblemDetail> handleGenericException(Exception ex) {
        String roleName = extractRoleNameFromPath(request.getRequestURI());
+       UUID leaseId = extractLeaseIdFromPath(request.getRequestURI());
        log.error("An unexpected error occurred processing DB credential request: {}", ex.getMessage(), ex);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected internal error occurred.");
        problemDetail.setTitle("Internal Server Error");
@@ -179,13 +238,13 @@
        // --- Audit Log for Failure ---
        logAuditEvent(
                "db_operation",
-               "generate_credentials", // Or "system_error"
+               determineActionFromPath(request.getRequestURI()),
                "failure",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "An unexpected internal error occurred.", // Generic message for audit
                roleName,
-               null
+               leaseId
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }
@@ -256,6 +315,26 @@
        return null; // Or return "unknown"
    }

+   // --- Helper to extract leaseId from path for exception handlers ---
+   private UUID extractLeaseIdFromPath(String uri) {
+       String prefix = request.getContextPath() + "/v1/db/leases/";
+       if (uri != null && uri.startsWith(prefix)) {
+           String uuidStr = uri.substring(prefix.length());
+           try {
+               return UUID.fromString(uuidStr);
+           } catch (IllegalArgumentException e) {
+               log.warn("Could not parse UUID from lease revocation path: {}", uri);
+               return null;
+           }
+       }
+       return null;
+   }
+
+   // --- Helper to determine action based on path for audit logging in exceptions ---
+   private String determineActionFromPath(String uri) {
+       if (uri != null && uri.contains("/leases/")) return "revoke_lease";
+       if (uri != null && uri.contains("/creds/")) return "generate_credentials";
+       return "unknown_db_operation";
+   }
 }

5. Run Tests:•Execute the DbControllerIntegrationTest class using your IDE or Maven (mvn test -Dtest=DbControllerIntegrationTest).•Testcontainers will automatically download the PostgreSQL image (if not present), start the container, run the tests, and stop the container.•Verify that all tests pass, including the database state checks.6. Update Task Status & Changelog:•Mark Task 30 as complete in mssm-atomic-tasks-v0-3-0.md.

# /Users/robertocastro/dev/lite-vault/project/mssm-atomic-tasks-v0-3-0.md
[...]
#### 29. [x] Write Unit Tests for PostgreSQL Engine
- **Description:**
  - Write unit tests for `PostgresSecretsEngine`.
  - Mock database interactions (JDBC calls) to test SQL template rendering and parameter substitution logic.
  - Test lease object creation, storage, retrieval, and removal.
  - Test credential generation and revocation logic, including error handling.
- **Rationale:**
  - Verifies the engine's internal logic without requiring a live database.

#### 30. [x] Write Integration Tests for DB Credential API
- **Description:**
  - Write Spring Boot integration tests (`@SpringBootTest`) for `DbController`.
  - Used Testcontainers (`@Testcontainers`, `PostgreSQLContainer`) to spin up a temporary PostgreSQL instance for each test run.
  - Configured `application-test.yml` with test-specific roles, policies, tokens, and pointed datasource/engine config to the Testcontainer using `@DynamicPropertySource`.
  - Sent authenticated requests to `GET /v1/db/creds/{role_name}` using `MockMvc`.
  - Verified successful credential generation (200 OK) and response structure (`DbCredentialsResponse`).
  - Verified that credentials actually create a user in the test DB using `JdbcTemplate` to query `pg_roles`.
  - Added a temporary `DELETE /v1/db/leases/{leaseId}` endpoint to `DbController` *for testing purposes only*.
  - Tested lease revocation via the temporary API endpoint, verifying the user is dropped from the test DB using `JdbcTemplate`.
  - Tested authentication failures (no token, invalid token -> 403).
  - Tested ACL enforcement (token without correct policy/capability -> 403).
  - Tested invalid input (unknown role -> 404).
  - Tested behavior when vault is sealed (-> 503).
- **Rationale:**
  - Validates the end-to-end flow from API request to credential generation and revocation against a real (test) database, including auth/authz and DB interaction.

---

## Result After Phase 3 Completion
[...]

•Add an entry to CHANGELOG.md under [Unreleased] -> Added.

# /Users/robertocastro/dev/lite-vault/CHANGELOG.md

## [Unreleased]

### Added
+ **Integration Tests for DB Credential API (Task 30):**
+   Added `DbControllerIntegrationTest.java` using `@SpringBootTest`, `@AutoConfigureMockMvc`, and Testcontainers (`PostgreSQLContainer`).
+   Created `application-test.yml` with specific configurations for testing (DB connection, roles, policies, tokens).
+   Used `@DynamicPropertySource` to inject Testcontainer DB details into the Spring context.
+   Tests cover:
+     - Authentication failures (no/invalid token -> 403).
+     - Authorization failures (insufficient permissions -> 403).
+     - Invalid input (unknown role -> 404).
+     - Successful credential generation (`GET /v1/db/creds/{role}` -> 200 OK), verifying response and DB user creation via `JdbcTemplate`.
+     - Vault sealed behavior (-> 503).
+   Added a temporary `DELETE /v1/db/leases/{leaseId}` endpoint to `DbController` *solely for testing revocation*.
+   Tested successful lease revocation via the temporary endpoint (-> 204 No Content), verifying DB user deletion via `JdbcTemplate`.
+   Tested revocation failures (unknown lease ID -> 404, insufficient permissions -> 403).
+   This completes the testing for the dynamic PostgreSQL secrets feature for v0.3.0.
+ **Audit Logging for DB Actions (Task 28):**
+   Injected `AuditBackend` into `DbController` and `PostgresSecretsEngine`.
+   Added audit logging within `DbController` for `GET /v1/db/creds/{roleName}` requests:
+     - Logs "success" events including authenticated principal, source IP, request ID, requested role, and generated lease ID.
+     - Logs "failure" events in exception handlers (404, 500, 503) including principal, source IP, request ID, requested role, and error message.
+   Added audit logging within `PostgresSecretsEngine`:
+     - Logs internal "success" event upon successful lease creation (`lease_creation` action) including lease ID and role name.
+     - Logs internal "success" or "failure" events for lease revocation attempts (`revoke_lease` action) including lease ID and error message on failure.
+   Ensured generated passwords are **not** included in any audit logs.
+   Added audit logging for the temporary `DELETE /v1/db/leases/{leaseId}` endpoint (success/failure).
+   Fulfills requirement F-CORE-130 for dynamic secrets.
[...]

Congratulations! Completing Task 30 marks the achievement of the v0.3.0 milestone. You now have a functional dynamic PostgreSQL secrets engine with API endpoints, configuration, basic lease management, auditing, unit tests, and integration tests.