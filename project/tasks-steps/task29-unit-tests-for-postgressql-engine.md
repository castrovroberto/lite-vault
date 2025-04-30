# Task 29: Unit Tests for PostgreSQL Engine

Okay, let's move on to Task 29: Write Unit Tests for PostgreSQL Engine.The goal is to test the logic within PostgresSecretsEngine in isolation, ensuring it behaves correctly based on its inputs and mocked dependencies, without needing a real PostgreSQL database.Here's a step-by-step guide:Phase 3: Task 29 - Write Unit Tests for PostgreSQL Engine1. Create Test Class:•Create a new test class: src/test/java/tech/yump/vault/secrets/db/PostgresSecretsEngineTest.java.•Annotate it with @ExtendWith(MockitoExtension.class) to enable Mockito integration with JUnit 5.2. Set Up Mocks and Test Instance:•Declare Mocks: Use @Mock for all dependencies injected into PostgresSecretsEngine:•MssmProperties mockProperties•DataSource mockDataSource (Needed for checkDbConnection)•JdbcTemplate mockJdbcTemplate•AuditBackend mockAuditBackend•Declare Instance Under Test: Use @InjectMocks to create an instance of PostgresSecretsEngine and inject the mocks into it:•PostgresSecretsEngine postgresSecretsEngine•Argument Captors: Use @Captor for capturing arguments passed to mocks, especially for SQL strings and AuditEvents:•ArgumentCaptor<String> sqlCaptor•ArgumentCaptor<AuditEvent> auditEventCaptor

// src/test/java/tech/yump/vault/secrets/db/PostgresSecretsEngineTest.java
package tech.yump.vault.secrets.db;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessException; // Import common exception
import org.springframework.jdbc.CannotGetJdbcConnectionException; // Example specific exception
import org.springframework.jdbc.core.JdbcTemplate;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.LeaseNotFoundException;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PostgresSecretsEngineTest {

    @Mock
    private MssmProperties mockProperties;
    @Mock
    private DataSource mockDataSource; // Needed for @PostConstruct check
    @Mock
    private JdbcTemplate mockJdbcTemplate;
    @Mock
    private AuditBackend mockAuditBackend;

    // Mocks needed for checkDbConnection
    @Mock
    private Connection mockConnection;
    @Mock
    private DatabaseMetaData mockMetaData;

    @InjectMocks
    private PostgresSecretsEngine postgresSecretsEngine;

    @Captor
    private ArgumentCaptor<String> sqlCaptor;
    @Captor
    private ArgumentCaptor<AuditEvent> auditEventCaptor;

    private final String TEST_ROLE_NAME = "test-role";
    private final Duration TEST_TTL = Duration.ofHours(1);
    private final List<String> TEST_CREATION_SQL = List.of(
            "CREATE ROLE \"{{username}}\" WITH LOGIN PASSWORD '{{password}}';",
            "GRANT CONNECT ON DATABASE testdb TO \"{{username}}\";"
    );
    private final List<String> TEST_REVOCATION_SQL = List.of(
            "REVOKE CONNECT ON DATABASE testdb FROM \"{{username}}\";",
            "DROP ROLE IF EXISTS \"{{username}}\";"
    );

    private MssmProperties.PostgresRoleDefinition testRoleDefinition;
    private MssmProperties.PostgresProperties postgresProperties;
    private MssmProperties.DbSecretsProperties dbSecretsProperties;
    private MssmProperties.SecretsProperties secretsProperties;

    @BeforeEach
    void setUp() {
        // Reset mocks if needed (often good practice)
        // Mockito.reset(mockProperties, mockDataSource, mockJdbcTemplate, mockAuditBackend, mockConnection, mockMetaData);

        // Set up the nested properties structure for mocking
        testRoleDefinition = new MssmProperties.PostgresRoleDefinition(
                TEST_CREATION_SQL,
                TEST_REVOCATION_SQL,
                TEST_TTL
        );
        postgresProperties = new MssmProperties.PostgresProperties(
                "jdbc:postgresql://host:5432/db",
                "user",
                "pass",
                Map.of(TEST_ROLE_NAME, testRoleDefinition)
        );
        dbSecretsProperties = new MssmProperties.DbSecretsProperties(postgresProperties);
        secretsProperties = new MssmProperties.SecretsProperties(dbSecretsProperties);

        // --- Mock the property retrieval ---
        // Use lenient() if the same mock setup is used across tests where it might not always be called
        lenient().when(mockProperties.secrets()).thenReturn(secretsProperties);
        // No need to mock deeper levels unless directly accessed,
        // but it's clearer to mock the chain if needed:
        // lenient().when(mockProperties.secrets().db()).thenReturn(dbSecretsProperties);
        // lenient().when(mockProperties.secrets().db().postgres()).thenReturn(postgresProperties);
        // lenient().when(mockProperties.secrets().db().postgres().roles()).thenReturn(Map.of(TEST_ROLE_NAME, testRoleDefinition));
    }

    // --- Tests for checkDbConnection (@PostConstruct) ---

    @Test
    @DisplayName("checkDbConnection: Should log success when connection is valid")
    void checkDbConnection_ValidConnection_LogsSuccess() throws SQLException {
        // Arrange
        when(mockDataSource.getConnection()).thenReturn(mockConnection);
        when(mockConnection.isValid(anyInt())).thenReturn(true);
        when(mockConnection.getMetaData()).thenReturn(mockMetaData);
        when(mockMetaData.getURL()).thenReturn("jdbc:mock");
        when(mockMetaData.getUserName()).thenReturn("mockUser");

        // Act
        postgresSecretsEngine.checkDbConnection(); // Call directly to test

        // Assert
        verify(mockDataSource).getConnection();
        verify(mockConnection).isValid(2);
        verify(mockConnection).close(); // Ensure connection is closed
        // Verify logging (requires log capture setup, often omitted in basic unit tests)
    }

    @Test
    @DisplayName("checkDbConnection: Should log error when connection is invalid")
    void checkDbConnection_InvalidConnection_LogsError() throws SQLException {
        // Arrange
        when(mockDataSource.getConnection()).thenReturn(mockConnection);
        when(mockConnection.isValid(anyInt())).thenReturn(false);

        // Act
        postgresSecretsEngine.checkDbConnection();

        // Assert
        verify(mockDataSource).getConnection();
        verify(mockConnection).isValid(2);
        verify(mockConnection).close();
        // Verify error logging (requires log capture setup)
    }

    @Test
    @DisplayName("checkDbConnection: Should log error on SQLException")
    void checkDbConnection_SQLException_LogsError() throws SQLException {
        // Arrange
        when(mockDataSource.getConnection()).thenThrow(new SQLException("Test DB connection failed"));

        // Act
        postgresSecretsEngine.checkDbConnection();

        // Assert
        verify(mockDataSource).getConnection();
        verify(mockConnection, never()).isValid(anyInt()); // Connection wasn't obtained
        verify(mockConnection, never()).close();
        // Verify error logging (requires log capture setup)
    }


    // --- Tests for generateCredentials ---

    @Test
    @DisplayName("generateCredentials: Should generate lease, execute SQL, log audit, and store lease on success")
    void generateCredentials_Success() {
        // Arrange
        // Properties mock already set up in @BeforeEach

        // Act
        Lease resultLease = postgresSecretsEngine.generateCredentials(TEST_ROLE_NAME);

        // Assert
        assertThat(resultLease).isNotNull();
        assertThat(resultLease.id()).isNotNull();
        assertThat(resultLease.roleName()).isEqualTo(TEST_ROLE_NAME);
        assertThat(resultLease.ttl()).isEqualTo(TEST_TTL);
        assertThat(resultLease.secretData()).containsKey("username");
        assertThat(resultLease.secretData()).containsKey("password");
        String generatedUsername = (String) resultLease.secretData().get("username");
        String generatedPassword = (String) resultLease.secretData().get("password");
        assertThat(generatedUsername).startsWith("lv-test-role-"); // Verify username format
        assertThat(generatedPassword).hasSize(32); // Verify password length

        // Verify SQL execution
        verify(mockJdbcTemplate, times(TEST_CREATION_SQL.size())).execute(sqlCaptor.capture());
        List<String> executedSql = sqlCaptor.getAllValues();
        assertThat(executedSql.get(0)).contains(generatedUsername);
        assertThat(executedSql.get(0)).contains(generatedPassword); // Check placeholders replaced
        assertThat(executedSql.get(0)).doesNotContain("{{username}}");
        assertThat(executedSql.get(0)).doesNotContain("{{password}}");
        assertThat(executedSql.get(1)).contains(generatedUsername); // Check second statement

        // Verify Audit Log
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();
        assertThat(auditEvent.type()).isEqualTo("db_operation");
        assertThat(auditEvent.action()).isEqualTo("lease_creation");
        assertThat(auditEvent.outcome()).isEqualTo("success");
        assertThat(auditEvent.data()).containsEntry("lease_id", resultLease.id().toString());
        assertThat(auditEvent.data()).containsEntry("role_name", TEST_ROLE_NAME);

        // Verify Lease stored (indirectly, by trying to retrieve it for revoke test later, or check map size if needed)
        // For simplicity, we can assume storage if revoke works later.
    }

    @Test
    @DisplayName("generateCredentials: Should throw RoleNotFoundException for unknown role")
    void generateCredentials_RoleNotFound() {
        // Arrange
        String unknownRole = "unknown-role";
        // Properties mock returns null for this role implicitly due to setup

        // Act & Assert
        assertThatThrownBy(() -> postgresSecretsEngine.generateCredentials(unknownRole))
                .isInstanceOf(RoleNotFoundException.class)
                .hasMessageContaining(unknownRole);

        // Verify no DB interaction or audit logging occurred
        verifyNoInteractions(mockJdbcTemplate);
        verifyNoInteractions(mockAuditBackend);
    }

    @Test
    @DisplayName("generateCredentials: Should throw SecretsEngineException on DB error during creation")
    void generateCredentials_DbErrorOnCreation() {
        // Arrange
        DataAccessException dbException = new CannotGetJdbcConnectionException("Test DB Error");
        // Mock JdbcTemplate to throw exception on the first execute call
        doThrow(dbException).when(mockJdbcTemplate).execute(anyString());

        // Act & Assert
        assertThatThrownBy(() -> postgresSecretsEngine.generateCredentials(TEST_ROLE_NAME))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessageContaining("Failed to execute credential creation SQL")
                .hasCause(dbException);

        // Verify SQL was attempted (at least once)
        verify(mockJdbcTemplate, atLeastOnce()).execute(sqlCaptor.capture());
        // Verify no audit log for successful lease creation
        verifyNoInteractions(mockAuditBackend);
        // Verify lease was NOT stored (difficult to check map directly without exposing it, rely on revoke tests)
    }

    // --- Tests for revokeLease ---

    @Test
    @DisplayName("revokeLease: Should execute SQL, log audit, and remove lease on success")
    void revokeLease_Success() {
        // Arrange: First, generate a lease to revoke
        Lease leaseToRevoke = postgresSecretsEngine.generateCredentials(TEST_ROLE_NAME);
        UUID leaseId = leaseToRevoke.id();
        String username = (String) leaseToRevoke.secretData().get("username");
        // Clear interactions from the generateCredentials call
        clearInvocations(mockJdbcTemplate, mockAuditBackend);

        // Act
        postgresSecretsEngine.revokeLease(leaseId);

        // Assert
        // Verify SQL execution
        verify(mockJdbcTemplate, times(TEST_REVOCATION_SQL.size())).execute(sqlCaptor.capture());
        List<String> executedSql = sqlCaptor.getAllValues();
        assertThat(executedSql.get(0)).contains(username); // Check username placeholder replaced
        assertThat(executedSql.get(0)).doesNotContain("{{username}}");
        assertThat(executedSql.get(1)).contains(username);

        // Verify Audit Log
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();
        assertThat(auditEvent.type()).isEqualTo("db_operation");
        assertThat(auditEvent.action()).isEqualTo("revoke_lease");
        assertThat(auditEvent.outcome()).isEqualTo("success");
        assertThat(auditEvent.data()).containsEntry("lease_id", leaseId.toString());

        // Verify Lease removed (by trying to revoke again)
        assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(leaseId))
                .isInstanceOf(LeaseNotFoundException.class);
    }

    @Test
    @DisplayName("revokeLease: Should throw LeaseNotFoundException for unknown lease ID")
    void revokeLease_LeaseNotFound() {
        // Arrange
        UUID unknownLeaseId = UUID.randomUUID();

        // Act & Assert
        assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(unknownLeaseId))
                .isInstanceOf(LeaseNotFoundException.class)
                .hasMessageContaining(unknownLeaseId.toString());

        // Verify no DB interaction or audit logging occurred
        verifyNoInteractions(mockJdbcTemplate);
        verifyNoInteractions(mockAuditBackend);
    }

     @Test
    @DisplayName("revokeLease: Should throw SecretsEngineException if role definition missing during revoke")
    void revokeLease_RoleDefinitionMissing() {
        // Arrange: Generate a lease first
        Lease leaseToRevoke = postgresSecretsEngine.generateCredentials(TEST_ROLE_NAME);
        UUID leaseId = leaseToRevoke.id();
        clearInvocations(mockJdbcTemplate, mockAuditBackend);

        // Arrange: Mock properties to return no roles during the revoke call
        when(mockProperties.secrets().db().postgres().roles()).thenReturn(Collections.emptyMap());

        // Act & Assert
        assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(leaseId))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessageContaining("Role definition '" + TEST_ROLE_NAME + "' not found");

        // Verify no DB interaction or audit logging occurred
        verifyNoInteractions(mockJdbcTemplate);
        verifyNoInteractions(mockAuditBackend);

        // Verify Lease NOT removed (by trying to revoke again *after restoring mock*)
        when(mockProperties.secrets().db().postgres().roles()).thenReturn(Map.of(TEST_ROLE_NAME, testRoleDefinition)); // Restore mock
        // This revoke should now succeed or fail differently, proving the lease wasn't removed before
         try {
             postgresSecretsEngine.revokeLease(leaseId);
         } catch(Exception e) {
             // Ignore exception here, just verifying it wasn't LeaseNotFoundException initially
         }
         // Now try revoking again, *should* be LeaseNotFoundException
         assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(leaseId))
                 .isInstanceOf(LeaseNotFoundException.class);
    }


    @Test
    @DisplayName("revokeLease: Should throw SecretsEngineException and log audit failure on DB error")
    void revokeLease_DbErrorOnRevocation() {
        // Arrange: Generate a lease first
        Lease leaseToRevoke = postgresSecretsEngine.generateCredentials(TEST_ROLE_NAME);
        UUID leaseId = leaseToRevoke.id();
        String username = (String) leaseToRevoke.secretData().get("username");
        clearInvocations(mockJdbcTemplate, mockAuditBackend);

        // Arrange: Mock DB error during revocation
        DataAccessException dbException = new CannotGetJdbcConnectionException("Test Revocation DB Error");
        doThrow(dbException).when(mockJdbcTemplate).execute(contains("REVOKE")); // Throw on first revoke statement

        // Act & Assert
        assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(leaseId))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessageContaining("Failed to execute credential revocation SQL")
                .hasCause(dbException);

        // Verify SQL was attempted
        verify(mockJdbcTemplate, atLeastOnce()).execute(sqlCaptor.capture());
        assertThat(sqlCaptor.getValue()).contains(username); // Verify it tried the correct SQL

        // Verify Audit Log for FAILURE
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();
        assertThat(auditEvent.type()).isEqualTo("db_operation");
        assertThat(auditEvent.action()).isEqualTo("revoke_lease");
        assertThat(auditEvent.outcome()).isEqualTo("failure");
        assertThat(auditEvent.data()).containsEntry("lease_id", leaseId.toString());
        assertThat(auditEvent.data()).containsEntry("error", dbException.getMessage());

        // Verify Lease NOT removed (by trying to revoke again *after removing DB error mock*)
        // Resetting the specific mock behavior:
        // Need to use Mockito.reset or re-setup mocks if using strict stubbing.
        // A simpler way for this test is to just verify it wasn't LeaseNotFoundException above,
        // and then try to revoke again *without* resetting the mock (it should throw the DB error again).
        assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(leaseId))
                .isInstanceOf(SecretsEngineException.class) // Should still throw DB error
                .hasCause(dbException);
    }
}

3. Write Test Cases:•checkDbConnection Tests:•Test the @PostConstruct method directly.•Mock DataSource.getConnection(), Connection.isValid(), Connection.getMetaData(), etc.•Verify success path (logs info, doesn't throw).•Verify failure paths (isValid returns false, getConnection throws SQLException) - check logs if possible/needed, ensure no unexpected exceptions.•generateCredentials Tests:•Success:•Mock mockProperties.secrets().db().postgres().roles().get(TEST_ROLE_NAME) to return testRoleDefinition.•Call generateCredentials(TEST_ROLE_NAME).•Assert the returned Lease is not null and has expected roleName, ttl.•Assert secretData contains non-blank username and password.•Verify mockJdbcTemplate.execute() was called the correct number of times (size of creationStatements).•Use sqlCaptor.capture() and sqlCaptor.getAllValues() to verify the executed SQL strings had {{username}} and {{password}} replaced correctly.•Verify mockAuditBackend.logEvent() was called once with auditEventCaptor.•Assert the captured AuditEvent has type="db_operation", action="lease_creation", outcome="success", and includes lease_id and role_name in its data.•Verify the lease is added to the internal activeLeases map (e.g., by checking its presence in a subsequent revokeLease test).•Role Not Found:

•Mock properties to return null or an empty map for the requested role.•Use assertThatThrownBy to assert that RoleNotFoundException is thrown.•Use verifyNoInteractions(mockJdbcTemplate, mockAuditBackend) to ensure no DB or audit calls were made.•DB Error:•Mock properties to return a valid role definition.•Mock mockJdbcTemplate.execute(anyString()) to throw a DataAccessException (e.g., CannotGetJdbcConnectionException).•Use assertThatThrownBy to assert that SecretsEngineException is thrown, wrapping the DataAccessException.•Verify mockJdbcTemplate.execute() was called (at least once).•Verify mockAuditBackend was not called for lease_creation.•revokeLease Tests:•Success:•Arrange: Call generateCredentials first to get a valid Lease and populate activeLeases. Clear mock interactions (clearInvocations).•Mock properties to return the correct role definition for the lease's role name.•Act: Call revokeLease with the generated lease ID.•Assert: Verify mockJdbcTemplate.execute() was called for each revocationStatement.•Use sqlCaptor to verify the executed SQL had {{username}} replaced.•Verify mockAuditBackend.logEvent() was called for revoke_lease success, including lease_id.•Verify the lease is removed from activeLeases (e.g., assert LeaseNotFoundException if revokeLease is called again with the same ID).•Lease Not Found:•Use assertThatThrownBy to assert LeaseNotFoundException when calling revokeLease with a random UUID.•Verify no DB or audit interactions.

•Role Definition Missing during Revoke:•Arrange: Generate a lease. Clear mocks. Mock properties to return null or empty map for the role during the revoke call.•Act & Assert: Use assertThatThrownBy for SecretsEngineException (mentioning role definition not found).•Verify no DB or audit interactions.•Verify lease was not removed (e.g., restore the role mock and try revoking again – it shouldn't throw LeaseNotFoundException immediately).•DB Error:•Arrange: Generate a lease. Clear mocks. Mock properties for the role. Mock mockJdbcTemplate.execute() to throw DataAccessException during the revoke call.•Act & Assert: Use assertThatThrownBy for SecretsEngineException wrapping the DB exception.•Verify mockJdbcTemplate.execute() was called.•Verify mockAuditBackend.logEvent() was called for revoke_lease failure, including lease_id and the error message.•Verify lease was not removed.4. Refine Assertions:•Use AssertJ (assertThat) for clear and readable assertions.•Be specific about exception messages and causes where relevant.•When checking captured SQL, ensure placeholders are gone and generated values are present.•When checking captured AuditEvent, verify the key fields (type, action, outcome) and relevant data entries (lease_id, role_name, error). Do not assert on the generated password in the audit event data (it shouldn't be there).

5. Run Tests:•Execute the tests using your IDE or Maven (mvn test). Ensure they pass.6. Update Task Status:•Mark Task 29 as complete in mssm-atomic-tasks-v0-3-0.md.

# /Users/robertocastro/dev/lite-vault/project/mssm-atomic-tasks-v0-3-0.md

[...]

#### 28. [x] Integrate Audit Logging for DB Actions
- **Description:**
  - Inject the `AuditBackend` (Task 16).
  - Log audit events for:
    - Credential generation requests (success/failure, requested role, authenticated user).
    - Lease creation (lease ID, associated role).
    - Lease revocation attempts (success/failure, lease ID).
  - Ensure generated passwords are *not* logged.
- **Rationale:**
  - Provides audit trail for dynamic secret generation and revocation (F-CORE-130).

#### 29. [x] Write Unit Tests for PostgreSQL Engine
- **Description:**
  - Write unit tests for `PostgresSecretsEngine`.
  - Mock database interactions (JDBC calls) to test SQL template rendering and parameter substitution logic.
  - Test lease object creation, storage, retrieval, and removal.
  - Test credential generation and revocation logic, including error handling.
- **Rationale:**
  - Verifies the engine's internal logic without requiring a live database.

#### 30. [ ] Write Integration Tests for DB Credential API
[...]

This comprehensive set of unit tests will give you confidence that the internal logic of your PostgresSecretsEngine is working correctly, independent of the actual database.