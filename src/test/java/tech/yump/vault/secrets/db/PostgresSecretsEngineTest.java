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
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.CannotGetJdbcConnectionException;
import org.springframework.jdbc.core.JdbcTemplate;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.core.SealManager;
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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PostgresSecretsEngineTest {

    @Mock
    private MssmProperties mockProperties;
    @Mock
    private DataSource mockDataSource;
    @Mock
    private JdbcTemplate mockJdbcTemplate;
    @Mock
    private SealManager mockSealManager;
    @Mock
    private AuditHelper mockAuditHelper; // Keep AuditHelper mock

    // Removed: @Mock private AuditBackend mockAuditBackend;

    @Mock
    private Connection mockConnection;
    @Mock
    private DatabaseMetaData mockMetaData;

    @InjectMocks
    private PostgresSecretsEngine postgresSecretsEngine;

    @Captor
    private ArgumentCaptor<String> sqlCaptor;

    // Removed: @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

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

    @Mock
    private MssmProperties.SecretsProperties mockSecretsProperties;
    @Mock
    private MssmProperties.DbSecretsProperties mockDbSecretsProperties;
    @Mock
    private MssmProperties.PostgresProperties mockPostgresProperties;


    @BeforeEach
    void setUp() {
        // Set up the nested properties structure for mocking
        testRoleDefinition = new MssmProperties.PostgresRoleDefinition(
                TEST_CREATION_SQL,
                TEST_REVOCATION_SQL,
                TEST_TTL
        );

        lenient().when(mockProperties.secrets()).thenReturn(mockSecretsProperties);
        lenient().when(mockSecretsProperties.db()).thenReturn(mockDbSecretsProperties);
        lenient().when(mockDbSecretsProperties.postgres()).thenReturn(mockPostgresProperties);

        // Mock the final roles() call on the last mock in the chain
        lenient().when(mockPostgresProperties.roles()).thenReturn(Map.of(TEST_ROLE_NAME, testRoleDefinition));

        // ALSO: Mock other methods on mockPostgresProperties if your code needs them
        // (Based on the original postgresProperties instantiation)
        lenient().when(mockPostgresProperties.connectionUrl()).thenReturn("jdbc:postgresql://host:5432/db");
        lenient().when(mockPostgresProperties.username()).thenReturn("user");
        lenient().when(mockPostgresProperties.password()).thenReturn("pass");
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
        postgresSecretsEngine.checkDbConnection(); // Call directly to test @PostConstruct logic

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
        // Mock metadata retrieval even on failure path if it's called before isValid check fails
        lenient().when(mockConnection.getMetaData()).thenReturn(mockMetaData);
        lenient().when(mockMetaData.getURL()).thenReturn("jdbc:mock-invalid");
        lenient().when(mockMetaData.getUserName()).thenReturn("mockUser-invalid");

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
        // Arrange (Properties mock already set up in @BeforeEach)

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
        assertThat(generatedPassword).hasSize(32); // Verify password length (default)

        // Verify SQL execution
        verify(mockJdbcTemplate, times(TEST_CREATION_SQL.size())).execute(sqlCaptor.capture());
        List<String> executedSql = sqlCaptor.getAllValues();
        assertThat(executedSql.get(0)).contains(generatedUsername);
        assertThat(executedSql.get(0)).contains(generatedPassword); // Check placeholders replaced
        assertThat(executedSql.get(0)).doesNotContain("{{username}}");
        assertThat(executedSql.get(0)).doesNotContain("{{password}}");
        assertThat(executedSql.get(1)).contains(generatedUsername); // Check second statement

        // --- UPDATED Audit Log Verification ---
        // Verify interaction with AuditHelper instead of AuditBackend
        verify(mockAuditHelper).logInternalEvent(
                eq("db_operation"),              // type
                eq("lease_creation"),           // action
                eq("success"),                  // outcome
                isNull(),                       // principal (expecting null as passed by engine)
                eq(Map.of(                      // data
                        "lease_id", resultLease.id().toString(),
                        "role_name", TEST_ROLE_NAME
                ))
        );
        // --- END UPDATED Audit Log Verification ---

        // Verify Lease stored (indirectly by checking revokeLease behavior later)
    }

    @Test
    @DisplayName("generateCredentials: Should throw RoleNotFoundException for unknown role")
    void generateCredentials_RoleNotFound() {
        // Arrange
        String unknownRole = "unknown-role";
        // Explicitly mock roles() to return the map without the unknown role for clarity
        // (This overrides the lenient mock from setUp for this specific test)
        when(mockProperties.secrets().db().postgres().roles()).thenReturn(Map.of(TEST_ROLE_NAME, testRoleDefinition));

        // Act & Assert
        assertThatThrownBy(() -> postgresSecretsEngine.generateCredentials(unknownRole))
                .isInstanceOf(RoleNotFoundException.class)
                .hasMessageContaining(unknownRole);

        // Verify no DB interaction or audit logging occurred
        verifyNoInteractions(mockJdbcTemplate);
        verifyNoInteractions(mockAuditHelper); // Also verify no audit helper interaction
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
        verifyNoInteractions(mockAuditHelper); // No audit log on creation failure path yet
    }

    // --- Tests for revokeLease ---

    @Test
    @DisplayName("revokeLease: Should execute SQL, log audit, and remove lease on success")
    void revokeLease_Success() {
        // Arrange: First, generate a lease to revoke
        Lease leaseToRevoke = postgresSecretsEngine.generateCredentials(TEST_ROLE_NAME);
        UUID leaseId = leaseToRevoke.id();
        String username = (String) leaseToRevoke.secretData().get("username");
        // Clear interactions from the generateCredentials call for clean verification
        clearInvocations(mockJdbcTemplate, mockAuditHelper); // Clear AuditHelper mock too

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
        verify(mockAuditHelper).logInternalEvent(
                eq("db_operation"),
                eq("revoke_lease"),
                eq("success"),
                isNull(),
                eq(Map.of("lease_id", leaseId.toString()))
        );

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
        verifyNoInteractions(mockAuditHelper); // Also verify no audit helper interaction
    }

    @Test
    @DisplayName("revokeLease: Should throw SecretsEngineException if role definition missing during revoke")
    void revokeLease_RoleDefinitionMissing() {
        // Arrange: Generate a lease first
        Lease leaseToRevoke = postgresSecretsEngine.generateCredentials(TEST_ROLE_NAME);
        UUID leaseId = leaseToRevoke.id();
        // Clear interactions from generate
        clearInvocations(mockJdbcTemplate, mockAuditHelper);

        // Arrange: Mock properties to return no roles during the revoke call
        // This overrides the lenient mock from setUp for this specific interaction
        when(mockProperties.secrets().db().postgres().roles()).thenReturn(Collections.emptyMap());

        // Act & Assert: Verify the initial failure due to missing role
        assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(leaseId))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessageContaining("Role definition '" + TEST_ROLE_NAME + "' not found");

        // Verify no DB interaction or audit logging occurred during the failed attempt
        verifyNoInteractions(mockJdbcTemplate);
        verifyNoInteractions(mockAuditHelper); // Also verify no audit helper interaction

        // --- Simplified Verification: Lease NOT removed by the failed attempt ---
        // 1. Restore the mock for the roles map to its original state from setUp
        when(mockProperties.secrets().db().postgres().roles()).thenReturn(Map.of(TEST_ROLE_NAME, testRoleDefinition));

        // 2. Attempt to revoke again. This should NOT throw LeaseNotFoundException,
        //    proving the lease still existed after the first failed attempt.
        //    It should now succeed (assuming no other mocks interfere).
        assertThatCode(() -> postgresSecretsEngine.revokeLease(leaseId))
                .doesNotThrowAnyException();

        // 3. Verify the lease IS removed now by calling revoke a final time.
        //    This call MUST throw LeaseNotFoundException.
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
        // Clear interactions from generate
        clearInvocations(mockJdbcTemplate, mockAuditHelper);

        // Arrange: Mock DB error during revocation
        DataAccessException dbException = new CannotGetJdbcConnectionException("Test Revocation DB Error");
        // Mock the first revocation statement to throw the exception
        doThrow(dbException).when(mockJdbcTemplate).execute(contains("REVOKE"));

        // Act & Assert
        assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(leaseId))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessageContaining("Failed to execute credential revocation SQL")
                .hasCause(dbException);

        // Verify SQL was attempted (at least the first statement)
        verify(mockJdbcTemplate, atLeastOnce()).execute(sqlCaptor.capture());
        assertThat(sqlCaptor.getValue()).contains(username); // Verify it tried the correct SQL

        // Verify Audit Log for FAILURE
        verify(mockAuditHelper).logInternalEvent(
                eq("db_operation"),
                eq("revoke_lease"),
                eq("failure"),
                isNull(),
                eq(Map.of(
                        "lease_id", leaseId.toString(),
                        "error", dbException.getMessage() // Verify error message is included
                ))
        );

        // Verify Lease NOT removed: Attempt to revoke again, it should fail the same way
        // because the lease still exists and the DB error mock is still active.
        assertThatThrownBy(() -> postgresSecretsEngine.revokeLease(leaseId))
                .isInstanceOf(SecretsEngineException.class) // Should still throw DB error
                .hasCause(dbException); // Verify it's the same underlying cause
    }
}