package tech.yump.vault.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tech.yump.vault.api.dto.DbCredentialsResponse;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.LeaseNotFoundException;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.db.PostgresSecretsEngine;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DbCredentialServiceImplTest {

    @Mock
    private PostgresSecretsEngine mockPostgresEngine;

    @InjectMocks
    private DbCredentialServiceImpl dbCredentialService;

    private final String TEST_ROLE = "test-role";
    private final UUID TEST_LEASE_ID = UUID.randomUUID();
    private final String TEST_USERNAME = "test-user";
    private final String TEST_PASSWORD = "test-password";
    private final Duration TEST_TTL = Duration.ofMinutes(30);
    private Lease testLease;

    @BeforeEach
    void setUp() {
        testLease = new Lease(
                TEST_LEASE_ID,
                "postgres",
                TEST_ROLE,
                Map.of("username", TEST_USERNAME, "password", TEST_PASSWORD),
                Instant.now(),
                TEST_TTL,
                false
        );
    }

    // --- generateCredentialsForRole Tests ---

    @Test
    @DisplayName("generateCredentialsForRole: Should call engine and map Lease to Response DTO on success")
    void generateCredentialsForRole_Success() {
        // Arrange
        when(mockPostgresEngine.generateCredentials(TEST_ROLE)).thenReturn(testLease);

        // Act
        DbCredentialsResponse response = dbCredentialService.generateCredentialsForRole(TEST_ROLE);

        // Assert
        assertThat(response).isNotNull();
        assertThat(response.leaseId()).isEqualTo(TEST_LEASE_ID);
        assertThat(response.username()).isEqualTo(TEST_USERNAME);
        assertThat(response.password()).isEqualTo(TEST_PASSWORD);
        assertThat(response.leaseDurationSeconds()).isEqualTo(TEST_TTL.toSeconds());

        verify(mockPostgresEngine, times(1)).generateCredentials(TEST_ROLE);
    }

    @Test
    @DisplayName("generateCredentialsForRole: Should throw SecretsEngineException if Lease data is incomplete (missing username)")
    void generateCredentialsForRole_IncompleteLease_MissingUsername() {
        // Arrange
        Lease incompleteLease = new Lease(
                TEST_LEASE_ID, "postgres", TEST_ROLE,
                Map.of("password", TEST_PASSWORD), // Missing username
                Instant.now(), TEST_TTL, false
        );
        when(mockPostgresEngine.generateCredentials(TEST_ROLE)).thenReturn(incompleteLease);

        // Act & Assert
        assertThatThrownBy(() -> dbCredentialService.generateCredentialsForRole(TEST_ROLE))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessageContaining("Generated credentials incomplete");

        verify(mockPostgresEngine, times(1)).generateCredentials(TEST_ROLE);
    }

    @Test
    @DisplayName("generateCredentialsForRole: Should throw SecretsEngineException if Lease data is incomplete (missing password)")
    void generateCredentialsForRole_IncompleteLease_MissingPassword() {
        // Arrange
        Lease incompleteLease = new Lease(
                TEST_LEASE_ID, "postgres", TEST_ROLE,
                Map.of("username", TEST_USERNAME), // Missing password
                Instant.now(), TEST_TTL, false
        );
        when(mockPostgresEngine.generateCredentials(TEST_ROLE)).thenReturn(incompleteLease);

        // Act & Assert
        assertThatThrownBy(() -> dbCredentialService.generateCredentialsForRole(TEST_ROLE))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessageContaining("Generated credentials incomplete");

        verify(mockPostgresEngine, times(1)).generateCredentials(TEST_ROLE);
    }

    @Test
    @DisplayName("generateCredentialsForRole: Should propagate RoleNotFoundException from engine")
    void generateCredentialsForRole_PropagatesRoleNotFound() {
        // Arrange
        when(mockPostgresEngine.generateCredentials(TEST_ROLE)).thenThrow(new RoleNotFoundException(TEST_ROLE));

        // Act & Assert
        assertThatThrownBy(() -> dbCredentialService.generateCredentialsForRole(TEST_ROLE))
                .isInstanceOf(RoleNotFoundException.class);

        verify(mockPostgresEngine, times(1)).generateCredentials(TEST_ROLE);
    }

    @Test
    @DisplayName("generateCredentialsForRole: Should propagate VaultSealedException from engine")
    void generateCredentialsForRole_PropagatesVaultSealed() {
        // Arrange
        when(mockPostgresEngine.generateCredentials(TEST_ROLE)).thenThrow(new VaultSealedException("Sealed"));

        // Act & Assert
        assertThatThrownBy(() -> dbCredentialService.generateCredentialsForRole(TEST_ROLE))
                .isInstanceOf(VaultSealedException.class);

        verify(mockPostgresEngine, times(1)).generateCredentials(TEST_ROLE);
    }

    @Test
    @DisplayName("generateCredentialsForRole: Should propagate SecretsEngineException from engine")
    void generateCredentialsForRole_PropagatesSecretsEngineException() {
        // Arrange
        when(mockPostgresEngine.generateCredentials(TEST_ROLE)).thenThrow(new SecretsEngineException("DB Error"));

        // Act & Assert
        assertThatThrownBy(() -> dbCredentialService.generateCredentialsForRole(TEST_ROLE))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessage("DB Error"); // Check message propagation

        verify(mockPostgresEngine, times(1)).generateCredentials(TEST_ROLE);
    }

    // --- revokeCredentialLease Tests ---

    @Test
    @DisplayName("revokeCredentialLease: Should call engine revokeLease on success")
    void revokeCredentialLease_Success() {
        // Arrange
        // No exception thrown by mock engine by default

        // Act
        dbCredentialService.revokeCredentialLease(TEST_LEASE_ID);

        // Assert
        verify(mockPostgresEngine, times(1)).revokeLease(TEST_LEASE_ID);
    }

    @Test
    @DisplayName("revokeCredentialLease: Should propagate LeaseNotFoundException from engine")
    void revokeCredentialLease_PropagatesLeaseNotFound() {
        // Arrange
        doThrow(new LeaseNotFoundException(TEST_LEASE_ID)).when(mockPostgresEngine).revokeLease(TEST_LEASE_ID);

        // Act & Assert
        assertThatThrownBy(() -> dbCredentialService.revokeCredentialLease(TEST_LEASE_ID))
                .isInstanceOf(LeaseNotFoundException.class);

        verify(mockPostgresEngine, times(1)).revokeLease(TEST_LEASE_ID);
    }

    @Test
    @DisplayName("revokeCredentialLease: Should propagate VaultSealedException from engine")
    void revokeCredentialLease_PropagatesVaultSealed() {
        // Arrange
        doThrow(new VaultSealedException("Sealed")).when(mockPostgresEngine).revokeLease(TEST_LEASE_ID);

        // Act & Assert
        assertThatThrownBy(() -> dbCredentialService.revokeCredentialLease(TEST_LEASE_ID))
                .isInstanceOf(VaultSealedException.class);

        verify(mockPostgresEngine, times(1)).revokeLease(TEST_LEASE_ID);
    }

    @Test
    @DisplayName("revokeCredentialLease: Should propagate SecretsEngineException from engine")
    void revokeCredentialLease_PropagatesSecretsEngineException() {
        // Arrange
        doThrow(new SecretsEngineException("DB Revoke Error")).when(mockPostgresEngine).revokeLease(TEST_LEASE_ID);

        // Act & Assert
        assertThatThrownBy(() -> dbCredentialService.revokeCredentialLease(TEST_LEASE_ID))
                .isInstanceOf(SecretsEngineException.class)
                .hasMessage("DB Revoke Error");

        verify(mockPostgresEngine, times(1)).revokeLease(TEST_LEASE_ID);
    }
}