package tech.yump.vault.service;

import tech.yump.vault.api.dto.DbCredentialsResponse;
import tech.yump.vault.secrets.LeaseNotFoundException;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;

import java.util.UUID;

/**
 * Service layer interface for managing dynamic database credentials.
 */
public interface DbCredentialService {

    /**
     * Generates dynamic credentials for a specific role.
     *
     * @param roleName The name of the configured role.
     * @return A DTO containing the generated credentials and lease information.
     * @throws RoleNotFoundException If the role is not configured.
     * @throws SecretsEngineException If an error occurs during generation.
     * @throws tech.yump.vault.core.VaultSealedException If the vault is sealed.
     */
    DbCredentialsResponse generateCredentialsForRole(String roleName) throws RoleNotFoundException, SecretsEngineException;

    /**
     * Revokes an existing credential lease.
     *
     * @param leaseId The ID of the lease to revoke.
     * @throws LeaseNotFoundException If the lease ID is not found or already revoked.
     * @throws SecretsEngineException If an error occurs during revocation.
     * @throws tech.yump.vault.core.VaultSealedException If the vault is sealed.
     */
    void revokeCredentialLease(UUID leaseId) throws LeaseNotFoundException, SecretsEngineException;
}