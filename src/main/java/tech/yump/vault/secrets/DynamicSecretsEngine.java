package tech.yump.vault.secrets;

import java.util.UUID;

/**
 * Interface for secrets engines that generate dynamic secrets with leases.
 * Extends the base SecretsEngine interface.
 */
public interface DynamicSecretsEngine extends SecretsEngine {

    /**
     * Generates new credentials based on a configured role.
     *
     * @param roleName The name of the role configuration to use for generation.
     * @return A Lease object containing the generated secret data and lease metadata.
     * @throws SecretsEngineException If credential generation fails (e.g., configuration error, backend error).
     * @throws RoleNotFoundException If the specified roleName does not exist or is not configured.
     */
    Lease generateCredentials(String roleName) throws SecretsEngineException, RoleNotFoundException;

    /**
     * Revokes an existing lease, invalidating the associated secret.
     * Implementations should attempt to clean up the generated secret (e.g., drop DB user).
     *
     * @param leaseId The unique ID of the lease to revoke.
     * @throws SecretsEngineException If revocation fails (e.g., backend error).
     * @throws LeaseNotFoundException If the specified leaseId does not exist or is not managed by this engine.
     */
    void revokeLease(UUID leaseId) throws SecretsEngineException, LeaseNotFoundException;

    // Potential future methods:
    // Lease renewLease(UUID leaseId, Duration requestedDuration) throws SecretsEngineException, LeaseNotFoundException, LeaseNotRenewableException;
}