package tech.yump.vault.secrets;

import java.util.UUID;

/**
 * Exception thrown when a requested lease ID is not found.
 */
public class LeaseNotFoundException extends SecretsEngineException {
    public LeaseNotFoundException(UUID leaseId) {
        super("Lease not found: " + leaseId);
    }
}