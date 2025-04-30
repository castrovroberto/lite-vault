package tech.yump.vault.secrets;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Represents a lease associated with a dynamically generated secret.
 * Contains the secret data, metadata about its lifetime, and renewal status.
 *
 * @param id           A unique identifier for this specific lease instance.
 * @param engineName   The name or type of the secrets engine that generated this lease (e.g., "postgres").
 * @param roleName     The specific role configuration used to generate the secret.
 * @param secretData   The actual generated secret credentials or data (e.g., username, password).
 *                     Using Map<String, Object> for flexibility across different secret types.
 * @param creationTime The timestamp when the lease (and secret) was created.
 * @param ttl          The initial time-to-live duration granted to the lease.
 * @param renewable    Flag indicating if this lease can be renewed.
 */
public record Lease(
        UUID id,
        String engineName,
        String roleName,
        Map<String, Object> secretData,
        Instant creationTime,
        Duration ttl,
        boolean renewable
) {
    /**
     * Calculates the expiration time based on creation time and TTL.
     *
     * @return The Instant when this lease expires.
     */
    public Instant getExpirationTime() {
        return creationTime.plus(ttl);
    }
}