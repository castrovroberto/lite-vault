package tech.yump.vault.api.dto;

import java.util.UUID;

/**
 * DTO representing the response for a dynamic database credential request.
 *
 * @param leaseId            The unique ID associated with this credential lease.
 * @param username           The generated database username.
 * @param password           The generated database password.
 * @param leaseDurationSeconds The duration (in seconds) for which this lease is valid.
 */
public record DbCredentialsResponse(
        UUID leaseId,
        String username,
        String password,
        long leaseDurationSeconds // Represent duration as seconds for simple JSON
) {}