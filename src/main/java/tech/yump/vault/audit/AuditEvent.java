package tech.yump.vault.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.time.Instant;
import java.util.Map;

/**
 * Represents a single audit log entry.
 * Contains information about the request, authentication, action, and outcome.
 * Designed to be logged in a structured format (e.g., JSON).
 */
@Builder // Use Lombok Builder for easier construction
@JsonInclude(JsonInclude.Include.NON_NULL) // Don't include null fields in JSON output
public record AuditEvent(
        Instant timestamp,       // When the event occurred
        String type,            // Type of event (e.g., "request", "auth", "kv_operation")
        String action,          // Specific action performed (e.g., "login_attempt", "read_secret", "policy_check")
        String outcome,         // Result of the action (e.g., "success", "failure", "denied")

        // Authentication Information
        AuthInfo authInfo,

        // Request Information
        RequestInfo requestInfo,

        // Response Information
        ResponseInfo responseInfo,

        // Optional additional data specific to the event
        Map<String, Object> data
) {

    /**
     * Information about the authenticated entity, if available.
     */
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuthInfo(
            String principal,     // Identifier of the authenticated entity (e.g., token ID)
            String sourceAddress, // IP address of the client initiating the request
            Map<String, Object> metadata // e.g., associated policy names
    ) {}

    /**
     * Information about the incoming request.
     */
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RequestInfo(
            String requestId,     // Unique ID for the request (can be generated or retrieved)
            String httpMethod,    // e.g., GET, PUT, DELETE
            String path,          // Request path (e.g., "/v1/kv/data/myapp/config")
            Map<String, String> headers // Potentially relevant headers (non-sensitive only!)
    ) {}

    /**
     * Information about the response sent back.
     */
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ResponseInfo(
            int statusCode,       // HTTP status code (e.g., 200, 403, 500)
            String errorMessage   // Error message if the outcome was failure/denied
    ) {}

    // Static factory method for convenience if needed later, or rely on Lombok Builder
    // public static AuditEvent create(...) { ... }
}
