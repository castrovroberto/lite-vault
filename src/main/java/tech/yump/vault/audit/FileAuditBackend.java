// src/main/java/tech/yump/vault/audit/FileAuditBackend.java
package tech.yump.vault.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An AuditBackend implementation that logs audit events as JSON strings
 * to a dedicated audit log file configured via Logback.
 */
@RequiredArgsConstructor // Constructor for ObjectMapper injection
@Slf4j // Use standard logger for internal errors (e.g., serialization failure)
public class FileAuditBackend implements AuditBackend {

    // The specific logger name configured in logback-spring.xml for audit events
    private static final String AUDIT_LOGGER_NAME = "tech.yump.vault.audit.FILE_AUDIT";
    private static final Logger auditLogger = LoggerFactory.getLogger(AUDIT_LOGGER_NAME);

    private final ObjectMapper objectMapper; // Inject shared ObjectMapper

    @Override
    public void logEvent(AuditEvent event) {
        if (event == null) {
            log.warn("Attempted to log a null audit event.");
            return;
        }

        try {
            // Serialize the AuditEvent to a JSON string
            String jsonEvent = objectMapper.writeValueAsString(event);
            // Log the JSON string using the dedicated audit logger
            // The logback configuration ensures this goes ONLY to the audit file
            auditLogger.info(jsonEvent);
        } catch (JsonProcessingException e) {
            // Log serialization errors to the main application log, not the audit log
            log.error("Failed to serialize AuditEvent to JSON for file audit logging. Event: {}", event, e);
            // Consider logging a minimal fallback to the audit log if absolutely required,
            // but it might pollute the JSON structure. Sticking to error log is safer.
            // auditLogger.error("AUDIT_SERIALIZATION_ERROR: {}", event.toString()); // Avoid if possible
        }
    }
}