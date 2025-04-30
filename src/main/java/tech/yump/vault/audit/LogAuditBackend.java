package tech.yump.vault.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * An AuditBackend implementation that logs audit events as JSON strings
 * to the configured SLF4j logger (typically at INFO level).
 */
@Service // Mark as a Spring service component
@Slf4j   // Lombok annotation for SLF4j logger instance
public class LogAuditBackend implements AuditBackend {

    private final ObjectMapper objectMapper;

    public LogAuditBackend() {
        // Configure ObjectMapper for consistent JSON output, including Java 8+ time
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        // Optional: Configure pretty printing for development if desired
        // this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    @Override
    public void logEvent(AuditEvent event) {
        if (event == null) {
            log.warn("Attempted to log a null audit event.");
            return;
        }

        try {
            // Serialize the AuditEvent to a JSON string
            String jsonEvent = objectMapper.writeValueAsString(event);
            // Log the JSON string at INFO level
            // Using a specific marker or prefix could be useful for filtering later
            log.info("AUDIT_EVENT: {}", jsonEvent);
        } catch (JsonProcessingException e) {
            // Fallback logging if JSON serialization fails
            log.error("Failed to serialize AuditEvent to JSON. Logging raw event details.", e);
            log.info("AUDIT_EVENT_FALLBACK: {}", event.toString()); // Log basic toString()
        }
    }
}