package tech.yump.vault.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * An AuditBackend implementation that logs audit events as JSON strings
 * to the configured SLF4j logger (typically at INFO level).
 */

@Slf4j
@RequiredArgsConstructor
public class LogAuditBackend implements AuditBackend {

    private final ObjectMapper objectMapper;

    @Override
    public void logEvent(AuditEvent event) {
        if (event == null) {
            log.warn("Attempted to log a null audit event.");
            return;
        }

        try {
            String jsonEvent = objectMapper.writeValueAsString(event);
            log.info("AUDIT_EVENT: {}", jsonEvent);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize AuditEvent to JSON. Logging raw event details.", e);
            log.info("AUDIT_EVENT_FALLBACK: {}", event.toString());
        }
    }
}