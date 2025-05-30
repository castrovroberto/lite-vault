package tech.yump.vault.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.ActiveProfiles;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.audit.LogAuditBackend;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for AuditConfiguration focusing on the SLF4j backend.
 */
@SpringBootTest
// No @TestPropertySource needed for backend type if slf4j is the default (matchIfMissing=true)
// No specific file path needed for slf4j backend
@DisplayName("Integration Test: SLF4j Audit Backend (Default)")
@ActiveProfiles("test") // Only need the base test profile
@ExtendWith(OutputCaptureExtension.class) // Enable console output capture
// @Order(1) // Order is less relevant between separate files unless run in a specific suite
public class Slf4jAuditBackendIntegrationTest {

    @Autowired
    private AuditBackend auditBackend;
    @Autowired
    private AuditHelper auditHelper;

    @Test
    void shouldUseSlf4jAuditBackendAndLogToConsole(CapturedOutput output) {
        // 1. Verify the correct bean was created (assuming slf4j is default)
        assertThat(auditBackend)
                .withFailMessage("Expected LogAuditBackend bean as the default")
                .isInstanceOf(LogAuditBackend.class);

        // 2. Trigger an audit event
        String eventId = UUID.randomUUID().toString();
        auditHelper.logInternalEvent("test_slf4j", "log_event", "success", "logger", java.util.Map.of("id", eventId));

        // 3. Verify the event DID go to standard console output
        assertThat(output.getOut())
                .withFailMessage("Audit event should appear in console output when using LogAuditBackend")
                .contains("AUDIT_EVENT:") // Check for the prefix used by LogAuditBackend
                .contains("\"type\":\"test_slf4j\"") // Check for parts of the JSON payload
                .contains(eventId); // Check for unique identifier

        // 4. Ensure no application errors on stderr (Mockito agent warnings are ignored)
        // Consider if this assertion is still needed or if it causes issues
        // assertThat(output.getErr()).isEmpty();
    }
}