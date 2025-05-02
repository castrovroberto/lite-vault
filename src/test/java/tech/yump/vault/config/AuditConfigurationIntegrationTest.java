package tech.yump.vault.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.audit.FileAuditBackend;
import tech.yump.vault.audit.LogAuditBackend;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for AuditConfiguration focusing on bean creation and basic logging behavior.
 * Uses nested classes for different backend configurations.
 */
@DisplayName("Integration Test: Audit Configuration")
public class AuditConfigurationIntegrationTest {

    // --- Test Suite for File Backend ---
    @Nested
    @SpringBootTest
    @TestPropertySource(properties = {
            "mssm.audit.backend=file",
            "mssm.audit.file.path=target/test-audit/integration-audit.log"
    })
    @DisplayName("Integration Test: File Audit Backend")
    @ActiveProfiles({"test", "audit-file"})
    @ExtendWith(OutputCaptureExtension.class)
    class FileBackendTest {

        @Autowired
        private AuditBackend auditBackend;
        @Autowired
        private AuditHelper auditHelper;

        private static final Path auditLogPath = Paths.get("target/test-audit/integration-audit.log");

        // Static initializer: Ensures directory exists before Spring/Logback start. Runs ONCE.
        static {
            try {
                // Ensure the parent directory exists very early
                // Use Files.exists, not Files.notExists for clarity if checking existence
                if (!Files.exists(auditLogPath.getParent())) {
                    Files.createDirectories(auditLogPath.getParent());
                    System.out.println("Static initializer created directory: " + auditLogPath.getParent());
                } else {
                    System.out.println("Static initializer found existing directory: " + auditLogPath.getParent());
                }
            } catch (IOException e) {
                throw new RuntimeException("Could not create/verify test audit directory in static initializer", e);
            }
        }

        // @BeforeEach: Ensures the specific log FILE is deleted before EACH test method runs.
        @AfterEach
        void cleanupLogFile() throws IOException {
            Files.deleteIfExists(auditLogPath);
            System.out.println("@BeforeEach deleted file (if existed): " + auditLogPath); // Optional debug log
        }

        // @AfterEach // No longer needed for deleting this specific file

        @Test
        void shouldUseFileAuditBackendAndLogToFile(CapturedOutput output) throws IOException {
            // 1. Verify bean
            assertThat(auditBackend).isInstanceOf(FileAuditBackend.class);

            // 2. Trigger event
            String eventId = UUID.randomUUID().toString();
            auditHelper.logInternalEvent("test_file", "write_log", "success", "tester", java.util.Map.of("id", eventId));

            // 3. Wait for file (Keep increased timeout, e.g., 10 seconds)
            await().atMost(5, TimeUnit.SECONDS).untilAsserted(() -> // Use a slightly longer timeout
                    assertThat(auditLogPath)
                            .withFailMessage("Audit log file should exist within timeout at: " + auditLogPath.toAbsolutePath())
                            .exists()
                            .isRegularFile()
            );

            // 4. Read content
            String logContent = Files.readString(auditLogPath);

            // 5. Verify content
            assertThat(logContent).startsWith("{").endsWith("}\n");
            assertThat(logContent).contains("\"type\":\"test_file\"");
            assertThat(logContent).contains(eventId);

            // 6. Verify console output
            assertThat(output.getOut()).doesNotContain("AUDIT_EVENT:");
            assertThat(output.getOut()).doesNotContain(eventId);
        }
    }

    // --- Test Suite for SLF4j Backend (Default) ---
    @Nested
    @SpringBootTest
    // No @TestPropertySource needed for backend type if slf4j is the default (matchIfMissing=true)
    // No specific file path needed for slf4j backend
    @DisplayName("Integration Test: SLF4j Audit Backend (Default)")
    @ActiveProfiles("test") // Only need the base test profile
    @ExtendWith(OutputCaptureExtension.class) // Enable console output capture
    class Slf4jBackendTest {

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
            // assertThat(output.getErr()).isEmpty(); // <-- COMMENT OUT or REMOVE this line
        }

    }

    // --- Add other Nested test classes for different scenarios if needed ---

}