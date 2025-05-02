package tech.yump.vault.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith; // Correct import
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension; // Correct import
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.audit.FileAuditBackend;
import tech.yump.vault.audit.LogAuditBackend; // Import LogAuditBackend if testing it elsewhere

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
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
            "mssm.audit.backend=file", // <-- Explicitly set backend for this test
            "mssm.audit.file.path=target/test-audit/integration-audit.log"
    })
    @DisplayName("Integration Test: File Audit Backend")
    @ActiveProfiles({"test", "audit-file"}) // Activate test profile AND the logback profile
    @ExtendWith(OutputCaptureExtension.class) // Enable console output capture
    class FileBackendTest {

        @Autowired
        private AuditBackend auditBackend;
        @Autowired
        private AuditHelper auditHelper;

        private static final Path auditLogPath = Paths.get("target/test-audit/integration-audit.log");

        // --- STATIC INITIALIZER BLOCK ---
        // Runs *before* Spring context initialization for this test class
        static {
            try {
                // Ensure the parent directory exists very early
                Files.createDirectories(auditLogPath.getParent());
                System.out.println("Static initializer created directory: " + auditLogPath.getParent()); // Optional: Add print statement for verification
            } catch (IOException e) {
                // Handle exception appropriately, maybe fail fast
                throw new RuntimeException("Could not create test audit directory in static initializer", e);
            }
        }
        // --- END STATIC INITIALIZER BLOCK ---


        @BeforeEach
        @AfterEach // Clean up log file before and after each test in this class
        void cleanupLogFile() throws IOException {
            // This now only needs to delete the file, directory is guaranteed by static block
            Files.deleteIfExists(auditLogPath);
            // Files.createDirectories(auditLogPath.getParent()); // No longer needed here
        }

        @Test
        void shouldUseFileAuditBackendAndLogToFile(CapturedOutput output) throws IOException {
            // 1. Verify the correct bean was created
            assertThat(auditBackend)
                    .withFailMessage("Expected FileAuditBackend bean due to mssm.audit.backend=file property")
                    .isInstanceOf(FileAuditBackend.class);

            // 2. Trigger an audit event
            String eventId = UUID.randomUUID().toString();
            auditHelper.logInternalEvent("test_file", "write_log", "success", "tester", java.util.Map.of("id", eventId));

            // <<--- Use Awaitility to wait for the file to exist --- >>
            await().atMost(5, TimeUnit.SECONDS).untilAsserted(() ->
                    assertThat(auditLogPath)
                            .withFailMessage("Audit log file should exist within timeout at: " + auditLogPath)
                            .exists()
                            .isRegularFile()
            );

            // 4. Read the log file content (Now safe to proceed as Awaitility passed)
            String logContent = Files.readString(auditLogPath);

            // 5. Verify content is JSON and contains expected fields
            assertThat(logContent).startsWith("{").endsWith("}\n");
            assertThat(logContent).contains("\"type\":\"test_file\"");
            assertThat(logContent).contains("\"action\":\"write_log\"");
            assertThat(logContent).contains("\"outcome\":\"success\"");
            assertThat(logContent).contains("\"principal\":\"tester\"");
            assertThat(logContent).contains(eventId);

            // 6. Verify the event DID NOT go to standard console output
            assertThat(output.getOut())
                    .withFailMessage("Audit event should not appear in console output when using FileAuditBackend with additivity=false")
                    .doesNotContain("AUDIT_EVENT:")
                    .doesNotContain(eventId);
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