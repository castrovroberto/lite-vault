package tech.yump.vault.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * Integration tests for AuditConfiguration focusing on the File backend.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "mssm.audit.backend=file",
        "mssm.audit.file.path=target/test-audit/integration-audit.log"
})
@DisplayName("Integration Test: File Audit Backend")
@ActiveProfiles({"test", "audit-file"})
@ExtendWith(OutputCaptureExtension.class)
// @Order(2) // Order is less relevant between separate files unless run in a specific suite
public class FileAuditBackendIntegrationTest {

    @Autowired
    private AuditBackend auditBackend;
    @Autowired
    private AuditHelper auditHelper;

    private static final Path auditLogPath = Paths.get("target/test-audit/integration-audit.log");

    // Static initializer: Ensures directory exists before Spring/Logback start. Runs ONCE per JVM class load.
    static {
        try {
            Path parentDir = auditLogPath.getParent();
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
                System.out.println("Static initializer created directory: " + parentDir);
            } else if (parentDir != null) {
                System.out.println("Static initializer found existing directory: " + parentDir);
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not create/verify test audit directory in static initializer", e);
        }
    }

    @AfterEach
    void cleanupLogFile() throws IOException {
        Files.deleteIfExists(auditLogPath);
        // Optional debug log - updated message slightly
        System.out.println("@BeforeEach deleted file (if it existed): " + auditLogPath);
    }

    @Test
    void shouldUseFileAuditBackendAndLogToFile(CapturedOutput output) throws IOException {
        // 1. Verify bean
        assertThat(auditBackend)
                .withFailMessage("Expected FileAuditBackend bean due to mssm.audit.backend=file property")
                .isInstanceOf(FileAuditBackend.class);

        // 2. Trigger event
        String eventId = UUID.randomUUID().toString();
        auditHelper.logInternalEvent("test_file", "write_log", "success", "tester", java.util.Map.of("id", eventId));

        // 3. Wait for file (Consider keeping a slightly increased timeout, e.g., 10 seconds)
        await().atMost(10, TimeUnit.SECONDS).untilAsserted(() -> // Increased timeout
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
        assertThat(logContent).contains("\"action\":\"write_log\"");
        assertThat(logContent).contains("\"outcome\":\"success\"");
        assertThat(logContent).contains("\"principal\":\"tester\"");
        assertThat(logContent).contains(eventId);

        // 6. Verify console output
        assertThat(output.getOut())
                .withFailMessage("Audit event should not appear in console output when using FileAuditBackend with additivity=false")
                .doesNotContain("AUDIT_EVENT:")
                .doesNotContain(eventId);
    }
}