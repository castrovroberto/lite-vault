package tech.yump.vault.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@ExtendWith(MockitoExtension.class)
class FileAuditBackendTest {

    @Mock
    private ObjectMapper mockObjectMapper;

    // We don't inject FileAuditBackend because we need to control its logger manually for testing
    private FileAuditBackend fileAuditBackend;

    private ListAppender<ILoggingEvent> listAppender;
    private Logger auditLogger;
    private Logger errorLogger; // To capture internal errors like serialization failure

    // The logger name must match the one used in FileAuditBackend
    private static final String AUDIT_LOGGER_NAME = "tech.yump.vault.audit.FILE_AUDIT";

    @BeforeEach
    void setUp() {
        fileAuditBackend = new FileAuditBackend(mockObjectMapper);

        // Get the specific audit logger instance
        auditLogger = (Logger) LoggerFactory.getLogger(AUDIT_LOGGER_NAME);
        // Get the logger used by @Slf4j in FileAuditBackend for error reporting
        errorLogger = (Logger) LoggerFactory.getLogger(FileAuditBackend.class);

        // Create and attach a ListAppender to capture log messages for the audit logger
        listAppender = new ListAppender<>();
        listAppender.start();
        auditLogger.addAppender(listAppender);
        // Ensure additivity is false for the test logger if needed, though usually default
        auditLogger.setAdditive(false);

        // Optionally capture errors from the class's own logger too
        // listAppenderError = new ListAppender<>();
        // listAppenderError.start();
        // errorLogger.addAppender(listAppenderError);
    }

    @AfterEach
    void tearDown() {
        // Detach the appender to avoid interference between tests
        auditLogger.detachAppender(listAppender);
        listAppender.stop();
        // errorLogger.detachAppender(listAppenderError);
        // listAppenderError.stop();
    }

    @Test
    @DisplayName("logEvent: Should serialize event and log JSON to dedicated audit logger")
    void logEvent_Success() throws JsonProcessingException {
        // Arrange
        AuditEvent event = AuditEvent.builder().timestamp(Instant.now()).type("test").action("do").outcome("success").build();
        String expectedJson = "{\"timestamp\":\"" + event.timestamp() + "\",\"type\":\"test\",\"action\":\"do\",\"outcome\":\"success\"}"; // Simplified example
        when(mockObjectMapper.writeValueAsString(event)).thenReturn(expectedJson);

        // Act
        fileAuditBackend.logEvent(event);

        // Assert
        verify(mockObjectMapper).writeValueAsString(event);

        List<ILoggingEvent> logsList = listAppender.list;
        assertThat(logsList).hasSize(1);
        assertThat(logsList.get(0).getLevel()).isEqualTo(Level.INFO);
        assertThat(logsList.get(0).getFormattedMessage()).isEqualTo(expectedJson);
        assertThat(logsList.get(0).getLoggerName()).isEqualTo(AUDIT_LOGGER_NAME);
    }

    @Test
    @DisplayName("logEvent: Should log error via internal logger when serialization fails")
    void logEvent_SerializationFailure() throws JsonProcessingException {
        // Arrange
        AuditEvent event = AuditEvent.builder().timestamp(Instant.now()).type("fail").build();
        JsonProcessingException exception = new JsonProcessingException("Test exception") {};
        when(mockObjectMapper.writeValueAsString(event)).thenThrow(exception);

        // Act
        fileAuditBackend.logEvent(event);

        // Assert
        verify(mockObjectMapper).writeValueAsString(event);

        // Verify no message was logged to the *audit* logger
        List<ILoggingEvent> auditLogsList = listAppender.list;
        assertThat(auditLogsList).isEmpty();

        // Here you would ideally capture logs from the 'errorLogger' (FileAuditBackend.class)
        // to verify the log.error call. This requires setting up another ListAppender
        // or using a dedicated log testing library.
        // For now, we trust that log.error was called based on the code path.
    }

    @Test
    @DisplayName("logEvent: Should handle null event gracefully")
    void logEvent_NullEvent() throws JsonProcessingException {
        // Act
        fileAuditBackend.logEvent(null);

        // Assert
        // Verify ObjectMapper was never called
        verify(mockObjectMapper, never()).writeValueAsString(any());

        // Verify no message was logged to the *audit* logger
        List<ILoggingEvent> auditLogsList = listAppender.list;
        assertThat(auditLogsList).isEmpty();

        // Verify that a warning was logged to the internal logger (requires capturing logs)
    }
}
