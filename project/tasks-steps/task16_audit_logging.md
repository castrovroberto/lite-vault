# Task 16: Implement Basic Audit Logging Backend

## Overview

This task defines the foundation for audit logging in the LiteVault system. It focuses on establishing the structure of an `AuditEvent`, the interface for audit backends, and a concrete implementation using SLF4j to log events as JSON. The actual triggering of logs will be handled in Task 17.

---

## Step 1: Define the `AuditEvent` Data Structure

Create the package: `tech.yump.vault.audit`

### File: `AuditEvent.java`

```java
package tech.yump.vault.audit;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.time.Instant;
import java.util.Map;

/**
 * Represents a single audit log entry.
 * Contains information about the request, authentication, action, and outcome.
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuditEvent(
        Instant timestamp,
        String type,
        String action,
        String outcome,
        AuthInfo authInfo,
        RequestInfo requestInfo,
        ResponseInfo responseInfo,
        Map<String, Object> data
) {
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record AuthInfo(
            String principal,
            String sourceAddress,
            Map<String, Object> metadata
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RequestInfo(
            String requestId,
            String httpMethod,
            String path,
            Map<String, String> headers
    ) {}

    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ResponseInfo(
            int statusCode,
            String errorMessage
    ) {}
}
```

---

## Step 2: Define the `AuditBackend` Interface

### File: `AuditBackend.java`

```java
package tech.yump.vault.audit;

/**
 * Interface for audit logging backends.
 */
public interface AuditBackend {
    /**
     * Logs a given audit event.
     *
     * @param event The AuditEvent to log.
     */
    void logEvent(AuditEvent event);
}
```

---

## Step 3: Implement the `LogAuditBackend` Class

### File: `LogAuditBackend.java`

```java
package tech.yump.vault.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Logs audit events as JSON strings using SLF4j.
 */
@Service
@Slf4j
public class LogAuditBackend implements AuditBackend {

    private final ObjectMapper objectMapper;

    public LogAuditBackend() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

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
            log.error("Failed to serialize AuditEvent to JSON.", e);
            log.info("AUDIT_EVENT_FALLBACK: {}", event.toString());
        }
    }
}
```

---

## Summary

✅ Defined:
- `AuditEvent` record
- `AuditBackend` interface
- `LogAuditBackend` implementation using SLF4j

📌 Next Step:
Inject `LogAuditBackend` into security filters or controllers to start logging auditable events (Task 17).
