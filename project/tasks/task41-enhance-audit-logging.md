# Task 41: Enhance Audit Logging Backend - Step-by-Step Plan

## Goal

Implement a file-based audit backend and make the active backend configurable.

## Prerequisites

* A working Spring Boot application structure.
* The existing `AuditBackend`, `AuditEvent`, `AuditHelper`, and `LogAuditBackend` classes.
* A mechanism for application properties (e.g., `application.properties`, `application.yml`, `MssmProperties` class).
* Logback (default Spring Boot logging) is available.

## Steps

### 1. Define Configuration Properties

* **Action:** Add new properties to configure the audit backend.
* **Details:**
    * Define a property to select the audit backend type (e.g., `mssm.audit.backend=slf4j` or `mssm.audit.backend=file`). An enum or simple string value is suitable.
    * Define a property for the audit file path when the file backend is selected (e.g., `mssm.audit.file.path=/var/log/mssm/audit.log`).
* **Implementation:** Update your `MssmProperties` class or add these to your `application.yml`/`application.properties`.

### 2. Implement `FileAuditBackend` Class

* **Action:** Create a new class `FileAuditBackend` that implements the `AuditBackend` interface.
* **Details:**
    * This class will need access to the configured audit file path. Inject the configuration property.
    * It will need an `ObjectMapper` (like `LogAuditBackend`) to serialize the `AuditEvent` to a JSON string. Inject `ObjectMapper`.
    * Crucially, instead of writing directly to a file stream (which complicates rotation), leverage Logback. Configure a specific Logback logger instance to write only to the designated audit file. The `FileAuditBackend` will obtain this specific logger.
    * The `logEvent(AuditEvent event)` method will serialize the `AuditEvent` to JSON and then log the JSON string using the dedicated Logback logger instance.
    * Handle potential `JsonProcessingException` during serialization.
* **Implementation:** Create `tech.yump.vault.audit.FileAuditBackend.java`.

### 3. Configure Logback for File Auditing

* **Action:** Configure Logback to create a dedicated appender and logger for the audit file.
* **Details:**
    * Create or modify `logback-spring.xml` (or `logback.xml`).
    * Define a `RollingFileAppender` targeting the file path specified by the `mssm.audit.file.path` property (Logback can read Spring properties).
    * Configure the rolling policy (e.g., based on size or time) and history for the appender.
    * Define a specific `<logger>` element (e.g., with name `tech.yump.vault.audit.FILE_AUDIT`) and attach only the audit file appender to it. Set its level appropriately (e.g., `INFO`).
    * Ensure this specific logger does not propagate events to the root logger (set `additivity="false"`).
    * In `FileAuditBackend`, obtain this logger using `LoggerFactory.getLogger("tech.yump.vault.audit.FILE_AUDIT")`.
* **Implementation:** Create/update `src/main/resources/logback-spring.xml`.

### 4. Make AuditBackend Bean Configurable

* **Action:** Create a Spring `@Configuration` class to conditionally provide the correct `AuditBackend` bean based on the `mssm.audit.backend` property.
* **Details:**
    * Use `@ConditionalOnProperty` or similar Spring mechanisms.
    * Define a `@Bean` method that returns `AuditBackend`.
    * Inside the method, read the `mssm.audit.backend` property.
    * If the value is `"slf4j"`, return an instance of `LogAuditBackend`.
    * If the value is `"file"`, return an instance of `FileAuditBackend` (injecting the file path property and `ObjectMapper`).
    * Handle invalid property values (e.g., default to SLF4j or throw an exception).
    * Remove the `@Service` annotation from `LogAuditBackend` and `FileAuditBackend` (once created) so that the configuration class is the single source of truth for the `AuditBackend` bean.
* **Implementation:** Create a new configuration class, e.g., `tech.yump.vault.config.AuditConfiguration.java`.

### 5. Verify `AuditHelper` Usage

* **Action:** Ensure `AuditHelper` correctly uses the injected `AuditBackend`.
* **Details:** `AuditHelper` is already designed to depend on the `AuditBackend` interface. As long as the Spring context provides exactly one bean implementing `AuditBackend` (which Step 4 ensures), `AuditHelper` should work without modification.
* **Implementation:** Review `AuditHelper.java` to confirm it uses `@Autowired` or constructor injection for `AuditBackend`.

### 6. Add Unit and Integration Tests

* **Action:** Write tests for the new functionality.
* **Details:**
    * **Unit Tests:** Test `FileAuditBackend`'s `logEvent` method (potentially mocking the logger it uses) to ensure it serializes correctly and calls the logger.
    * **Integration Tests:**
        * Write tests that start the application with `mssm.audit.backend=slf4j` and verify audit logs appear in standard output.
        * Write tests that start the application with `mssm.audit.backend=file` and verify audit logs appear in the configured audit file (and not standard output for the audit events themselves).
        * Test log rotation configuration by generating enough logs to trigger it (might be complex, focus on basic file writing first).
* **Implementation:** Create new test classes (e.g., `FileAuditBackendTest`, `AuditConfigurationIntegrationTest`).

### 7. Update Documentation

* **Action:** Document the new audit configuration options.
* **Details:** Explain the `mssm.audit.backend` and `mssm.audit.file.path` properties and how to configure Logback for file rotation.
* **Implementation:** Update the relevant documentation file (likely part of Task 47).

### 8. Code Review and Cleanup

* **Action:** Review the implemented code for correctness, style, and potential issues.
* **Details:** Ensure proper error handling, resource management (though Logback handles file streams), and adherence to coding standards. Remove any temporary code or comments.

---

By following these steps, you will successfully implement Task 41, providing a configurable and file-based audit logging option with proper rotation handled by the logging framework.