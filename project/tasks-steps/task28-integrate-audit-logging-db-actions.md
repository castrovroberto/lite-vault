# Task 28: Integrate Audit Logging for DB Actions

Okay, let's tackle Task 28: Integrate Audit Logging for DB Actions.The goal is to log important events related to dynamic credential generation and revocation using the existing AuditBackend infrastructure. We need to inject AuditBackend into the relevant components and add logging calls at appropriate points.Here's a step-by-step guide:Phase 3: Task 28 - Integrate Audit Logging for DB Actions1. Inject Dependencies:•DbController.java: Needs AuditBackend and HttpServletRequest to log request-level events with user and request context.•PostgresSecretsEngine.java: Needs AuditBackend to log internal engine actions like lease creation and revocation outcomes.

// src/main/java/tech/yump/vault/api/DbController.java
package tech.yump.vault.api;

+import jakarta.servlet.http.HttpServletRequest; // Added
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
+import org.springframework.security.core.Authentication; // Added
+import org.springframework.security.core.GrantedAuthority; // Added
+import org.springframework.security.core.context.SecurityContextHolder; // Added
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.dto.DbCredentialsResponse;
+import tech.yump.vault.audit.AuditBackend; // Added
+import tech.yump.vault.audit.AuditEvent; // Added
+import tech.yump.vault.auth.StaticTokenAuthFilter; // Added for REQUEST_ID_ATTR
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.db.PostgresSecretsEngine; // Import the engine

+import java.time.Instant; // Added
import java.util.Map;
+import java.util.List; // Added
+import java.util.Optional; // Added
+import java.util.UUID; // Added

@RestController
@RequestMapping("/v1/db") // Base path for database secrets endpoints
@RequiredArgsConstructor
@Slf4j
public class DbController {

    private final PostgresSecretsEngine postgresSecretsEngine;
+   private final AuditBackend auditBackend; // Added
+   private final HttpServletRequest request; // Added

    /**
     * Generates dynamic credentials for a specified PostgreSQL role.
     * Requires authentication and authorization (READ capability on db/creds/{roleName}).
     *
     * @param roleName The name of the configured PostgreSQL role definition.
     * @return ResponseEntity containing the generated credentials and lease info.
     */
    @GetMapping("/creds/{roleName}")
    public ResponseEntity<DbCredentialsResponse> generateDbCredentials(@PathVariable String roleName) {
        log.info("Received request to generate credentials for DB role: {}", roleName);
+       UUID generatedLeaseId = null; // To store lease ID for audit log

        try {
            // Call the engine (Task 25 implementation is now present)
            Lease generatedLease = postgresSecretsEngine.generateCredentials(roleName);
+           generatedLeaseId = generatedLease.id(); // Capture lease ID on success

            // --- Mapping Logic ---
            Map<String, Object> secretData = generatedLease.secretData();
            String username = (String) secretData.get("username"); // Assumes Task 25 puts "username"
            String password = (String) secretData.get("password"); // Assumes Task 25 puts "password"

            if (username == null || password == null) {
                log.error("Generated lease for role '{}' is missing username or password in secretData.", roleName);
                throw new SecretsEngineException("Internal error: Generated credentials incomplete.");
            }

            DbCredentialsResponse response = new DbCredentialsResponse(
                    generatedLease.id(),
                    username,
-                   password,
+                   password, // IMPORTANT: Password is in the response, but MUST NOT be in the audit log
                    generatedLease.ttl().toSeconds() // Convert Duration to seconds
            );
            // --- End Mapping Logic ---

            log.info("Successfully generated credentials for DB role: {}", roleName);

+           // --- Audit Log for Success ---
+           logAuditEvent(
+                   "db_operation",
+                   "generate_credentials",
+                   "success",
+                   HttpStatus.OK.value(),
+                   null, // No error message
+                   roleName,
+                   generatedLeaseId // Include lease ID on success
+           );
+
            return ResponseEntity.ok(response);

        } catch (RoleNotFoundException e) {
            log.warn("Credential generation failed: Role '{}' not found.", roleName);
            // Let the exception handler (Step 4) handle this
            throw e;
        } catch (SecretsEngineException e) {
            log.error("Credential generation failed for role '{}': {}", roleName, e.getMessage(), e);
            // Let the exception handler (Step 4) handle this
            throw e;
        } catch (ClassCastException | NullPointerException e) {
            // Catch potential errors accessing username/password from the Lease's secretData map
            log.error("Internal error processing generated lease data for role '{}': {}", roleName, e.getMessage(), e);
            throw new SecretsEngineException("Internal error: Failed to process generated credentials.", e);
        }
    }


    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleRoleNotFound(RoleNotFoundException ex) {
+       String roleName = extractRoleNameFromPath(request.getRequestURI()); // Helper needed
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setTitle("Role Not Found");
+       // --- Audit Log for Failure ---
+       logAuditEvent(
+               "db_operation",
+               "generate_credentials",
+               "failure",
+               HttpStatus.NOT_FOUND.value(),
+               ex.getMessage(),
+               roleName,
+               null // No lease ID generated
+       );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problemDetail);
    }

    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ProblemDetail> handleVaultSealed(VaultSealedException ex) {
+       String roleName = extractRoleNameFromPath(request.getRequestURI());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, ex.getMessage());
        problemDetail.setTitle("Vault Sealed");
+       // --- Audit Log for Failure ---
+       logAuditEvent(
+               "db_operation",
+               "generate_credentials",
+               "failure",
+               HttpStatus.SERVICE_UNAVAILABLE.value(),
+               ex.getMessage(),
+               roleName,
+               null
+       );
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problemDetail);
    }

    @ExceptionHandler(SecretsEngineException.class)
    public ResponseEntity<ProblemDetail> handleSecretsEngineException(SecretsEngineException ex) {
+       String roleName = extractRoleNameFromPath(request.getRequestURI());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        problemDetail.setTitle("Secrets Engine Error");
+       // --- Audit Log for Failure ---
+       logAuditEvent(
+               "db_operation",
+               "generate_credentials",
+               "failure",
+               HttpStatus.INTERNAL_SERVER_ERROR.value(),
+               ex.getMessage(),
+               roleName,
+               null
+       );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }

    // Optional: Add a handler for general exceptions if needed
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGenericException(Exception ex) {
+       String roleName = extractRoleNameFromPath(request.getRequestURI());
        log.error("An unexpected error occurred processing DB credential request: {}", ex.getMessage(), ex);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected internal error occurred.");
        problemDetail.setTitle("Internal Server Error");
+       // --- Audit Log for Failure ---
+       logAuditEvent(
+               "db_operation",
+               "generate_credentials",
+               "failure",
+               HttpStatus.INTERNAL_SERVER_ERROR.value(),
+               "An unexpected internal error occurred.", // Generic message for audit
+               roleName,
+               null
+       );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }

+   // --- Helper method to build and log AuditEvent (similar to KVController) ---
+   private void logAuditEvent(String type, String action, String outcome, int statusCode, String errorMessage, String roleName, UUID leaseId) {
+       try {
+           Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
+
+           AuditEvent.AuthInfo.AuthInfoBuilder authInfoBuilder = AuditEvent.AuthInfo.builder()
+                   .sourceAddress(request.getRemoteAddr());
+
+           if (authentication != null && authentication.isAuthenticated()) {
+               authInfoBuilder.principal(authentication.getName());
+               List<String> policyNames = authentication.getAuthorities().stream()
+                       .map(GrantedAuthority::getAuthority)
+                       .filter(a -> a.startsWith("POLICY_"))
+                       .map(a -> a.substring("POLICY_".length()))
+                       .toList();
+               if (!policyNames.isEmpty()) {
+                   authInfoBuilder.metadata(Map.of("policies", policyNames));
+               }
+           } else {
+               authInfoBuilder.principal("unknown");
+           }
+
+           AuditEvent.RequestInfo requestInfo = AuditEvent.RequestInfo.builder()
+                   .requestId((String) request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR))
+                   .httpMethod(request.getMethod())
+                   .path(request.getRequestURI())
+                   .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
+                   .build();
+
+           AuditEvent.ResponseInfo responseInfo = AuditEvent.ResponseInfo.builder()
+                   .statusCode(statusCode)
+                   .errorMessage(errorMessage) // Will be null for success cases
+                   .build();
+
+           // Add DB specific data
+           Map<String, Object> data = new java.util.HashMap<>();
+           data.put("requested_role", Optional.ofNullable(roleName).orElse("N/A"));
+           if (leaseId != null) {
+               data.put("lease_id", leaseId.toString());
+           }
+           // IMPORTANT: DO NOT ADD PASSWORD HERE
+
+           AuditEvent event = AuditEvent.builder()
+                   .timestamp(Instant.now())
+                   .type(type)
+                   .action(action)
+                   .outcome(outcome)
+                   .authInfo(authInfoBuilder.build())
+                   .requestInfo(requestInfo)
+                   .responseInfo(responseInfo)
+                   .data(data)
+                   .build();
+
+           auditBackend.logEvent(event);
+
+       } catch (Exception e) {
+           // Avoid letting audit failures break the main request flow
+           log.error("Failed to log audit event in DbController: {}", e.getMessage(), e);
+       }
+   }
+
+   // --- Helper to extract roleName from path for exception handlers ---
+   private String extractRoleNameFromPath(String uri) {
+       String prefix = request.getContextPath() + "/v1/db/creds/";
+       if (uri != null && uri.startsWith(prefix)) {
+           return uri.substring(prefix.length());
+       }
+       return null; // Or return "unknown"
+   }
}

// src/main/java/tech/yump/vault/secrets/db/PostgresSecretsEngine.java
package tech.yump.vault.secrets.db;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
+import org.springframework.security.core.Authentication; // Added
+import org.springframework.security.core.context.SecurityContextHolder; // Added
import org.springframework.stereotype.Service;
+import tech.yump.vault.audit.AuditBackend; // Added
+import tech.yump.vault.audit.AuditEvent; // Added
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.secrets.DynamicSecretsEngine;
import tech.yump.vault.secrets.Lease;
@@ -34,6 +37,7 @@
     private final MssmProperties properties;
     private final DataSource dataSource; // Spring Boot auto-configures this
     private final JdbcTemplate jdbcTemplate; // Spring Boot auto-configures this based on primary DataSource
+   private final AuditBackend auditBackend; // Added

    // Connection pool is managed by the injected DataSource (HikariCP by default)
    // TODO: Cache role definitions loaded from properties (Task 23) for performance?
@@ -203,6 +207,18 @@
         // 6. Store lease details in the in-memory map (Task 26)
         activeLeases.put(lease.id(), lease);
         log.debug("Lease {} added to active lease tracker. Current active leases: {}", lease.id(), activeLeases.size());
+
+       // --- Audit Log for Lease Creation (Internal Engine Success) ---
+       // Note: This logs the internal creation event, separate from the controller's request log.
+       logAuditEvent(
+               "db_operation",
+               "lease_creation", // Different action
+               "success",
+               Map.of(
+                       "lease_id", lease.id().toString(),
+                       "role_name", lease.roleName()
+               )
+       );
         // --- END: Modification for Task 26 Step 2 ---

         log.info("Successfully generated credentials and lease for DB role: {}", roleName);
@@ -258,11 +274,30 @@
             // 5. Remove lease from in-memory map AFTER successful revocation (Task 26)
             activeLeases.remove(leaseId);
             log.info("Successfully revoked and removed lease: {}. Remaining active leases: {}", leaseId, activeLeases.size());
+
+           // --- Audit Log for Revocation Success ---
+           logAuditEvent(
+                   "db_operation",
+                   "revoke_lease",
+                   "success",
+                   Map.of("lease_id", leaseId.toString())
+           );
 
         } catch (DataAccessException e) {
             log.error("Database error executing revocation SQL for lease '{}', username '{}': {}",
                     leaseId, username, e.getMessage(), e);
             // If revocation fails, DO NOT remove the lease from the map.
             // The credential might still exist in the DB.
+
+           // --- Audit Log for Revocation Failure ---
+           logAuditEvent(
+                   "db_operation",
+                   "revoke_lease",
+                   "failure",
+                   Map.of(
+                           "lease_id", leaseId.toString(),
+                           "error", e.getMessage()
+                   )
+           );
             throw new SecretsEngineException("Failed to execute credential revocation SQL for lease: " + leaseId, e);
         }
     }
@@ -270,4 +305,38 @@
 
 }
 

2. Add Audit Logging Logic:•DbController.generateDbCredentials:•Inside the try block, after successfully generating the lease and response DTO, call a new private helper method logAuditEvent with outcome="success", statusCode=200, roleName, and the generatedLeaseId.•DbController Exception Handlers:•In each @ExceptionHandler method (handleRoleNotFound, handleVaultSealed, handleSecretsEngineException, handleGenericException), before returning the ResponseEntity, call the logAuditEvent helper method.•Pass outcome="failure", the appropriate statusCode, the exception message (ex.getMessage() or a generic one), and the roleName (extracted from the request path). Pass null for the lease ID as it wasn't successfully generated.•DbController Helper Method (logAuditEvent):•Create a private method similar to the one in KVController.•It should accept parameters like type, action, outcome, statusCode, errorMessage, roleName, leaseId.•Inside the helper:•Get Authentication from SecurityContextHolder.•Build AuthInfo (principal, source IP from request, policies from authorities).•Build RequestInfo (request ID from request attribute, method, path, headers).•Build ResponseInfo (status code, error message).•Build the data map: include requested_role and lease_id (if not null). Crucially, DO NOT include the password.•Build the AuditEvent object.•Call auditBackend.logEvent(event).•Wrap the logging call in a try-catch(Exception) to prevent audit failures from breaking the main flow.•PostgresSecretsEngine.generateCredentials:•After successfully executing creation SQL and storing the lease in activeLeases, call a new private helper method logAuditEvent (within the engine) for the lease_creation action.•Pass type="db_operation", action="lease_creation", outcome="success", and a data map containing lease_id and role_name.

•PostgresSecretsEngine.revokeLease:•Inside the try block, after successfully executing revocation SQL and removing the lease, call the engine's logAuditEvent helper for revoke_lease success. Include lease_id in the data.•Inside the catch (DataAccessException e) block, call the engine's logAuditEvent helper for revoke_lease failure. Include lease_id and the error message (e.getMessage()) in the data.•PostgresSecretsEngine Helper Method (logAuditEvent):•Create a simple private helper method within the engine.•It should accept type, action, outcome, and data.•Inside the helper:•Build a minimal AuditEvent. Since this is an internal engine event, RequestInfo and full AuthInfo/ResponseInfo might not be directly available or necessary. You could retrieve the principal from SecurityContextHolder if needed, but focus on the core action data.•Call auditBackend.logEvent(event).•Wrap in try-catch(Exception).3. Update CHANGELOG.md:Add an entry under [Unreleased] -> Added describing the implementation of audit logging for DB credential generation and revocation (Task 28). Mention the specific events logged (generation request success/failure, lease creation, revocation attempt success/failure) and that passwords are not logged.

### Added
+ **Audit Logging for DB Actions (Task 28):**
+   Injected `AuditBackend` into `DbController` and `PostgresSecretsEngine`.
+   Added audit logging within `DbController` for `GET /v1/db/creds/{roleName}` requests:
+     - Logs "success" events including authenticated principal, source IP, request ID, requested role, and generated lease ID.
+     - Logs "failure" events in exception handlers (404, 500, 503) including principal, source IP, request ID, requested role, and error message.
+   Added audit logging within `PostgresSecretsEngine`:
+     - Logs internal "success" event upon successful lease creation (`lease_creation` action) including lease ID and role name.
+     - Logs internal "success" or "failure" events for lease revocation attempts (`revoke_lease` action) including lease ID and error message on failure.
+   Ensured generated passwords are **not** included in any audit logs.
+   Fulfills requirement F-CORE-130 for dynamic secrets.

4. Update README.md:Update the "Auditing" section under "Security Considerations" to mention that dynamic database credential generation and revocation events are now also audited.

 - **Auditing:** **Implemented (F-CORE-130):** Audit events are now logged for authentication attempts, authorization decisions, and KV operations via the `LogAuditBackend` (Task 16, Task 17). Events are structured JSON including timestamp, principal, source IP, request details, outcome, and relevant metadata. Sensitive data (e.g., secret values) is excluded.
+  - **(Task 28):** Audit logging now also covers dynamic PostgreSQL credential operations:
+    - Credential generation requests (`GET /v1/db/creds/{roleName}`) log success (with lease ID, role) or failure (with role, error).
+    - Internal lease creation events are logged by the engine upon success.
+    - Lease revocation attempts (internal engine logic) log success or failure (with lease ID, error).
+    - Generated passwords are **never** logged.

Next Steps:1.Apply the code changes shown above.2.Run the application.3.Test the GET /v1/db/creds/{role_name} endpoint with valid and invalid roles, and with valid/invalid tokens (to test ACLs triggering controller exceptions).4.Check the application logs for the AUDIT_EVENT: JSON entries corresponding to these DB operations. Verify the content, especially ensuring passwords are absent and relevant data (role, lease ID, outcome, error) is present.5.(Optional, requires adding a temporary revocation mechanism/endpoint for testing): Test the revocation logic and verify its audit logs.This completes Task 28, adding crucial auditability to the dynamic secrets feature.