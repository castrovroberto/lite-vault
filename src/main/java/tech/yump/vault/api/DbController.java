package tech.yump.vault.api;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping; // Added
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.dto.DbCredentialsResponse;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.auth.StaticTokenAuthFilter;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.LeaseNotFoundException; // Added
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.db.PostgresSecretsEngine;

import java.time.Instant;
import java.util.HashMap; // Keep HashMap for mutable map in logAuditEvent
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/v1/db") // Base path for database secrets endpoints
@RequiredArgsConstructor
@Slf4j
public class DbController {

    private final PostgresSecretsEngine postgresSecretsEngine;
    private final AuditBackend auditBackend;
    private final HttpServletRequest request;

    /**
     * Generates dynamic credentials for a specified PostgreSQL role.
     */
    @GetMapping("/creds/{roleName}")
    public ResponseEntity<DbCredentialsResponse> generateDbCredentials(@PathVariable String roleName) {
        log.info("Received request for DB credentials for role: {}", roleName);
        UUID generatedLeaseId = null; // Keep track for potential error logging
        try {
            // Get authenticated principal from SecurityContext
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String authenticatedPrincipal = authentication != null ? authentication.getName() : "anonymous"; // Handle null auth

            // Get request ID from attribute set by filter
            String requestId = (String) request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR);

            log.debug("Generating credentials for role '{}' by principal '{}' with request ID '{}'",
                    roleName, authenticatedPrincipal, requestId);

            Lease lease = postgresSecretsEngine.generateCredentials(roleName);
            generatedLeaseId = lease.id(); // Assign lease ID

            log.info("Successfully generated credentials for role '{}', lease ID: {}", roleName, lease.id());

            // --- Audit Log for Success ---
            logAuditEvent(
                    "db_operation",
                    "generate_credentials",
                    "success",
                    HttpStatus.OK.value(),
                    null, // No error message on success
                    roleName,
                    lease.id()
            );

            // --- Mapping Logic ---
            Map<String, Object> secretData = lease.secretData();
            String username = (String) secretData.get("username");
            String password = (String) secretData.get("password");

            if (username == null || password == null) {
                log.error("Generated lease for role '{}' is missing username or password in secretData.", roleName);
                // Log audit failure before throwing
                logAuditEvent(
                        "db_operation",
                        "generate_credentials",
                        "failure",
                        HttpStatus.INTERNAL_SERVER_ERROR.value(),
                        "Internal error: Generated credentials incomplete.",
                        roleName,
                        generatedLeaseId // Log the lease ID if available
                );
                throw new SecretsEngineException("Internal error: Generated credentials incomplete.");
            }

            DbCredentialsResponse response = new DbCredentialsResponse(
                    lease.id(),
                    username,
                    password,
                    lease.ttl().toSeconds() // Convert Duration to seconds
            );
            // --- End Mapping Logic ---

            return ResponseEntity.ok(response);

        } catch (RoleNotFoundException e) {
            log.warn("Credential generation failed: Role '{}' not found.", roleName);
            // Audit logging handled by exception handler
            throw e;
        } catch (VaultSealedException e) {
            log.error("Credential generation failed: Vault is sealed.");
            // Audit logging handled by exception handler
            throw e;
        } catch (SecretsEngineException e) {
            log.error("Credential generation failed for role '{}': {}", roleName, e.getMessage(), e);
            // Audit logging handled by exception handler (if not already logged above)
            throw e;
        } catch (Exception e) { // Catch unexpected errors like ClassCastException from mapping
            log.error("An unexpected error occurred generating credentials for role '{}': {}", roleName, e.getMessage(), e);
            // Audit logging handled by exception handler
            throw e;
        }
    }

    // --- START: Temporary Revocation Endpoint for Testing (Task 30) ---
    // TODO: Remove or replace this endpoint with a proper lease management API later.
    /**
     * TEMPORARY endpoint for testing lease revocation.
     * Requires authentication and authorization (e.g., DELETE capability on db/leases/{leaseId}).
     *
     * @param leaseId The UUID of the lease to revoke.
     * @return ResponseEntity indicating success (204 No Content) or failure.
     */
    @DeleteMapping("/leases/{leaseId}")
    public ResponseEntity<Void> revokeDbLease(@PathVariable UUID leaseId) {
        log.info("Received request to revoke DB lease: {}", leaseId);
        try {
            postgresSecretsEngine.revokeLease(leaseId);
            log.info("Successfully revoked DB lease: {}", leaseId);

            // --- Audit Log for Success ---
            logAuditEvent( // Use the same helper as generate
                    "db_operation",
                    "revoke_lease", // Different action
                    "success",
                    HttpStatus.NO_CONTENT.value(),
                    null, // No error message
                    null, // No role name directly associated with revoke request path
                    leaseId // Include lease ID
            );
            return ResponseEntity.noContent().build();
        } catch (LeaseNotFoundException e) {
            log.warn("Lease revocation failed: Lease '{}' not found.", leaseId);
            // Audit logging handled by exception handler
            throw e; // Let handler deal with it
        } catch (VaultSealedException e) { // Added VaultSealedException handling
            log.error("Lease revocation failed for lease '{}': Vault is sealed.", leaseId);
            // Audit logging handled by exception handler
            throw e;
        } catch (SecretsEngineException e) {
            log.error("Lease revocation failed for lease '{}': {}", leaseId, e.getMessage(), e);
            // Audit logging handled by exception handler
            throw e; // Let handler deal with it
        } catch (Exception e) { // Catch unexpected errors
            log.error("An unexpected error occurred revoking lease '{}': {}", leaseId, e.getMessage(), e);
            // Audit logging handled by exception handler
            throw e;
        }
    }
    // --- END: Temporary Revocation Endpoint ---


    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleRoleNotFound(RoleNotFoundException ex) {
        String roleName = extractRoleNameFromPath(request.getRequestURI());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setTitle("Role Not Found");
        // --- Audit Log for Failure ---
        logAuditEvent(
                "db_operation",
                "generate_credentials", // This handler is specific to generate path structure
                "failure",
                HttpStatus.NOT_FOUND.value(),
                ex.getMessage(),
                roleName,
                null // No lease ID generated
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problemDetail);
    }

    // Add handler for LeaseNotFoundException (for the revoke endpoint)
    @ExceptionHandler(LeaseNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleLeaseNotFound(LeaseNotFoundException ex) {
        UUID leaseId = extractLeaseIdFromPath(request.getRequestURI()); // Helper needed
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setTitle("Lease Not Found");
        // --- Audit Log for Failure ---
        logAuditEvent(
                "db_operation",
                "revoke_lease", // This handler is specific to revoke path structure
                "failure",
                HttpStatus.NOT_FOUND.value(),
                ex.getMessage(),
                null, // No role name in revoke path
                leaseId // Include the lease ID that was not found
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problemDetail);
    }

    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ProblemDetail> handleVaultSealed(VaultSealedException ex) {
        // Determine context based on path
        String roleName = extractRoleNameFromPath(request.getRequestURI());
        UUID leaseId = extractLeaseIdFromPath(request.getRequestURI());
        String action = determineActionFromPath(request.getRequestURI());

        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, ex.getMessage());
        problemDetail.setTitle("Vault Sealed");
        // --- Audit Log for Failure ---
        logAuditEvent(
                "db_operation",
                action, // Use determined action
                "failure",
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                ex.getMessage(),
                roleName, // Will be null if it was a revoke request
                leaseId   // Will be null if it was a generate request
        );
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problemDetail);
    }

    @ExceptionHandler(SecretsEngineException.class)
    public ResponseEntity<ProblemDetail> handleSecretsEngineException(SecretsEngineException ex) {
        // Determine context based on path
        String roleName = extractRoleNameFromPath(request.getRequestURI());
        UUID leaseId = extractLeaseIdFromPath(request.getRequestURI());
        String action = determineActionFromPath(request.getRequestURI());

        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        problemDetail.setTitle("Secrets Engine Error");
        // --- Audit Log for Failure ---
        logAuditEvent(
                "db_operation",
                action,
                "failure", // Or "error"? Let's stick with failure.
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                ex.getMessage(),
                roleName,
                leaseId
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGenericException(Exception ex) {
        // Determine context based on path
        String roleName = extractRoleNameFromPath(request.getRequestURI());
        UUID leaseId = extractLeaseIdFromPath(request.getRequestURI());
        String action = determineActionFromPath(request.getRequestURI());

        log.error("An unexpected error occurred processing DB request for action '{}': {}", action, ex.getMessage(), ex);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected internal error occurred.");
        problemDetail.setTitle("Internal Server Error");
        // --- Audit Log for Failure ---
        logAuditEvent(
                "db_operation", // Or "system_error"
                action,
                "failure",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "An unexpected internal error occurred.", // Generic message for audit
                roleName,
                leaseId
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }

    /**
     * Helper method to log audit events.
     * (Modified to use AuditEvent.Builder and include more details)
     */
    private void logAuditEvent(String type, String action, String outcome, int statusCode, String error, String roleName, UUID leaseId) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            AuditEvent.AuthInfo.AuthInfoBuilder authInfoBuilder = AuditEvent.AuthInfo.builder()
                    .sourceAddress(request.getRemoteAddr());

            if (authentication != null && authentication.isAuthenticated()) {
                authInfoBuilder.principal(authentication.getName());
                List<String> policyNames = authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(a -> a.startsWith("POLICY_"))
                        .map(a -> a.substring("POLICY_".length()))
                        .toList();
                if (!policyNames.isEmpty()) {
                    authInfoBuilder.metadata(Map.of("policies", policyNames));
                }
            } else {
                authInfoBuilder.principal("anonymous"); // Or unknown
            }

            AuditEvent.RequestInfo requestInfo = AuditEvent.RequestInfo.builder()
                    .requestId((String) request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR))
                    .httpMethod(request.getMethod())
                    .path(request.getRequestURI())
                    .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
                    .build();

            AuditEvent.ResponseInfo responseInfo = AuditEvent.ResponseInfo.builder()
                    .statusCode(statusCode)
                    .errorMessage(error) // Will be null on success
                    .build();

            // Use a mutable map for data to handle optional fields cleanly
            Map<String, Object> data = new HashMap<>();
            Optional.ofNullable(roleName).ifPresent(rn -> data.put("role_name", rn));
            Optional.ofNullable(leaseId).ifPresent(lid -> data.put("lease_id", lid.toString()));
            // DO NOT INCLUDE GENERATED PASSWORD

            AuditEvent auditEvent = AuditEvent.builder()
                    .timestamp(Instant.now())
                    .type(type)
                    .action(action)
                    .outcome(outcome)
                    .authInfo(authInfoBuilder.build())
                    .requestInfo(requestInfo)
                    .responseInfo(responseInfo)
                    .data(data.isEmpty() ? null : data) // Set data only if not empty, or use JsonInclude.Include.NON_EMPTY
                    .build();

            auditBackend.logEvent(auditEvent);
        } catch (Exception e) {
            log.error("Failed to log audit event in DbController: {}", e.getMessage(), e);
        }
    }

    // --- Helper to extract roleName from path for exception handlers ---
    private String extractRoleNameFromPath(String uri) {
        // Ensure context path is handled correctly if deployed under one
        String prefix = request.getContextPath() + "/v1/db/creds/";
        if (uri != null && uri.startsWith(prefix)) {
            String potentialRoleName = uri.substring(prefix.length());
            // Avoid matching if there are further path segments (e.g., /v1/db/creds/role/subpath)
            if (!potentialRoleName.contains("/")) {
                return potentialRoleName;
            }
        }
        return null; // Not a creds path or has extra segments
    }

    // --- Helper to extract leaseId from path for exception handlers ---
    private UUID extractLeaseIdFromPath(String uri) {
        String prefix = request.getContextPath() + "/v1/db/leases/";
        if (uri != null && uri.startsWith(prefix)) {
            String uuidStr = uri.substring(prefix.length());
            // Avoid matching if there are further path segments
            if (!uuidStr.contains("/")) {
                try {
                    return UUID.fromString(uuidStr);
                } catch (IllegalArgumentException e) {
                    log.warn("Could not parse UUID from lease revocation path segment: {}", uuidStr);
                    return null;
                }
            }
        }
        return null; // Not a leases path or has extra segments or invalid UUID format
    }

    // --- Helper to determine action based on path for audit logging in exceptions ---
    private String determineActionFromPath(String uri) {
        // Use the more specific helpers first
        if (extractLeaseIdFromPath(uri) != null) return "revoke_lease";
        if (extractRoleNameFromPath(uri) != null) return "generate_credentials";
        // Fallback based on less specific matching if needed
        if (uri != null && uri.contains("/v1/db/leases/")) return "revoke_lease";
        if (uri != null && uri.contains("/v1/db/creds/")) return "generate_credentials";
        return "unknown_db_operation";
    }
}