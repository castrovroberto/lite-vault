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
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.db.PostgresSecretsEngine; // Import the engine

import java.time.Instant;
import java.util.HashMap;
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
     * Requires authentication and authorization (READ capability on db/creds/{roleName}).
     *
     * @param roleName The name of the configured PostgreSQL role definition.
     * @return ResponseEntity containing the generated credentials and lease info.
     */
    @GetMapping("/creds/{roleName}")
    public ResponseEntity<DbCredentialsResponse> generateDbCredentials(@PathVariable String roleName) {
        log.info("Received request to generate credentials for DB role: {}", roleName);
        UUID generatedLeaseId = null;
        try {
            Lease generatedLease = postgresSecretsEngine.generateCredentials(roleName);
            generatedLeaseId = generatedLease.id();

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
                    password,
                    generatedLease.ttl().toSeconds() // Convert Duration to seconds
            );
            // --- End Mapping Logic ---

            log.info("Successfully generated credentials for DB role: {}", roleName);

            // --- Audit Log for success
            logAuditEvent(
                    "db_operation",
                    "generate_credentials",
                    "success",
                    HttpStatus.OK.value(),
                    null,
                    roleName,
                    generatedLeaseId
            );

            return ResponseEntity.ok(response);

        } catch (RoleNotFoundException e) {
            log.warn("Credential generation failed: Role '{}' not found.", roleName);
            // Let the exception handler (Step 4) handle this
            throw e;
        } catch (SecretsEngineException e) {
            log.error("Credential generation failed for role '{}': {}", roleName, e.getMessage(), e);
            // Let the exception handler (Step 4) handle this
            throw e;
            // Remove the temporary UnsupportedOperationException handling as Task 25 is done
            // } catch (UnsupportedOperationException e) {
            //     log.error("DB Credential generation for role '{}' is not yet implemented.", roleName);
            //     throw new SecretsEngineException("Feature not implemented yet.", e);
        } catch (ClassCastException | NullPointerException e) {
            // Catch potential errors accessing username/password from the Lease's secretData map
            log.error("Internal error processing generated lease data for role '{}': {}", roleName, e.getMessage(), e);
            throw new SecretsEngineException("Internal error: Failed to process generated credentials.", e);
        }
    }


    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleRoleNotFound(RoleNotFoundException ex) {
        String roleName = extractRoleNameFromPath(request.getRequestURI());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setTitle("Role Not Found");
        logAuditEvent(
                "db_operation",
                "generate_credentials",
                "failure",
                HttpStatus.NOT_FOUND.value(),
                ex.getMessage(),
                roleName,
                null
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problemDetail);
    }

    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ProblemDetail> handleVaultSealed(VaultSealedException ex) {
        String roleName = extractRoleNameFromPath(request.getRequestURI());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, ex.getMessage());
        problemDetail.setTitle("Vault Sealed");
        logAuditEvent(
                "db_operation",
                "generate_credentials",
                "failure",
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                ex.getMessage(),
                roleName,
                null
        );
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problemDetail);
    }

    @ExceptionHandler(SecretsEngineException.class)
    public ResponseEntity<ProblemDetail> handleSecretsEngineException(SecretsEngineException ex) {
        String roleName = extractRoleNameFromPath(request.getRequestURI());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        problemDetail.setTitle("Secrets Engine Error");
        logAuditEvent(
                "db_operation",
                "generate_credentials",
                "failure",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                ex.getMessage(),
                roleName,
                null
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGenericException(Exception ex) {
        log.error("An unexpected error occurred processing DB credential request: {}", ex.getMessage(), ex);
        String roleName = extractRoleNameFromPath(request.getRequestURI());
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected internal error occurred.");
        problemDetail.setTitle("Internal Server Error");
        logAuditEvent(
                "db_operation",
                "generate_credentials",
                "failure",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "An unexpected internal error occurred.",
                roleName,
                null
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }

    private void logAuditEvent(
            String type,
            String action,
            String outcome,
            int statusCode,
            String errorMessage,
            String roleName,
            UUID leaseId) {
        try {
            Authentication authentication = SecurityContextHolder
                    .getContext()
                    .getAuthentication();
            AuditEvent.AuthInfo.AuthInfoBuilder authInfoBuilder = AuditEvent
                    .AuthInfo
                    .builder()
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
                } else {
                    authInfoBuilder.principal("unknown");
                }

                AuditEvent.RequestInfo requestInfo = AuditEvent.RequestInfo.builder()
                        .requestId(request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR).toString())
                        .httpMethod(request.getMethod())
                        .path(request.getRequestURI())
                        .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
                        .build();

                AuditEvent.ResponseInfo responseInfo = AuditEvent.ResponseInfo.builder()
                        .statusCode(statusCode)
                        .errorMessage(errorMessage)
                        .build();

                Map<String, Object> data = new HashMap<>();
                data.put("requested_role", Optional.ofNullable(roleName).orElse("N/A"));
                if (leaseId != null) {
                    data.put("lease_id", leaseId.toString());
                }

                AuditEvent auditEvent = AuditEvent.builder()
                        .timestamp(Instant.now())
                        .type(type)
                        .action(action)
                        .outcome(outcome)
                        .authInfo(authInfoBuilder.build())
                        .requestInfo(requestInfo)
                        .responseInfo(responseInfo)
                        .data(data)
                        .build();

                auditBackend.logEvent(auditEvent);

            }
        } catch (Exception e) {
            log.error("Failed to log audit event in DBController: {}", e.getMessage(), e);
        }
    }

    private String extractRoleNameFromPath(String uri) {
        String prefix = request.getContextPath() + "v1/db/creds/";
        if (uri != null && uri.startsWith(prefix)) {
            return uri.substring(prefix.length());
        } else {
            return null;
        }
    }

}