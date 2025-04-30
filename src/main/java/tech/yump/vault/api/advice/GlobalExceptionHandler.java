package tech.yump.vault.api.advice;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
// Removed SecurityContextHolder and related imports if only used for audit
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
// Removed AuditBackend and AuditEvent imports
import tech.yump.vault.audit.AuditHelper; // Added
// Removed StaticTokenAuthFilter import if only used for REQUEST_ID_ATTR (now handled by helper)
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.LeaseNotFoundException;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.kv.KVEngineException;

// Removed time, collections, map, optional imports if only used for audit
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestControllerAdvice
@RequiredArgsConstructor
@Slf4j
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    // Inject AuditHelper instead of AuditBackend
    private final AuditHelper auditHelper; // Changed

    // Patterns remain the same
    private static final Pattern DB_CREDS_PATH_PATTERN = Pattern.compile(".*/v1/db/creds/([^/]+)");
    private static final Pattern DB_LEASES_PATH_PATTERN = Pattern.compile(".*/v1/db/leases/([0-9a-fA-F-]+)");
    private static final Pattern KV_PATH_PATTERN = Pattern.compile(".*/v1/kv/data/(.+)");


    // --- Specific Handlers ---

    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ProblemDetail> handleVaultSealed(VaultSealedException ex, HttpServletRequest request) {
        HttpStatus status = HttpStatus.SERVICE_UNAVAILABLE;
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, ex.getMessage());
        problemDetail.setTitle("Vault Sealed");
        log.warn("Operation failed: Vault is sealed. Request: {} {}", request.getMethod(), request.getRequestURI());

        // Use AuditHelper
        auditHelper.logHttpEvent(
                determineEventType(request),
                determineActionFromRequest(request),
                "failure",
                status.value(),
                ex.getMessage(),
                extractContextData(request) // Extract context for audit
        );
        return ResponseEntity.status(status).body(problemDetail);
    }

    @ExceptionHandler({RoleNotFoundException.class, LeaseNotFoundException.class})
    public ResponseEntity<ProblemDetail> handleNotFoundExceptions(SecretsEngineException ex, HttpServletRequest request) {
        HttpStatus status = HttpStatus.NOT_FOUND;
        String title = (ex instanceof RoleNotFoundException) ? "Role Not Found" : "Lease Not Found";
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, ex.getMessage());
        problemDetail.setTitle(title);
        log.warn("{}: {}. Request: {} {}", title, ex.getMessage(), request.getMethod(), request.getRequestURI());

        // Use AuditHelper
        auditHelper.logHttpEvent(
                determineEventType(request),
                determineActionFromRequest(request),
                "failure",
                status.value(),
                ex.getMessage(),
                extractContextData(request) // Extract context for audit
        );
        return ResponseEntity.status(status).body(problemDetail);
    }

    @ExceptionHandler(KVEngineException.class)
    public ResponseEntity<ProblemDetail> handleKVEngineException(KVEngineException ex, HttpServletRequest request) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = "Internal server error processing KV request.";
        String title = "KV Engine Error";

        // Check cause for VaultSealedException
        if (ex.getCause() instanceof VaultSealedException) {
            status = HttpStatus.SERVICE_UNAVAILABLE;
            message = "Vault is sealed.";
            title = "Vault Sealed";
            log.warn("KV operation failed: Vault is sealed. Request: {} {}", request.getMethod(), request.getRequestURI());
        } else {
            log.error("KV Engine error: {}. Request: {} {}", ex.getMessage(), request.getMethod(), request.getRequestURI(), ex);
        }

        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, message);
        problemDetail.setTitle(title);

        // Use AuditHelper
        auditHelper.logHttpEvent(
                "kv_operation",
                determineActionFromRequest(request),
                "failure",
                status.value(),
                message, // Log the user-facing message
                extractContextData(request)
        );
        return ResponseEntity.status(status).body(problemDetail);
    }

    @ExceptionHandler(SecretsEngineException.class) // Catch other SecretsEngineExceptions (like DB errors)
    public ResponseEntity<ProblemDetail> handleSecretsEngineException(SecretsEngineException ex, HttpServletRequest request) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, ex.getMessage());
        problemDetail.setTitle("Secrets Engine Error");
        log.error("Secrets Engine error: {}. Request: {} {}", ex.getMessage(), request.getMethod(), request.getRequestURI(), ex);

        // Use AuditHelper
        auditHelper.logHttpEvent(
                determineEventType(request),
                determineActionFromRequest(request),
                "failure",
                status.value(),
                ex.getMessage(),
                extractContextData(request)
        );
        return ResponseEntity.status(status).body(problemDetail);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleIllegalArgumentException(IllegalArgumentException ex, HttpServletRequest request) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, ex.getMessage());
        problemDetail.setTitle("Bad Request");
        log.warn("Bad request: {}. Request: {} {}", ex.getMessage(), request.getMethod(), request.getRequestURI());

        // Use AuditHelper
        auditHelper.logHttpEvent(
                determineEventType(request), // Or maybe "request_validation"
                determineActionFromRequest(request),
                "failure",
                status.value(),
                ex.getMessage(),
                extractContextData(request)
        );
        return ResponseEntity.status(status).body(problemDetail);
    }

    // --- Fallback Handler ---

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGenericException(Exception ex, HttpServletRequest request) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = "An unexpected internal error occurred.";
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, message);
        problemDetail.setTitle("Internal Server Error");
        log.error("An unexpected error occurred: {}. Request: {} {}", ex.getMessage(), request.getMethod(), request.getRequestURI(), ex);

        // Use AuditHelper
        auditHelper.logHttpEvent(
                "system_error",
                determineActionFromRequest(request),
                "failure",
                status.value(),
                message, // Don't expose internal details
                extractContextData(request)
        );
        return ResponseEntity.status(status).body(problemDetail);
    }

    // --- REMOVED Audit Logging Helper (logAuditEvent) ---

    // --- Helper Methods for Audit Context (determineEventType, determineActionFromRequest, extractContextData) remain unchanged ---
    private String determineEventType(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.startsWith("/v1/kv/")) {
            return "kv_operation";
        } else if (path.startsWith("/v1/db/")) {
            return "db_operation";
        }
        return "request_error"; // Default type
    }

    private String determineActionFromRequest(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();

        if (path.contains("/v1/db/creds/")) return "generate_credentials";
        if (path.contains("/v1/db/leases/")) return "revoke_lease";

        if (path.contains("/v1/kv/data/")) {
            return switch (method.toUpperCase()) {
                case "GET" -> "read";
                case "PUT", "POST" -> "write";
                case "DELETE" -> "delete";
                default -> "unknown_kv";
            };
        }
        return "unknown";
    }

    private Map<String, Object> extractContextData(HttpServletRequest request) {
        Map<String, Object> data = new HashMap<>();
        String uri = request.getRequestURI();

        Matcher dbCredsMatcher = DB_CREDS_PATH_PATTERN.matcher(uri);
        if (dbCredsMatcher.matches()) {
            data.put("role_name", dbCredsMatcher.group(1));
            return data;
        }

        Matcher dbLeasesMatcher = DB_LEASES_PATH_PATTERN.matcher(uri);
        if (dbLeasesMatcher.matches()) {
            try {
                data.put("lease_id", UUID.fromString(dbLeasesMatcher.group(1)).toString());
            } catch (IllegalArgumentException e) {
                log.warn("Could not parse UUID from lease path segment: {}", dbLeasesMatcher.group(1));
                data.put("lease_id_raw", dbLeasesMatcher.group(1)); // Log raw value if parsing fails
            }
            return data;
        }

        Matcher kvMatcher = KV_PATH_PATTERN.matcher(uri);
        if (kvMatcher.matches()) {
            data.put("kv_path", kvMatcher.group(1));
            return data;
        }

        // Add more specific context extraction if needed
        return data; // Return empty map if no specific context found
    }
}