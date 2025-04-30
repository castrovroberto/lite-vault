package tech.yump.vault.api.v1;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.auth.StaticTokenAuthFilter;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.kv.KVEngineException;
import tech.yump.vault.secrets.kv.KVSecretEngine;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/v1/kv/data")
@Slf4j
@RequiredArgsConstructor // Lombok handles constructor
public class KVController {

    private final KVSecretEngine kvSecretEngine;
    private final AuditBackend auditBackend; // Added
    private final HttpServletRequest request; // Added (to get request-specific info like IP)

    @PutMapping("/{*path}")
    public ResponseEntity<?> writeSecret(
            @PathVariable String path,
            @RequestBody Map<String, String> secrets // DO NOT LOG THIS MAP
    ) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to write secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
        kvSecretEngine.write(sanitizedPath, secrets);
        log.info("Successfully wrote secrets to path: {}", sanitizedPath);

        // --- Audit Log for Success ---
        logAuditEvent(
                "kv_operation",
                "write",
                "success",
                HttpStatus.NO_CONTENT.value(), // 204
                null, // No error message
                sanitizedPath
        );

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{*path}")
    public ResponseEntity<Map<String, String>> readSecret(
            @PathVariable String path
    ) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to read secrets from raw path: {}, sanitized path: {}", path, sanitizedPath);
        Optional<Map<String, String>> secretsOptional = kvSecretEngine.read(sanitizedPath);

        if (secretsOptional.isPresent()) {
            log.info("Secrets found for path: {}", sanitizedPath);
            // --- Audit Log for Success ---
            logAuditEvent(
                    "kv_operation",
                    "read",
                    "success",
                    HttpStatus.OK.value(), // 200
                    null,
                    sanitizedPath
            );
            return ResponseEntity.ok(secretsOptional.get());
        } else {
            log.info("No secrets found for path: {}", sanitizedPath);
            // --- Audit Log for Not Found (still a 'successful' operation outcome in a way) ---
            logAuditEvent(
                    "kv_operation",
                    "read",
                    "success", // Or maybe "not_found"? Let's stick with success for the operation itself.
                    HttpStatus.NOT_FOUND.value(), // 404
                    "Secret not found at path",
                    sanitizedPath
            );
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{*path}")
    public ResponseEntity<Void> deleteSecret(@PathVariable String path) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to delete secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
        kvSecretEngine.delete(sanitizedPath);
        log.info("Successfully processed delete request for path: {}", sanitizedPath);

        // --- Audit Log for Success ---
        logAuditEvent(
                "kv_operation",
                "delete",
                "success",
                HttpStatus.NO_CONTENT.value(), // 204
                null,
                sanitizedPath
        );

        return ResponseEntity.noContent().build();
    }

    // --- Exception Handlers with Audit Logging ---

    @ExceptionHandler(KVEngineException.class)
    public ResponseEntity<ApiError> handleKVEngineException(KVEngineException ex, HttpServletRequest req) { // Added req
        String path = extractPathFromRequest(req); // Helper to get path if possible
        log.error("KV Engine error for path [{}]: {}", path, ex.getMessage(), ex);
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = "Internal server error processing KV request.";
        if (ex.getCause() instanceof VaultSealedException) {
            status = HttpStatus.SERVICE_UNAVAILABLE; // 503
            message = "Vault is sealed.";
        }

        // --- Audit Log for Failure ---
        logAuditEvent(
                "kv_operation",
                determineActionFromMethod(req.getMethod()), // Determine action from method
                "failure",
                status.value(),
                message,
                path
        );

        return ResponseEntity.status(status).body(new ApiError(message));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleIllegalArgumentException(IllegalArgumentException ex, HttpServletRequest req) { // Added req
        String path = extractPathFromRequest(req);
        log.warn("Bad request for path [{}]: {}", path, ex.getMessage());
        HttpStatus status = HttpStatus.BAD_REQUEST; // 400
        String message = "Bad request: " + ex.getMessage();

        // --- Audit Log for Failure ---
        logAuditEvent(
                "kv_operation", // Or maybe "request_validation"?
                determineActionFromMethod(req.getMethod()),
                "failure",
                status.value(),
                message,
                path
        );

        return ResponseEntity.status(status).body(new ApiError(message));
    }

    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ApiError> handleVaultSealedException(VaultSealedException ex, HttpServletRequest req) { // Added req
        String path = extractPathFromRequest(req);
        log.warn("Operation failed for path [{}]: Vault is sealed.", path);
        HttpStatus status = HttpStatus.SERVICE_UNAVAILABLE; // 503
        String message = "Vault is sealed.";

        // --- Audit Log for Failure ---
        logAuditEvent(
                "kv_operation",
                determineActionFromMethod(req.getMethod()),
                "failure",
                status.value(),
                message,
                path
        );

        return ResponseEntity.status(status).body(new ApiError(message));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGenericException(Exception ex, HttpServletRequest req) { // Added req
        String path = extractPathFromRequest(req);
        log.error("An unexpected error occurred for path [{}]: {}", path, ex.getMessage(), ex);
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR; // 500
        String message = "An unexpected internal error occurred.";

        // --- Audit Log for Failure ---
        logAuditEvent(
                "kv_operation", // Or "system_error"
                determineActionFromMethod(req.getMethod()),
                "failure",
                status.value(),
                message,
                path
        );

        return ResponseEntity.status(status).body(new ApiError(message));
    }

    // --- Helper method to build and log AuditEvent ---
    private void logAuditEvent(String type, String action, String outcome, int statusCode, String errorMessage, String kvPath) {
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
                authInfoBuilder.principal("unknown"); // Should ideally not happen if security config is right
            }

            AuditEvent.RequestInfo requestInfo = AuditEvent.RequestInfo.builder()
                    .requestId((String) request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR))
                    .httpMethod(request.getMethod())
                    .path(request.getRequestURI()) // Full request URI
                    .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
                    .build();

            AuditEvent.ResponseInfo responseInfo = AuditEvent.ResponseInfo.builder()
                    .statusCode(statusCode)
                    .errorMessage(errorMessage) // Will be null for success cases
                    .build();

            // Add KV path to specific data map
            Map<String, Object> data = Map.of("kv_path", Optional.ofNullable(kvPath).orElse("N/A"));

            AuditEvent event = AuditEvent.builder()
                    .timestamp(Instant.now())
                    .type(type)
                    .action(action)
                    .outcome(outcome)
                    .authInfo(authInfoBuilder.build())
                    .requestInfo(requestInfo)
                    .responseInfo(responseInfo)
                    .data(data)
                    .build();

            auditBackend.logEvent(event);

        } catch (Exception e) {
            // Avoid letting audit failures break the main request flow
            log.error("Failed to log audit event in KVController: {}", e.getMessage(), e);
        }
    }

    // --- Helper to get path for logging in exception handlers ---
    private String extractPathFromRequest(HttpServletRequest req) {
        String uri = req.getRequestURI();
        String prefix = req.getContextPath() + "/v1/kv/data/";
        if (uri.startsWith(prefix)) {
            return sanitizePath(uri.substring(prefix.length()));
        }
        return uri; // Fallback to full URI if pattern doesn't match
    }

    // --- Helper to map HTTP method to action string ---
    private String determineActionFromMethod(String method) {
        return switch (method.toUpperCase()) {
            case "GET" -> "read";
            case "PUT", "POST" -> "write"; // Treat POST as write for KV
            case "DELETE" -> "delete";
            default -> "unknown";
        };
    }

    // --- Keep sanitizePath method ---
    private String sanitizePath(String rawPath) {
        if (rawPath != null && rawPath.startsWith("/")) {
            return rawPath.substring(1);
        }
        return rawPath;
    }
}
