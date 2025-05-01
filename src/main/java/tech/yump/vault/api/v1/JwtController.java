// src/main/java/tech/yump/vault/api/v1/JwtController.java
package tech.yump.vault.api.v1;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.jwt.JwtSecretsEngine;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/v1/jwt")
@RequiredArgsConstructor
@Slf4j
public class JwtController {

    private final JwtSecretsEngine jwtSecretsEngine;
    private final AuditHelper auditHelper;

    // Pattern to extract key name from exception messages if possible
    private static final Pattern KEY_NAME_PATTERN = Pattern.compile("key '([^']*)'");

    public record JwtResponse(String jwt) {}

    @PostMapping("/sign/{keyName}")
    public ResponseEntity<JwtResponse> signJwt(
            @PathVariable String keyName,
            @RequestBody Map<String, Object> claims
    ) {
        log.info("Controller: Received request to sign JWT using key: {}", keyName);
        String operation = "sign_jwt"; // For audit context

        try {
            String jwtString = jwtSecretsEngine.signJwt(keyName, claims);
            log.info("Controller: Successfully signed JWT using key '{}'", keyName);

            // Audit success
            auditHelper.logHttpEvent(
                    "jwt_operation",
                    operation,
                    "success",
                    HttpStatus.OK.value(),
                    null,
                    Map.of("key_name", keyName)
            );

            return ResponseEntity.ok(new JwtResponse(jwtString));
        } catch (Exception e) {
            // Let exception handlers manage audit logging for failures
            throw e;
        }
    }

    @PostMapping("/rotate/{keyName}")
    public ResponseEntity<Void> rotateKey(@PathVariable String keyName) {
        log.info("Controller: Received request to rotate JWT key: {}", keyName);
        String operation = "rotate_key"; // For audit context

        try {
            jwtSecretsEngine.rotateKey(keyName);
            log.info("Controller: Successfully rotated JWT key '{}'", keyName);

            // Audit success
            auditHelper.logHttpEvent(
                    "jwt_operation",
                    operation,
                    "success",
                    HttpStatus.NO_CONTENT.value(),
                    null,
                    Map.of("key_name", keyName)
            );

            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            // Let exception handlers manage audit logging for failures
            throw e;
        }
    }

    // --- Exception Handlers (Updated for better audit context) ---

    @ExceptionHandler(JwtSecretsEngine.JwtKeyNotFoundException.class)
    public ResponseEntity<ApiError> handleKeyNotFoundException(JwtSecretsEngine.JwtKeyNotFoundException ex) {
        log.warn("JWT Key Not Found: {}", ex.getMessage());
        String keyName = extractKeyName(ex.getMessage()).orElse("unknown");
        // Determine operation based on request path or keep generic? Let's keep it generic for now.
        String operation = "jwt_operation_failed"; // Generic failure action

        // Audit failure
        Map<String, Object> auditData = new HashMap<>();
        auditData.put("error_type", "key_not_found");
        auditData.put("key_name", keyName);

        auditHelper.logHttpEvent(
                "jwt_operation",
                operation,
                "failure",
                HttpStatus.NOT_FOUND.value(),
                ex.getMessage(),
                auditData
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiError("JWT key configuration or version not found: " + ex.getMessage()));
    }

    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ApiError> handleVaultSealedException(VaultSealedException ex) {
        log.warn("Operation failed: {}", ex.getMessage());
        String operation = "jwt_operation_failed"; // Generic failure action

        // Audit failure
        auditHelper.logHttpEvent(
                "jwt_operation",
                operation,
                "failure",
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                ex.getMessage(),
                Map.of("error_type", "vault_sealed")
        );
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(new ApiError("Vault is sealed.")); // Keep message generic for clients
    }

    @ExceptionHandler(SecretsEngineException.class)
    public ResponseEntity<ApiError> handleSecretsEngineException(SecretsEngineException ex) {
        log.error("JWT Secrets Engine Error: {}", ex.getMessage(), ex);
        String operation = "jwt_operation_failed"; // Generic failure action
        String keyName = extractKeyName(ex.getMessage()).orElse("unknown");

        // Audit failure
        Map<String, Object> auditData = new HashMap<>();
        auditData.put("error_type", "engine_error");
        auditData.put("key_name", keyName); // Include key name if found

        auditHelper.logHttpEvent(
                "jwt_operation",
                operation,
                "failure",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                ex.getMessage(),
                auditData
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError("Internal server error during JWT operation."));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGenericException(Exception ex) {
        log.error("Unexpected error during JWT operation: {}", ex.getMessage(), ex);
        String operation = "jwt_operation_failed"; // Generic failure action

        // Audit failure
        auditHelper.logHttpEvent(
                "jwt_operation",
                operation,
                "failure",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                ex.getMessage(),
                Map.of("error_type", "unexpected")
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError("An unexpected error occurred."));
    }

    // Helper to extract key name from exception messages
    private static Optional<String> extractKeyName(String message) {
        if (message == null) {
            return Optional.empty();
        }
        Matcher matcher = KEY_NAME_PATTERN.matcher(message);
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }
}