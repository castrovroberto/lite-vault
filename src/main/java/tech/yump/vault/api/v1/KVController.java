package tech.yump.vault.api.v1;

// Removed HttpServletRequest import if only used for audit
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
// Removed SecurityContextHolder and related imports if only used for audit
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
// Removed AuditBackend and AuditEvent imports
import tech.yump.vault.audit.AuditHelper; // Added
// Removed StaticTokenAuthFilter import if only used for REQUEST_ID_ATTR
import tech.yump.vault.secrets.kv.KVSecretEngine;

// Removed time, collections, map, optional imports if only used for audit
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/v1/kv/data")
@Slf4j
@RequiredArgsConstructor
public class KVController {

    private final KVSecretEngine kvSecretEngine;
    // Inject AuditHelper instead of AuditBackend
    private final AuditHelper auditHelper; // Changed
    // Removed HttpServletRequest request;

    @PutMapping("/{*path}")
    public ResponseEntity<?> writeSecret(
            @PathVariable String path,
            @RequestBody Map<String, String> secrets
    ) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to write secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
        kvSecretEngine.write(sanitizedPath, secrets);
        log.info("Successfully wrote secrets to path: {}", sanitizedPath);

        // Use AuditHelper
        auditHelper.logHttpEvent(
                "kv_operation",
                "write",
                "success",
                HttpStatus.NO_CONTENT.value(),
                null, // No error message
                Map.of("kv_path", sanitizedPath)
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
            // Use AuditHelper for success
            auditHelper.logHttpEvent(
                    "kv_operation",
                    "read",
                    "success",
                    HttpStatus.OK.value(),
                    null,
                    Map.of("kv_path", sanitizedPath)
            );
            return ResponseEntity.ok(secretsOptional.get());
        } else {
            log.info("No secrets found for path: {}", sanitizedPath);
            // Use AuditHelper for "not found" outcome (still a successful HTTP interaction)
            auditHelper.logHttpEvent(
                    "kv_operation",
                    "read",
                    "success", // Or maybe "not_found"? Let's stick with success for HTTP 404
                    HttpStatus.NOT_FOUND.value(),
                    "KV secret not found at path", // Optional message
                    Map.of("kv_path", sanitizedPath)
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

        // Use AuditHelper
        auditHelper.logHttpEvent(
                "kv_operation",
                "delete",
                "success",
                HttpStatus.NO_CONTENT.value(),
                null,
                Map.of("kv_path", sanitizedPath)
        );

        return ResponseEntity.noContent().build();
    }

    // --- REMOVED logSuccessAuditEvent helper method ---

    // --- Keep sanitizePath method ---
    private String sanitizePath(String rawPath) {
        if (rawPath != null && rawPath.startsWith("/")) {
            return rawPath.substring(1);
        }
        return rawPath;
    }
}