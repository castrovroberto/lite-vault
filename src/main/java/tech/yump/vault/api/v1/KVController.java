package tech.yump.vault.api.v1;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.kv.KVEngineException;
import tech.yump.vault.secrets.kv.KVSecretEngine;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/v1/kv/data")
@Slf4j
@RequiredArgsConstructor
public class KVController {

    private final KVSecretEngine kvSecretEngine;

    @PutMapping("/{*path}")
    public ResponseEntity<?> writeSecret(
            @PathVariable String path,
            @RequestBody Map<String, String> secrets
    ) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to write secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
        kvSecretEngine.write(sanitizedPath, secrets);
        log.info("Successfully wrote secrets to path: {}", sanitizedPath);
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
            return ResponseEntity.ok(secretsOptional.get());
        } else {
            log.info("No secrets found for path: {}", sanitizedPath);
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{*path}")
    public ResponseEntity<Void> deleteSecret(@PathVariable String path) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to delete secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
        kvSecretEngine.delete(sanitizedPath);
        log.info("Successfully processed delete request for path: {}", sanitizedPath);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(KVEngineException.class)
    public ResponseEntity<ApiError> handleKVEngineException(KVEngineException ex) {
        log.error("KV Engine error: {}", ex.getMessage(), ex);
        if (ex.getCause() instanceof VaultSealedException) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(new ApiError("Vault is sealed."));
        }
        // Default to 500 for other KV engine errors (storage, encryption, etc.)
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError("Internal server error processing KV request."));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiError> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.warn("Bad request: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ApiError("Bad request: " + ex.getMessage()));
    }

    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ApiError> handleVaultSealedException(VaultSealedException ex) {
        log.warn("Operation failed: Vault is sealed.");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE) // 503
                .body(new ApiError("Vault is sealed."));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGenericException(Exception ex) {
        log.error("An unexpected error occurred: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiError("An unexpected internal error occurred."));
    }

    private String sanitizePath(String rawPath) {
        if (rawPath != null && rawPath.startsWith("/")) {
            return rawPath.substring(1);
        }
        return rawPath;
    }

}