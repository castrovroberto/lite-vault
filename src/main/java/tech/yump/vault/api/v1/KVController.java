package tech.yump.vault.api.v1;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.secrets.kv.KVSecretEngine;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/v1/kv/data") // Base path for KV data operations
@Slf4j
@RequiredArgsConstructor
@Tag(name = "KV Secrets", description = "Operations for the Key-Value v1 Secrets Engine (data path)")
// Global security via OpenApiConfig applies, no need for @SecurityRequirement here
public class KVController {

    private final KVSecretEngine kvSecretEngine;
    private final AuditHelper auditHelper;
    // Removed HttpServletRequest request;

    @PutMapping("/{*path}") // Use PUT for create/update
    @Operation(
            summary = "Write secret",
            description = "Stores or updates secret data (key-value pairs) at the specified path within the KV engine's data mount."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Secret written successfully."),
            @ApiResponse(responseCode = "400", description = "Invalid request body format.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Authentication failed (Missing or invalid X-Vault-Token).", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied based on token policy.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "500", description = "Internal server error during write operation.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "503", description = "Vault is sealed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))) // Added 503
    })
    public ResponseEntity<?> writeSecret(
            @Parameter(description = "Path to the secret within the KV data mount (e.g., 'myapp/config' or 'shared/credentials'). Do not include leading '/'.", required = true, example = "myapp/config")
            @PathVariable String path,
            @RequestBody( // Use io.swagger.v3.oas.annotations.parameters.RequestBody
                    description = "A JSON object containing the key-value pairs to store as the secret data.",
                    required = true,
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(type = "object", additionalProperties = Schema.AdditionalPropertiesValue.TRUE, example = "{\"apiKey\": \"123-abc\", \"timeout\": \"30s\"}")
                    )
            )
            @org.springframework.web.bind.annotation.RequestBody Map<String, String> secrets // Keep Spring's annotation
            // No need to declare @RequestHeader("X-Vault-Token") here, it's handled globally
    ) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to write secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
        kvSecretEngine.write(sanitizedPath, secrets);
        log.info("Successfully wrote secrets to path: {}", sanitizedPath);

        auditHelper.logHttpEvent(
                "kv_operation", "write", "success", HttpStatus.NO_CONTENT.value(),
                null, Map.of("kv_path", sanitizedPath)
        );
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{*path}")
    @Operation(
            summary = "Read secret",
            description = "Retrieves the secret data (key-value pairs) stored at the specified path."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Secret data retrieved successfully.",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(type = "object", additionalProperties = Schema.AdditionalPropertiesValue.TRUE, example = "{\"apiKey\": \"123-abc\", \"timeout\": \"30s\"}")
                    )
            ),
            @ApiResponse(responseCode = "401", description = "Authentication failed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "Secret not found at the specified path.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "500", description = "Internal server error.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "503", description = "Vault is sealed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))) // Added 503
    })
    public ResponseEntity<Map<String, String>> readSecret(
            @Parameter(description = "Path of the secret to read (e.g., 'myapp/config'). Do not include leading '/'.", required = true, example = "myapp/config")
            @PathVariable String path
            // No token parameter needed
    ) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to read secrets from raw path: {}, sanitized path: {}", path, sanitizedPath);
        Optional<Map<String, String>> secretsOptional = kvSecretEngine.read(sanitizedPath);

        if (secretsOptional.isPresent()) {
            log.info("Secrets found for path: {}", sanitizedPath);
            auditHelper.logHttpEvent(
                    "kv_operation", "read", "success", HttpStatus.OK.value(),
                    null, Map.of("kv_path", sanitizedPath)
            );
            return ResponseEntity.ok(secretsOptional.get());
        } else {
            log.info("No secrets found for path: {}", sanitizedPath);
            auditHelper.logHttpEvent(
                    "kv_operation", "read", "success", HttpStatus.NOT_FOUND.value(),
                    "KV secret not found at path", Map.of("kv_path", sanitizedPath)
            );
            // Return 404 via standard Spring mechanism, which GlobalExceptionHandler might catch
            // For documentation, we list 404 as a possible response.
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{*path}")
    @Operation(
            summary = "Delete secret",
            description = "Permanently removes the secret data stored at the specified path."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Secret deleted successfully."),
            @ApiResponse(responseCode = "401", description = "Authentication failed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            // Note: Delete might not return 404 if path doesn't exist, often returns 204 regardless. Adjust if needed.
            // @ApiResponse(responseCode = "404", description = "Secret not found.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "500", description = "Internal server error.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "503", description = "Vault is sealed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))) // Added 503
    })
    public ResponseEntity<Void> deleteSecret(
            @Parameter(description = "Path of the secret to delete (e.g., 'myapp/config'). Do not include leading '/'.", required = true, example = "myapp/config")
            @PathVariable String path
            // No token parameter needed
    ) {
        String sanitizedPath = sanitizePath(path);
        log.info("Received request to delete secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
        kvSecretEngine.delete(sanitizedPath);
        log.info("Successfully processed delete request for path: {}", sanitizedPath);

        auditHelper.logHttpEvent(
                "kv_operation", "delete", "success", HttpStatus.NO_CONTENT.value(),
                null, Map.of("kv_path", sanitizedPath)
        );
        return ResponseEntity.noContent().build();
    }

    private String sanitizePath(String rawPath) {
        if (rawPath != null && rawPath.startsWith("/")) {
            return rawPath.substring(1);
        }
        return rawPath;
    }
}
