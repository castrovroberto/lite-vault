package tech.yump.vault.api.v1;

// Import Swagger annotations

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.secrets.jwt.JwtSecretsEngine;

import java.util.Map;

@RestController
@RequestMapping("/v1/jwt")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "JWT Secrets", description = "Operations for the JWT Secrets Engine (Signing, JWKS, Rotation)")
public class JwtController {

    private final JwtSecretsEngine jwtSecretsEngine;
    private final AuditHelper auditHelper;

    // Define DTO for response schema documentation
    @Schema(description = "Response containing the signed JSON Web Token.")
    public record JwtResponse(
            @Schema(description = "The generated and signed JWT string.", example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
            String jwt
    ) {}

    @PostMapping("/sign/{keyName}")
    @Operation(
            summary = "Sign JWT",
            description = "Generates and signs a JSON Web Token (JWT) using the specified key configuration and provided claims."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "JWT signed successfully.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = JwtResponse.class))
            ),
            @ApiResponse(responseCode = "400", description = "Invalid request body (claims).", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Authentication failed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "Specified JWT key name not found.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))), // JwtKeyNotFoundException
            @ApiResponse(responseCode = "500", description = "Internal server error during signing.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))), // SecretsEngineException
            @ApiResponse(responseCode = "503", description = "Vault is sealed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))) // VaultSealedException
    })
    public ResponseEntity<JwtResponse> signJwt(
            @Parameter(description = "Name of the configured JWT key to use for signing.", required = true, example = "api-signing-key-rsa")
            @PathVariable String keyName,
            @RequestBody( // Use io.swagger.v3.oas.annotations.parameters.RequestBody
                    description = "A JSON object containing the claims to include in the JWT payload.",
                    required = true,
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(type = "object", example = "{\"sub\": \"user123\", \"iss\": \"lite-vault\", \"aud\": \"my-api\", \"customClaim\": true}")
                    )
            )
            @org.springframework.web.bind.annotation.RequestBody Map<String, Object> claims // Keep Spring's annotation
            // No token parameter needed
    ) {
        if (claims == null) {
            throw new IllegalArgumentException("Claims body must not be null.");
        }
        if (claims.size() > 50) {
            throw new IllegalArgumentException("Claims map exceeds maximum allowed size (50 entries).");
        }
        log.info("Controller: Received request to sign JWT using key: {}", keyName);
        String operation = "sign_jwt";
        try {
            String jwtString = jwtSecretsEngine.signJwt(keyName, claims);
            log.info("Controller: Successfully signed JWT using key '{}'", keyName);
            auditHelper.logHttpEvent("jwt_operation", operation, "success", HttpStatus.OK.value(), null, Map.of("key_name", keyName));
            return ResponseEntity.ok(new JwtResponse(jwtString));
        } catch (Exception e) {
            throw e; // Let exception handlers manage audit logging for failures
        }
    }

    @GetMapping("/jwks/{keyName}")
    // Override global security: JWKS endpoint is often public
    @SecurityRequirement(name = "NoAuthenticationNeeded") // Define a dummy requirement name or use an empty one if allowed by tool version
    @Operation(
            summary = "Get JWKS",
            description = "Retrieves the public JSON Web Key Set (JWKS) for the specified key name. This endpoint is typically public and used by clients to verify JWT signatures.",
            // Explicitly state no security needed for this specific endpoint
            security = {} // Empty array overrides global security requirement
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "JWKS retrieved successfully.",
                    content = @Content(
                            mediaType = MediaType.APPLICATION_JSON_VALUE,
                            // JWKS structure is standard: https://tools.ietf.org/html/rfc7517
                            schema = @Schema(type = "object", example = "{\"keys\": [{\"kty\": \"RSA\", \"kid\": \"...\", \"n\": \"...\", \"e\": \"AQAB\"}]}")
                    )
            ),
            @ApiResponse(responseCode = "404", description = "Specified JWT key name not found.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))), // JwtKeyNotFoundException
            @ApiResponse(responseCode = "500", description = "Internal server error retrieving key.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))), // SecretsEngineException
            @ApiResponse(responseCode = "503", description = "Vault is sealed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))) // VaultSealedException
    })
    public ResponseEntity<Map<String, Object>> getJsonWebKeySet(
            @Parameter(description = "Name of the configured JWT key whose public JWKS should be retrieved.", required = true, example = "api-signing-key-rsa")
            @PathVariable String keyName
    ) {
        log.info("Controller: Received request for JWKS for key: {}", keyName);
        String operation = "get_jwks";
        try {
            Map<String, Object> jwksMap = jwtSecretsEngine.getJwks(keyName);
            log.info("Controller: Successfully retrieved JWKS for key '{}'", keyName);
            // Audit success (even though public, might be useful to log access)
            auditHelper.logHttpEvent("jwt_operation", operation, "success", HttpStatus.OK.value(), null, Map.of("key_name", keyName));
            return ResponseEntity.ok(jwksMap);
        } catch (Exception e) {
            log.debug("Controller: Exception occurred during JWKS retrieval for key '{}', delegating to handler.", keyName, e);
            throw e; // Let exception handlers manage audit logging for failures
        }
    }

    @PostMapping("/rotate/{keyName}")
    @Operation(
            summary = "Rotate JWT key",
            description = "Initiates the rotation of the specified JWT key. A new key version will be generated and become the active signing key."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Key rotated successfully."),
            @ApiResponse(responseCode = "401", description = "Authentication failed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "Specified JWT key name not found.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))), // JwtKeyNotFoundException
            @ApiResponse(responseCode = "500", description = "Internal server error during rotation.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))), // SecretsEngineException
            @ApiResponse(responseCode = "503", description = "Vault is sealed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))) // VaultSealedException
    })
    public ResponseEntity<Void> rotateKey(
            @Parameter(description = "Name of the configured JWT key to rotate.", required = true, example = "internal-service-key-ec")
            @PathVariable String keyName
            // No token parameter needed
    ) {
        log.info("Controller: Received request to rotate JWT key: {}", keyName);
        String operation = "rotate_key";
        try {
            jwtSecretsEngine.rotateKey(keyName);
            log.info("Controller: Successfully rotated JWT key '{}'", keyName);
            auditHelper.logHttpEvent("jwt_operation", operation, "success", HttpStatus.NO_CONTENT.value(), null, Map.of("key_name", keyName));
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            throw e; // Let exception handlers manage audit logging for failures
        }
    }

}
