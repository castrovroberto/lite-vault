package tech.yump.vault.api.v1;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.crypto.EncryptionService;

import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/v1/transit")
@Slf4j
@RequiredArgsConstructor
@Tag(name = "Transit", description = "Encryption-as-a-Service: encrypt and decrypt data without exposing the key")
public class TransitController {

    private final EncryptionService encryptionService;
    private final AuditHelper auditHelper;

    @PostMapping("/encrypt/{keyName}")
    @Operation(
            summary = "Encrypt plaintext",
            description = "Encrypts a Base64-encoded plaintext using the vault master key. " +
                    "The {keyName} parameter is accepted for API compatibility but currently " +
                    "a single global key is used. Returns Base64-encoded ciphertext (nonce || ciphertext)."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Plaintext encrypted successfully.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example = "{\"ciphertext\":\"BASE64_ENCODED_NONCE_AND_CIPHERTEXT\"}"))),
            @ApiResponse(responseCode = "400", description = "Invalid request body or Base64 encoding.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Authentication failed.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "503", description = "Vault is sealed.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class)))
    })
    public ResponseEntity<Map<String, String>> encrypt(
            @Parameter(description = "Key name (reserved for future multi-key support; currently ignored)", required = true)
            @PathVariable String keyName,
            @RequestBody Map<String, String> body
    ) {
        String plaintextB64 = body.get("plaintext");
        if (plaintextB64 == null || plaintextB64.isBlank()) {
            throw new IllegalArgumentException("Request body must contain a non-empty 'plaintext' field (Base64-encoded).");
        }

        byte[] plaintext;
        try {
            plaintext = Base64.getDecoder().decode(plaintextB64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("'plaintext' field must be valid Base64.");
        }

        log.debug("Transit encrypt request for keyName='{}', plaintext size={} bytes", keyName, plaintext.length);

        byte[] nonceAndCiphertext = encryptionService.encrypt(plaintext);
        String ciphertextB64 = Base64.getEncoder().encodeToString(nonceAndCiphertext);

        auditHelper.logHttpEvent(
                "transit_operation", "encrypt", "success", 200,
                null, Map.of("key_name", keyName, "plaintext_bytes", plaintext.length)
        );

        return ResponseEntity.ok(Map.of("ciphertext", ciphertextB64));
    }

    @PostMapping("/decrypt/{keyName}")
    @Operation(
            summary = "Decrypt ciphertext",
            description = "Decrypts a Base64-encoded ciphertext (nonce || ciphertext format) using the vault master key. " +
                    "Returns the original plaintext as a Base64-encoded string."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Ciphertext decrypted successfully.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(example = "{\"plaintext\":\"BASE64_ENCODED_PLAINTEXT\"}"))),
            @ApiResponse(responseCode = "400", description = "Invalid request body, Base64 encoding, or tampered ciphertext.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Authentication failed.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "503", description = "Vault is sealed.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class)))
    })
    public ResponseEntity<Map<String, String>> decrypt(
            @Parameter(description = "Key name (reserved for future multi-key support; currently ignored)", required = true)
            @PathVariable String keyName,
            @RequestBody Map<String, String> body
    ) {
        String ciphertextB64 = body.get("ciphertext");
        if (ciphertextB64 == null || ciphertextB64.isBlank()) {
            throw new IllegalArgumentException("Request body must contain a non-empty 'ciphertext' field (Base64-encoded).");
        }

        byte[] nonceAndCiphertext;
        try {
            nonceAndCiphertext = Base64.getDecoder().decode(ciphertextB64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("'ciphertext' field must be valid Base64.");
        }

        log.debug("Transit decrypt request for keyName='{}', ciphertext size={} bytes", keyName, nonceAndCiphertext.length);

        byte[] plaintext = encryptionService.decrypt(nonceAndCiphertext);
        String plaintextB64 = Base64.getEncoder().encodeToString(plaintext);

        auditHelper.logHttpEvent(
                "transit_operation", "decrypt", "success", 200,
                null, Map.of("key_name", keyName)
        );

        return ResponseEntity.ok(Map.of("plaintext", plaintextB64));
    }
}
