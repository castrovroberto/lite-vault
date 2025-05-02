package tech.yump.vault.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.dto.DbCredentialsResponse;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.service.DbCredentialService;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/v1/db") // Corrected path
@RequiredArgsConstructor
@Slf4j
@Tag(name = "DB Credentials", description = "Operations for the Dynamic Database Credentials Secrets Engine")
public class DbController {

    private final DbCredentialService dbCredentialService;
    private final AuditHelper auditHelper;

    @GetMapping("/creds/{roleName}")
    @Operation(
            summary = "Generate dynamic DB credentials",
            description = "Generates a new set of database credentials (username, password) based on a pre-configured role. Returns the credentials along with a lease ID and duration."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Credentials generated successfully.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = DbCredentialsResponse.class))
            ),
            @ApiResponse(responseCode = "401", description = "Authentication failed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "Specified role name not found or configured.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))), // RoleNotFoundException
            @ApiResponse(responseCode = "500", description = "Internal server error during credential generation (e.g., DB connection issue).", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "503", description = "Vault is sealed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))) // VaultSealedException
    })
    public ResponseEntity<DbCredentialsResponse> generateDbCredentials(
            @Parameter(description = "Name of the configured database role.", required = true, example = "readonly-app-role")
            @PathVariable String roleName
            // No token parameter needed
    ) {
        log.info("Controller: Received request for DB credentials for role: {}", roleName);
        DbCredentialsResponse response = dbCredentialService.generateCredentialsForRole(roleName);
        UUID generatedLeaseId = response.leaseId();
        log.info("Controller: Successfully generated credentials for role '{}', lease ID: {}", roleName, generatedLeaseId);

        Map<String, Object> data = new HashMap<>();
        data.put("role_name", roleName);
        data.put("lease_id", generatedLeaseId.toString());
        auditHelper.logHttpEvent(
                "db_operation", "generate_credentials", "success", HttpStatus.OK.value(),
                null, data
        );
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/leases/{leaseId}")
    @Operation(
            summary = "Revoke DB credential lease",
            description = "Revokes the lease associated with a set of dynamic database credentials, triggering the cleanup (e.g., dropping the DB user)."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Lease revoked successfully."),
            @ApiResponse(responseCode = "401", description = "Authentication failed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "403", description = "Permission denied.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "404", description = "Specified lease ID not found.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))), // LeaseNotFoundException
            @ApiResponse(responseCode = "500", description = "Internal server error during lease revocation.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "503", description = "Vault is sealed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))) // VaultSealedException
    })
    public ResponseEntity<Void> revokeDbLease(
            @Parameter(description = "UUID of the lease to revoke.", required = true, example = "f47ac10b-58cc-4372-a567-0e02b2c3d479")
            @PathVariable UUID leaseId
            // No token parameter needed
    ) {
        log.info("Controller: Received request to revoke DB lease: {}", leaseId);
        dbCredentialService.revokeCredentialLease(leaseId);
        log.info("Controller: Successfully revoked DB lease: {}", leaseId);

        auditHelper.logHttpEvent(
                "db_operation", "revoke_lease", "success", HttpStatus.NO_CONTENT.value(),
                null, Map.of("lease_id", leaseId.toString())
        );
        return ResponseEntity.noContent().build();
    }
}
