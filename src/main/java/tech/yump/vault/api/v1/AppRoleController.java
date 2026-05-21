package tech.yump.vault.api.v1;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.auth.approle.AppRoleDefinition;
import tech.yump.vault.auth.approle.AppRoleService;
import tech.yump.vault.auth.approle.dto.CreateRoleRequest;
import tech.yump.vault.auth.approle.dto.LoginRequest;
import tech.yump.vault.auth.approle.dto.LoginResponse;
import tech.yump.vault.auth.approle.dto.SecretIdResponse;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/v1/auth/approle")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "AppRole Auth", description = "Dynamic credential exchange: role CRUD, secret_id generation, and JWT login")
public class AppRoleController {

    private static final Duration DEFAULT_TOKEN_TTL = Duration.ofHours(1);
    private static final Duration DEFAULT_SECRET_ID_TTL = Duration.ofHours(24);

    private final AppRoleService appRoleService;
    private final AuditHelper auditHelper;

    @PostMapping("/login")
    @Operation(summary = "Login with AppRole credentials",
            description = "Exchange a role_id and secret_id for a short-lived JWT. No authentication header required.",
            security = {})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful, JWT returned.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid or expired credentials.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ApiError.class)))
    })
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        if (request.roleId() == null || request.roleId().isBlank()) {
            throw new IllegalArgumentException("role_id is required.");
        }
        if (request.secretId() == null || request.secretId().isBlank()) {
            throw new IllegalArgumentException("secret_id is required.");
        }
        AppRoleService.LoginResult result = appRoleService.login(request.roleId(), request.secretId());
        auditHelper.logHttpEvent("approle_operation", "login", "success", 200, null,
                Map.of("role_id", request.roleId()));
        return ResponseEntity.ok(new LoginResponse(result.token(), result.ttlSeconds()));
    }

    @PostMapping("/role/{roleName}")
    @Operation(summary = "Create or update an AppRole",
            description = "Defines a named role bound to one or more policies. Requires WRITE on auth/approle/role/*.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Role created or updated."),
            @ApiResponse(responseCode = "400", description = "Invalid request.",
                    content = @Content(schema = @Schema(implementation = ApiError.class))),
            @ApiResponse(responseCode = "401", description = "Unauthenticated."),
            @ApiResponse(responseCode = "403", description = "Permission denied.")
    })
    public ResponseEntity<Void> createOrUpdateRole(@PathVariable String roleName,
                                                    @RequestBody CreateRoleRequest request) {
        AppRoleDefinition role = new AppRoleDefinition(
                roleName,
                request.policyNames(),
                request.tokenTtl() != null ? request.tokenTtl() : DEFAULT_TOKEN_TTL,
                request.secretIdTtl() != null ? request.secretIdTtl() : DEFAULT_SECRET_ID_TTL,
                request.secretIdNumUses()
        );
        appRoleService.createOrUpdateRole(role);
        auditHelper.logHttpEvent("approle_operation", "role_create_or_update", "success", 204, null,
                Map.of("role_name", roleName));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/role/{roleName}")
    @Operation(summary = "Read an AppRole definition",
            description = "Returns the role definition including policy bindings and TTL settings.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Role found.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = AppRoleDefinition.class))),
            @ApiResponse(responseCode = "404", description = "Role not found.",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    public ResponseEntity<AppRoleDefinition> getRole(@PathVariable String roleName) {
        AppRoleDefinition role = appRoleService.getRole(roleName);
        auditHelper.logHttpEvent("approle_operation", "role_read", "success", 200, null,
                Map.of("role_name", roleName));
        return ResponseEntity.ok(role);
    }

    @DeleteMapping("/role/{roleName}")
    @Operation(summary = "Delete an AppRole",
            description = "Deletes the role and all associated pending secret_ids.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Role deleted."),
            @ApiResponse(responseCode = "404", description = "Role not found.",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    public ResponseEntity<Void> deleteRole(@PathVariable String roleName) {
        appRoleService.deleteRole(roleName);
        auditHelper.logHttpEvent("approle_operation", "role_delete", "success", 204, null,
                Map.of("role_name", roleName));
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/role/{roleName}/secret-id")
    @Operation(summary = "Generate a secret_id for an AppRole",
            description = "Creates a new secret_id credential for the named role. The secret_id is single-use " +
                    "if secretIdNumUses is 1, unlimited if 0.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "secret_id generated.",
                    content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = SecretIdResponse.class))),
            @ApiResponse(responseCode = "404", description = "Role not found.",
                    content = @Content(schema = @Schema(implementation = ApiError.class)))
    })
    public ResponseEntity<SecretIdResponse> generateSecretId(@PathVariable String roleName) {
        String secretId = appRoleService.generateSecretId(roleName);
        auditHelper.logHttpEvent("approle_operation", "secret_id_generate", "success", 200, null,
                Map.of("role_name", roleName));
        return ResponseEntity.ok(new SecretIdResponse(secretId));
    }
}
