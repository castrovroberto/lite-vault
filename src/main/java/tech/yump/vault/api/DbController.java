package tech.yump.vault.api;

// Removed HttpServletRequest import if only used for audit
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
// Removed SecurityContextHolder and related imports if only used for audit
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.dto.DbCredentialsResponse;
// Removed AuditBackend and AuditEvent imports
import tech.yump.vault.audit.AuditHelper; // Added
// Removed StaticTokenAuthFilter import if only used for REQUEST_ID_ATTR
import tech.yump.vault.service.DbCredentialService;

// Removed time, collections, map, optional imports if only used for audit
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/v1/db")
@RequiredArgsConstructor
@Slf4j
public class DbController {

    private final DbCredentialService dbCredentialService;
    // Inject AuditHelper instead of AuditBackend
    private final AuditHelper auditHelper; // Changed
    // Removed HttpServletRequest request;

    @GetMapping("/creds/{roleName}")
    public ResponseEntity<DbCredentialsResponse> generateDbCredentials(@PathVariable String roleName) {
        log.info("Controller: Received request for DB credentials for role: {}", roleName);

        // Delegate to the service layer
        DbCredentialsResponse response = dbCredentialService.generateCredentialsForRole(roleName);
        UUID generatedLeaseId = response.leaseId();

        log.info("Controller: Successfully generated credentials for role '{}', lease ID: {}", roleName, generatedLeaseId);

        // Use AuditHelper
        Map<String, Object> data = new HashMap<>();
        data.put("role_name", roleName);
        data.put("lease_id", generatedLeaseId.toString());
        auditHelper.logHttpEvent(
                "db_operation",
                "generate_credentials",
                "success",
                HttpStatus.OK.value(),
                null, // No error message
                data
        );

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/leases/{leaseId}")
    public ResponseEntity<Void> revokeDbLease(@PathVariable UUID leaseId) {
        log.info("Controller: Received request to revoke DB lease: {}", leaseId);

        dbCredentialService.revokeCredentialLease(leaseId);
        log.info("Controller: Successfully revoked DB lease: {}", leaseId);

        // Use AuditHelper
        auditHelper.logHttpEvent(
                "db_operation",
                "revoke_lease",
                "success",
                HttpStatus.NO_CONTENT.value(),
                null, // No error message
                Map.of("lease_id", leaseId.toString())
        );
        return ResponseEntity.noContent().build();
    }

    // --- REMOVED logSuccessAuditEvent helper method ---
}