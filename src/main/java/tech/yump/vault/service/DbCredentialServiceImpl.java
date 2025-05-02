package tech.yump.vault.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.yump.vault.api.dto.DbCredentialsResponse;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.LeaseNotFoundException;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.db.PostgresSecretsEngine;

import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class DbCredentialServiceImpl implements DbCredentialService {

    // Inject the specific engine implementation for now.
    private final PostgresSecretsEngine postgresSecretsEngine;

    @Override
    public DbCredentialsResponse generateCredentialsForRole(String roleName) throws RoleNotFoundException, SecretsEngineException, VaultSealedException {
        log.info("Service layer: Generating credentials for role '{}'", roleName); // Changed to info
        // Delegate directly to the engine
        Lease lease = postgresSecretsEngine.generateCredentials(roleName);

        // --- Mapping Logic (Moved from Controller) ---
        Map<String, Object> secretData = lease.secretData();
        String username = (String) secretData.get("username");
        String password = (String) secretData.get("password");

        if (username == null || password == null) {
            log.error("Service layer: Generated lease for role '{}' (ID: {}) is missing username or password.", roleName, lease.id());
            // Consider revoking the potentially incomplete lease? For now, just throw.
            // postgresSecretsEngine.revokeLease(lease.id()); // Optional cleanup
            throw new SecretsEngineException("Internal error: Generated credentials incomplete for lease " + lease.id());
        }

        DbCredentialsResponse response = new DbCredentialsResponse(
                lease.id(),
                username,
                password,
                lease.ttl().toSeconds() // Convert Duration to seconds
        );
        // --- End Mapping Logic ---

        log.info("Service layer: Successfully generated and mapped credentials for role '{}', lease ID: {}", roleName, lease.id()); // Changed to info
        return response;
    }

    @Override
    public void revokeCredentialLease(UUID leaseId) throws LeaseNotFoundException, SecretsEngineException, VaultSealedException {
        log.info("Service layer: Revoking lease ID '{}'", leaseId); // Changed to info
        // Delegate directly to the engine
        // Note: PostgresSecretsEngine.revokeLease currently doesn't check seal status,
        // so VaultSealedException is unlikely here unless added to the engine method.
        // We keep the throws clause for interface consistency and future-proofing.
        postgresSecretsEngine.revokeLease(leaseId);
        log.info("Service layer: Successfully revoked lease ID '{}'", leaseId); // Changed to info
    }
}