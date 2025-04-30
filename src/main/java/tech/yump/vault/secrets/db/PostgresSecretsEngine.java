package tech.yump.vault.secrets.db;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.secrets.DynamicSecretsEngine;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.LeaseNotFoundException;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;

import javax.sql.DataSource;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap; // Added

/**
 * Secrets Engine implementation for dynamically generating PostgreSQL credentials.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PostgresSecretsEngine implements DynamicSecretsEngine {


    private final MssmProperties properties;
    private final DataSource dataSource;
    private final JdbcTemplate jdbcTemplate;
    private final AuditBackend auditBackend;

    // Connection pool is managed by the injected DataSource (HikariCP by default)
    // TODO: Cache role definitions loaded from properties (Task 23) for performance?
    private final ConcurrentHashMap<UUID, Lease> activeLeases = new ConcurrentHashMap<>();

    // --- START: Helper methods from Task 25 Step 1 ---
    // ... (generatePassword, generateUsername, prepareSqlStatements methods remain unchanged) ...
    private static final String ALLOWED_PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    private static final int DEFAULT_PASSWORD_LENGTH = 32;
    private static final String USERNAME_PREFIX = "lv-"; // LiteVault prefix
    private static final int USERNAME_RANDOM_SUFFIX_LENGTH = 8;
    private static final String ALLOWED_USERNAME_SUFFIX_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private final SecureRandom random = new SecureRandom();

    /**
     * Generates a secure random password.
     * @return A randomly generated password string.
     */
    private String generatePassword() {
        StringBuilder password = new StringBuilder(DEFAULT_PASSWORD_LENGTH);
        for (int i = 0; i < DEFAULT_PASSWORD_LENGTH; i++) {
            int index = random.nextInt(ALLOWED_PASSWORD_CHARS.length());
            password.append(ALLOWED_PASSWORD_CHARS.charAt(index));
        }
        return password.toString();
    }

    /**
     * Generates a unique username based on role name and random suffix.
     * NOTE: This is a simple generation strategy. Collision is possible but unlikely
     * with a reasonable suffix length. Production systems might need more robust generation
     * or check-then-generate loops. PostgreSQL identifier length limits also apply (default 63).
     *
     * @param roleName The base role name.
     * @return A generated username string (e.g., "lv-readonly-app-role-a3b1c2d4").
     */
    private String generateUsername(String roleName) {
        StringBuilder suffix = new StringBuilder(USERNAME_RANDOM_SUFFIX_LENGTH);
        for (int i = 0; i < USERNAME_RANDOM_SUFFIX_LENGTH; i++) {
            int index = random.nextInt(ALLOWED_USERNAME_SUFFIX_CHARS.length());
            suffix.append(ALLOWED_USERNAME_SUFFIX_CHARS.charAt(index));
        }
        // Combine prefix, sanitized role name, and suffix
        // Replace non-alphanumeric chars in roleName with underscore, ensure reasonable length
        String sanitizedRoleName = roleName.replaceAll("[^a-zA-Z0-9-]", "_").toLowerCase();
        // Truncate if necessary to avoid exceeding potential DB limits (e.g., 63 chars total)
        int maxRoleNameLength = 63 - USERNAME_PREFIX.length() - USERNAME_RANDOM_SUFFIX_LENGTH - 1; // -1 for hyphen
        if (sanitizedRoleName.length() > maxRoleNameLength) {
            sanitizedRoleName = sanitizedRoleName.substring(0, maxRoleNameLength);
        }

        return USERNAME_PREFIX + sanitizedRoleName + "-" + suffix;
    }

    /**
     * Replaces placeholders in SQL statements.
     * WARNING: This uses simple string replacement. Assumes generated username/password
     * contain only characters safe for direct inclusion in DDL statements.
     *
     * @param statements The list of SQL statements with placeholders.
     * @param username The generated username.
     * @param password The generated password.
     * @return A list of SQL statements with placeholders replaced.
     */
    private List<String> prepareSqlStatements(List<String> statements, String username, String password) {
        // Be cautious with password replacement if it contains single quotes or other special chars
        // The current generatePassword() avoids single quotes, but this is a potential vulnerability point.
        // Using PreparedStatement for DDL is often not possible or practical across different DBs.
        return statements.stream()
                .map(sql -> sql.replace("{{username}}", username)
                        .replace("{{password}}", password))
                .toList();
    }
    // --- END: Helper methods from Task 25 Step 1 ---

    // --- START: Helper method from Task 26 Step 3 ---
    /**
     * Retrieves an active lease by its ID from the in-memory tracker.
     *
     * @param leaseId The UUID of the lease to retrieve.
     * @return An Optional containing the Lease if found, otherwise Optional.empty().
     */
    private Optional<Lease> getLeaseById(UUID leaseId) {
        return Optional.ofNullable(activeLeases.get(leaseId));
    }
    // --- END: Helper method from Task 26 Step 3 ---


    /**
     * Simple check after initialization to verify DB connection using the configured DataSource.
     */
    // ... (@PostConstruct checkDbConnection method remains unchanged) ...
    @PostConstruct
    public void checkDbConnection() {
        log.info("Checking connection to target PostgreSQL database via configured DataSource...");
        try (Connection connection = dataSource.getConnection()) {
            if (connection.isValid(2)) { // Check validity with a 2-second timeout
                String url = connection.getMetaData().getURL();
                String user = connection.getMetaData().getUserName();
                log.info("Successfully established connection to target PostgreSQL database: URL='{}', User='{}'", url, user);
                // Optional: Use jdbcTemplate for a simple query test
                // Integer result = jdbcTemplate.queryForObject("SELECT 1", Integer.class);
                // log.info("Successfully executed test query (SELECT 1) on target database. Result: {}", result);
            } else {
                log.error("Failed to establish a valid connection to the target PostgreSQL database (isValid returned false). Check credentials and DB status.");
                // Consider throwing a specific exception here to prevent startup if connection is mandatory
                // throw new IllegalStateException("Failed to establish valid connection to target PostgreSQL DB.");
            }
        } catch (SQLException e) {
            log.error("Failed to connect to the target PostgreSQL database during startup check: {}. Check URL, credentials, driver, and DB status.", e.getMessage());
            // Log details without full stack trace unless DEBUG is enabled
            log.debug("SQL Exception details:", e);
            // Consider throwing
            // throw new SecretsEngineException("Failed to initialize connection to target PostgreSQL database", e);
        } catch (Exception e) {
            // Catch other potential errors during connection test (e.g., from jdbcTemplate)
            log.error("An unexpected error occurred during database connection check: {}", e.getMessage(), e);
            // Consider throwing
        }
    }


    // --- START: Implementation of generateCredentials from Task 25 Step 2 ---
    @Override
    public Lease generateCredentials(String roleName) throws SecretsEngineException, RoleNotFoundException {
        log.info("Attempting to generate credentials for DB role: {}", roleName);

        // 1. Look up role configuration
        MssmProperties.PostgresRoleDefinition roleDefinition = properties.secrets()
                .db()
                .postgres()
                .roles()
                .get(roleName);

        if (roleDefinition == null) {
            log.warn("Role definition not found for role name: {}", roleName);
            throw new RoleNotFoundException(roleName);
        }
        log.debug("Found role definition for: {}", roleName);

        // 2. Generate unique username and secure password
        String username = generateUsername(roleName);
        String password = generatePassword();
        // DO NOT LOG THE PASSWORD
        log.debug("Generated username: {}", username);

        // 3. Prepare SQL statements by replacing placeholders
        List<String> creationSqlStatements = prepareSqlStatements(
                roleDefinition.creationStatements(),
                username,
                password
        );

        // 4. Execute SQL statements against the target DB
        log.debug("Executing creation SQL statements for role '{}', username '{}'", roleName, username);
        try {
            // Execute each statement. Note: DDL might not be transactional across statements.
            // If one fails, prior ones might have already executed.
            for (String sql : creationSqlStatements) {
                log.trace("Executing SQL: {}", sql); // Log SQL only at TRACE level
                jdbcTemplate.execute(sql);
            }
            log.info("Successfully executed creation SQL for role '{}', username '{}'", roleName, username);
        } catch (DataAccessException e) {
            // Catch Spring's generic DAO exception, which wraps various JDBC exceptions
            log.error("Database error executing creation SQL for role '{}', username '{}': {}",
                    roleName, username, e.getMessage(), e);
            // Attempt cleanup? Difficult with DDL. For now, just report failure.
            // Consider adding logic here later to attempt running revocation statements if creation fails mid-way.
            throw new SecretsEngineException("Failed to execute credential creation SQL for role: " + roleName, e);
        }

        // 5. Create Lease object
        UUID leaseId = UUID.randomUUID();
        Instant creationTime = Instant.now();
        // Use TTL from the role definition
        java.time.Duration ttl = roleDefinition.defaultTtl();

        // Store generated credentials in the lease data map
        Map<String, Object> secretData = new HashMap<>();
        secretData.put("username", username);
        secretData.put("password", password); // Store the password in the lease data

        Lease lease = new Lease(
                leaseId,
                "postgres", // Engine name/type
                roleName,
                secretData,
                creationTime,
                ttl,
                false // Renewable: false for now (implement renewal later if needed)
        );

        activeLeases.put(lease.id(), lease);
        log.debug("Lease {} added to active lease tracker. Current active leases: {}", lease.id(), activeLeases.size());

        logAuditEvent(
                "db_operation",
                "lease_creation",
                "success",
                Map.of(
                        "lease_id", lease.id().toString(),
                        "role_name", roleName
                )
        );

        log.info("Successfully generated credentials and lease for DB role: {}", roleName);
        // 7. Return Lease
        return lease;
    }
    // --- END: Implementation of generateCredentials from Task 25 Step 2 ---


    // --- START: Modification for Task 26 Step 4 (including self-correction) ---
    @Override
    public void revokeLease(UUID leaseId) throws SecretsEngineException, LeaseNotFoundException {
        log.info("Attempting to revoke lease with ID: {}", leaseId);

        // 1. Look up lease details from in-memory map using leaseId (Task 26)
        Lease lease = getLeaseById(leaseId)
                .orElseThrow(() -> {
                    log.warn("Lease not found in active tracker: {}", leaseId);
                    return new LeaseNotFoundException(leaseId);
                });

        String username = (String) lease.secretData().get("username");
        if (username == null) {
            // Should not happen if lease was stored correctly, but handle defensively
            log.error("Cannot revoke lease {}: username missing in lease data.", leaseId);
            // Remove the potentially corrupted lease entry anyway?
            activeLeases.remove(leaseId);
            throw new SecretsEngineException("Internal error: Username not found for lease " + leaseId);
        }
        log.debug("Found lease {} for username '{}'. Proceeding with revocation logic.", leaseId, username);

        // 2. Look up role configuration (revocation SQL) (Task 23)
        MssmProperties.PostgresRoleDefinition roleDefinition = properties.secrets().db().postgres().roles().get(lease.roleName());
        if (roleDefinition == null) {
            // Role might have been removed from config since lease was created. Still try to revoke?
            // Guide suggests throwing an exception here as we need the statements.
            log.error("Role definition '{}' not found for revoking lease {}. Cannot determine revocation SQL.", lease.roleName(), leaseId);
            // Don't remove from map, as we couldn't revoke.
            throw new SecretsEngineException("Role definition '" + lease.roleName() + "' not found, cannot determine revocation SQL for lease " + leaseId);
        }

        // 3. Prepare revocation SQL (using username, no password needed)
        // Note: Using a simplified version of prepareSqlStatements for revocation
        List<String> revocationSqlStatements = roleDefinition.revocationStatements().stream()
                .map(sql -> sql.replace("{{username}}", username))
                .toList();

        // 4. Execute revocation SQL statements using jdbcTemplate
        log.debug("Executing revocation SQL statements for lease '{}', username '{}'", leaseId, username);
        try {
            for (String sql : revocationSqlStatements) {
                log.trace("Executing SQL: {}", sql); // Log SQL only at TRACE level
                jdbcTemplate.execute(sql);
            }
            log.info("Successfully executed revocation SQL for lease '{}', username '{}'", leaseId, username);

            // 5. Remove lease from in-memory map AFTER successful revocation (Task 26)
            activeLeases.remove(leaseId);
            log.info("Successfully revoked and removed lease: {}. Remaining active leases: {}", leaseId, activeLeases.size());

            logAuditEvent(
                    "db_operation",
                    "revoke_lease",
                    "success",
                    Map.of("lease_id", leaseId.toString())
            );

        } catch (DataAccessException e) {
            log.error("Database error executing revocation SQL for lease '{}', username '{}': {}",
                    leaseId, username, e.getMessage(), e);

            logAuditEvent(
                    "db_operation",
                    "revoke_lease",
                    "failure",
                    Map.of(
                            "lease_id", leaseId.toString(),
                            "error", e.getMessage())
            );

            throw new SecretsEngineException("Failed to execute credential revocation SQL for lease: " + leaseId, e);
        }
    }

    private void logAuditEvent(
            String type,
            String action,
            String outcome,
            Map<String, Object> data) {
        try {
            String principal = "system";
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()) {
                principal = authentication.getName();
            }

            AuditEvent.AuthInfo authInfo = AuditEvent.AuthInfo.builder()
                    .principal(principal)
                    .build();

            AuditEvent auditEvent = AuditEvent.builder()
                    .timestamp(Instant.now())
                    .type(type)
                    .action(action)
                    .outcome(outcome)
                    .authInfo(authInfo)
                    .data(data)
                    .build();
            auditBackend.logEvent(auditEvent);
        } catch (Exception e) {
            log.error("Failed to log audit event in PostgresSecretsEngine: {}", e.getMessage(), e);
        }
    }

}