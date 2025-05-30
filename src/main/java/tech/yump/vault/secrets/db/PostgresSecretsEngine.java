package tech.yump.vault.secrets.db;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.core.SealManager;
import tech.yump.vault.core.VaultSealedException;
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
import java.util.concurrent.ConcurrentHashMap;

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
    private final AuditHelper auditHelper;
    private final SealManager sealManager;

    // Store leases using UUID as key
    private final ConcurrentHashMap<UUID, Lease> activeLeases = new ConcurrentHashMap<>();

    // --- Helper methods (generatePassword, generateUsername, prepareSqlStatements) ---
    private static final String ALLOWED_PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    static final int DEFAULT_PASSWORD_LENGTH = 32;
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
     */
    private String generateUsername(String roleName) {
        StringBuilder suffix = new StringBuilder(USERNAME_RANDOM_SUFFIX_LENGTH);
        for (int i = 0; i < USERNAME_RANDOM_SUFFIX_LENGTH; i++) {
            int index = random.nextInt(ALLOWED_USERNAME_SUFFIX_CHARS.length());
            suffix.append(ALLOWED_USERNAME_SUFFIX_CHARS.charAt(index));
        }
        // Sanitize role name: replace non-alphanumeric/hyphen with underscore, lowercase
        String sanitizedRoleName = roleName.replaceAll("[^a-zA-Z0-9-]", "_").toLowerCase();
        // Ensure username length doesn't exceed PostgreSQL limit (default 63)
        int maxRoleNameLength = 63 - USERNAME_PREFIX.length() - USERNAME_RANDOM_SUFFIX_LENGTH - 1; // -1 for the hyphen
        if (sanitizedRoleName.length() > maxRoleNameLength) {
            sanitizedRoleName = sanitizedRoleName.substring(0, maxRoleNameLength);
        }
        return USERNAME_PREFIX + sanitizedRoleName + "-" + suffix;
    }

    /**
     * Replaces placeholders in SQL statements.
     * Uses quoting for username and escaping for password.
     */
    private List<String> prepareSqlStatements(
            List<String> statements,
            String username,
            String password) {
        String quotedUsername = quotePostgresIdentifier(username);
        // Password should be escaped for string literal context ('password')
        String escapedPassword = escapePostgresStringLiteral(password);

        return statements.stream()
                .map(sql -> sql.replace("{{username}}", quotedUsername)
                        .replace("{{password}}", escapedPassword)) // Use escaped password
                .toList();
    }

    /**
     * Retrieves an active lease by its ID from the in-memory tracker.
     */
    private Optional<Lease> getLeaseById(UUID leaseId) {
        return Optional.ofNullable(activeLeases.get(leaseId));
    }

    /**
     * Simple check after initialization to verify DB connection using the configured DataSource.
     */
    @PostConstruct
    public void checkDbConnection() {
        log.info("Checking connection to target PostgreSQL database via configured DataSource...");
        try (Connection connection = dataSource.getConnection()) {
            if (connection.isValid(2)) {
                String url = connection.getMetaData().getURL();
                String user = connection.getMetaData().getUserName();
                log.info("Successfully established connection to target PostgreSQL database: URL='{}', User='{}'", url, user);
            } else {
                log.error("Failed to establish a valid connection to the target PostgreSQL database (isValid returned false). Check credentials and DB status.");
            }
        } catch (SQLException e) {
            log.error("Failed to connect to the target PostgreSQL database during startup check: {}. Check URL, credentials, driver, and DB status.", e.getMessage());
            // Log stack trace only at DEBUG level to avoid excessive logging
            log.debug("SQL Exception details:", e);
        } catch (Exception e) {
            // Catch broader exceptions during startup check
            log.error("An unexpected error occurred during database connection check: {}", e.getMessage(), e);
        }
    }

    @Override
    public Lease generateCredentials(String roleName) throws SecretsEngineException, RoleNotFoundException {
        if (sealManager.isSealed()) {
            log.warn("Cannot generate DB credentials for role '{}': Vault is sealed.", roleName);
            throw new VaultSealedException("Vault is sealed");
        }

        log.info("Attempting to generate credentials for DB role: {}", roleName);

        MssmProperties.PostgresRoleDefinition roleDefinition = properties.secrets()
                .db()
                .postgres()
                .roles()
                .get(roleName);

        if (roleDefinition == null) {
            log.warn("Role definition not found for role name: {}", roleName);
            // Audit this specific failure? Maybe not needed as RoleNotFoundException is specific.
            throw new RoleNotFoundException(roleName);
        }
        log.debug("Found role definition for: {}", roleName);

        String username = generateUsername(roleName);
        String password = generatePassword();
        log.debug("Generated username: {}", username);

        List<String> creationSqlStatements = prepareSqlStatements(
                roleDefinition.creationStatements(),
                username,
                password
        );

        log.debug("Executing creation SQL statements for role '{}', username '{}'", roleName, username);
        try {
            for (String sql : creationSqlStatements) {
                log.trace("Executing SQL: {}", sql); // Use trace for potentially sensitive SQL
                jdbcTemplate.execute(sql);
            }
            log.info("Successfully executed creation SQL for role '{}', username '{}'", roleName, username);
        } catch (DataAccessException e) {
            log.error("Database error executing creation SQL for role '{}', username '{}': {}",
                    roleName, username, e.getMessage(), e);
            // Audit failure? Handled by caller/exception handler usually.
            throw new SecretsEngineException("Failed to execute credential creation SQL for role: " + roleName, e);
        }

        UUID leaseId = UUID.randomUUID();
        Instant creationTime = Instant.now();
        java.time.Duration ttl = roleDefinition.defaultTtl();

        Map<String, Object> secretData = new HashMap<>();
        secretData.put("username", username);
        secretData.put("password", password);

        Lease lease = new Lease(
                leaseId,
                "postgres", // Engine type/path prefix
                roleName,
                secretData,
                creationTime,
                ttl,
                false // Not renewable by default
        );

        activeLeases.put(lease.id(), lease);
        log.debug("Lease {} added to active lease tracker. Current active leases: {}", lease.id(), activeLeases.size());

        // Use AuditHelper for internal event
        auditHelper.logInternalEvent(
                "db_operation", // type
                "generate_credentials", // action
                "success", // outcome
                null, // principal (will be derived from SecurityContext or default to "system")
                Map.of( // data
                        "lease_id", lease.id().toString(),
                        "role_name", roleName,
                        "username", username // Include username for traceability
                )
        );

        log.info("Successfully generated credentials and lease for DB role: {}", roleName);
        return lease;
    }

    @Override
    public void revokeLease(UUID leaseId) throws SecretsEngineException, LeaseNotFoundException {
        log.info("Attempting to revoke lease with ID: {}", leaseId);

        // 1. Lease Existence Check & Audit
        Lease lease = getLeaseById(leaseId)
                .orElseThrow(() -> {
                    log.warn("Lease not found in active tracker: {}", leaseId);
                    // Audit "Lease not found" failure
                    auditHelper.logInternalEvent(
                            "db_operation",
                            "revoke_lease",
                            "failure",
                            null, // Principal from context or "system"
                            Map.of(
                                    "lease_id", leaseId.toString(),
                                    "reason", "Lease not found"
                            )
                    );
                    return new LeaseNotFoundException(leaseId);
                });

        String username = (String) lease.secretData().get("username");
        if (username == null) {
            // This indicates an internal inconsistency if a lease exists without a username
            log.error("Cannot revoke lease {}: username missing in lease data. Removing lease entry.", leaseId);
            activeLeases.remove(leaseId); // Remove inconsistent lease entry
            auditHelper.logInternalEvent(
                    "db_operation",
                    "revoke_lease",
                    "failure",
                    null,
                    Map.of(
                            "lease_id", leaseId.toString(),
                            "reason", "Internal error: Username missing in lease data"
                    )
            );
            throw new SecretsEngineException("Internal error: Username not found for lease " + leaseId);
        }
        log.debug("Found lease {} for username '{}'. Proceeding with revocation logic.", leaseId, username);

        // 2. Role Definition Retrieval & Audit
        MssmProperties.PostgresRoleDefinition roleDefinition = properties.secrets().db().postgres().roles().get(lease.roleName());
        if (roleDefinition == null) {
            log.error("Role definition '{}' not found for revoking lease {}. Cannot determine revocation SQL. Lease entry will NOT be removed.", lease.roleName(), leaseId);
            // Audit "Role definition missing" failure
            auditHelper.logInternalEvent(
                    "db_operation",
                    "revoke_lease",
                    "failure",
                    null, // Principal from context or "system"
                    Map.of(
                            "lease_id", leaseId.toString(),
                            "role_name", lease.roleName(),
                            "username", username,
                            "reason", "Role definition missing"
                    )
            );
            // Do NOT remove the lease from activeLeases here, as we couldn't perform DB cleanup.
            // An admin might need to manually clean up the DB role later.
            throw new SecretsEngineException("Role definition '" + lease.roleName() + "' not found, cannot determine revocation SQL for lease " + leaseId);
        }

        // 3. Revocation Statements Processing
        List<String> revocationStmts = roleDefinition.revocationStatements();
        if (revocationStmts == null || revocationStmts.isEmpty()) {
            log.warn("No revocation statements found for role '{}', lease '{}'. Lease entry will be removed, but no DB actions taken.", lease.roleName(), leaseId);
            // Proceed to remove lease from map, as no DB action is configured/needed.
            activeLeases.remove(leaseId);
            log.info("Successfully removed lease {} (no DB revocation statements configured). Remaining active leases: {}", leaseId, activeLeases.size());
            // Audit success (as configured action was completed - i.e., nothing)
            auditHelper.logInternalEvent(
                    "db_operation",
                    "revoke_lease",
                    "success",
                    null,
                    Map.of(
                            "lease_id", leaseId.toString(),
                            "role_name", lease.roleName(),
                            "username", username,
                            "detail", "No revocation statements configured"
                    )
            );
            return; // Exit early
        }

        // 4. Placeholder Replacement & Quoting
        String quotedUsername = quotePostgresIdentifier(username);
        List<String> revocationSqlStatements = revocationStmts.stream()
                .map(sql -> sql.replace("{{username}}", quotedUsername))
                .toList();

        log.debug("Executing revocation SQL statements for lease '{}', username '{}'", leaseId, username);
        try {
            // 5. SQL Execution (Non-transactional loop)
            for (String sql : revocationSqlStatements) {
                log.trace("Executing SQL: {}", sql);
                jdbcTemplate.execute(sql);
            }
            log.info("Successfully executed revocation SQL for lease '{}', username '{}'", leaseId, username);

            // 7. Lease Removal (Only after successful SQL execution)
            activeLeases.remove(leaseId);
            log.info("Successfully revoked and removed lease: {}. Remaining active leases: {}", leaseId, activeLeases.size());

            // 8. Auditing (Success)
            auditHelper.logInternalEvent(
                    "db_operation",
                    "revoke_lease",
                    "success",
                    null, // Principal from context or "system"
                    Map.of(
                            "lease_id", leaseId.toString(),
                            "role_name", lease.roleName(),
                            "username", username
                    )
            );

        } catch (DataAccessException e) {
            // 6. Error Handling (Database) & Auditing
            log.error("Database error executing revocation SQL for lease '{}', username '{}': {}",
                    leaseId, username, e.getMessage(), e);

            // Audit database failure
            auditHelper.logInternalEvent(
                    "db_operation",
                    "revoke_lease",
                    "failure",
                    null, // Principal from context or "system"
                    Map.of(
                            "lease_id", leaseId.toString(),
                            "role_name", lease.roleName(),
                            "username", username,
                            "reason", "Database error during revocation",
                            "error", e.getMessage()
                    )
            );
            // Do NOT remove the lease from activeLeases here, as DB cleanup failed.
            throw new SecretsEngineException("Failed to execute credential revocation SQL for lease: " + leaseId, e);
        }
    }

    /**
     * Quotes a PostgreSQL identifier (like a username) correctly.
     * Handles embedded double quotes and wraps the result in double quotes.
     * Example: my"User -> "my""User"
     * Example: my_user -> "my_user" (quoting is safe even if not strictly needed)
     *
     * @param identifier The identifier to quote.
     * @return The safely quoted identifier, ready for insertion into SQL. Returns `""` if identifier is null.
     */
    String quotePostgresIdentifier(String identifier) {
        if (identifier == null) {
            log.warn("Attempted to quote a null identifier. Returning empty quoted string \"\".");
            return "\"\""; // Return valid empty quoted identifier
        }
        // Replace all occurrences of " with ""
        String escapedIdentifier = identifier.replace("\"", "\"\"");
        // Wrap in double quotes
        return "\"" + escapedIdentifier + "\"";
    }

    /**
     * Escapes a string literal for safe inclusion within single quotes in PostgreSQL SQL.
     * Handles embedded single quotes by doubling them.
     * Example: pass'word -> pass''word
     *
     * @param value The string value to escape.
     * @return The safely escaped string, ready for insertion within single quotes ('...') in SQL. Returns empty string '' if value is null.
     */
    String escapePostgresStringLiteral(String value) {
        if (value == null) {
            // Represent null password as empty string in SQL context? Or handle differently?
            // Returning empty string is safer than returning SQL NULL literal here.
            log.warn("Attempted to escape a null string literal (likely password). Returning empty string ''.");
            return "";
        }
        // Replace all occurrences of ' with ''
        return value.replace("'", "''");
    }

}