package tech.yump.vault.secrets.db;

import jakarta.annotation.PostConstruct; // For connection test
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate; // Import JdbcTemplate
import org.springframework.stereotype.Service;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.secrets.DynamicSecretsEngine;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.LeaseNotFoundException;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;

import javax.sql.DataSource;
import java.sql.Connection; // For connection test
import java.sql.SQLException; // For connection test
import java.util.UUID;

/**
 * Secrets Engine implementation for dynamically generating PostgreSQL credentials.
 */
@Slf4j
@Service // Register as a Spring Bean
@RequiredArgsConstructor // Creates constructor for final fields (dependency injection)
public class PostgresSecretsEngine implements DynamicSecretsEngine {

    // Dependencies injected via constructor by Lombok's @RequiredArgsConstructor
    private final MssmProperties properties;
    private final DataSource dataSource; // Spring Boot auto-configures this
    private final JdbcTemplate jdbcTemplate; // Spring Boot auto-configures this based on primary DataSource

    // Connection pool is managed by the injected DataSource (HikariCP by default)
    // TODO: Add fields for storing role definitions loaded from properties (Task 23) - maybe cache them?
    // TODO: Add fields for in-memory lease tracking (Task 26)

    /**
     * Simple check after initialization to verify DB connection using the configured DataSource.
     */
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

    @Override
    public Lease generateCredentials(String roleName) throws SecretsEngineException, RoleNotFoundException {
        log.warn("PostgresSecretsEngine.generateCredentials for role '{}' is not yet implemented.", roleName);
        // TODO: Implement credential generation logic (Task 25)
        // 1. Look up role configuration (SQL template, TTL) from properties (Task 23)
        // 2. Generate unique username/password
        // 3. Use injected jdbcTemplate (which uses the DataSource/pool) (Task 24/25)
        // 4. Execute creation SQL statements using jdbcTemplate.execute() or update()
        // 5. Create Lease object
        // 6. Store lease details (in-memory map) (Task 26)
        // 7. Return Lease
        throw new UnsupportedOperationException("generateCredentials not implemented yet");
    }

    @Override
    public void revokeLease(UUID leaseId) throws SecretsEngineException, LeaseNotFoundException {
        log.warn("PostgresSecretsEngine.revokeLease for lease ID '{}' is not yet implemented.", leaseId);
        // TODO: Implement lease revocation logic (Future Task, beyond Phase 3 initial scope)
        // 1. Look up lease details (username) from in-memory map using leaseId (Task 26)
        // 2. Look up role configuration (revocation SQL) (Task 23)
        // 3. Use injected jdbcTemplate (which uses the DataSource/pool) (Task 24/Future)
        // 4. Execute revocation SQL statements using jdbcTemplate.execute() or update()
        // 5. Remove lease from in-memory map (Task 26)
        throw new UnsupportedOperationException("revokeLease not implemented yet");
    }

    // --- Helper methods for DB interaction, password generation etc. will go here ---

}