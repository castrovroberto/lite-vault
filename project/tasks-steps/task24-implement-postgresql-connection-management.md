# Task 24: Implement PostgreSQL Connection Management

Okay, let's tackle Task 24: Implement PostgreSQL Connection Management.The goal here is to ensure that our PostgresSecretsEngine can successfully connect to the target PostgreSQL database using the configuration we set up in Task 23. We'll leverage Spring Boot's auto-configuration for DataSource (which typically uses HikariCP for connection pooling) by providing the standard spring.datasource.* properties.Strategy:Instead of manually creating a DataSource bean specifically for the PostgresSecretsEngine, we will configure Spring Boot's primary DataSource to connect to the target PostgreSQL database defined in mssm.secrets.db.postgres.*. This is simpler because:1.We added spring-boot-starter-jdbc in Task 22, which enables DataSource auto-configuration.2.Spring Boot will automatically create and manage a connection pool (HikariCP by default).3.Spring Boot will also automatically configure a JdbcTemplate bean, which simplifies executing SQL statements (useful for Task 25).4.Our PostgresSecretsEngine already injects DataSource (from Task 22), so it will receive the auto-configured bean.Important Note: This approach assumes LiteVault itself doesn't need its own separate database for internal state (like persistent lease storage) at this time. If it did, we would need a more complex multi-DataSource configuration. Since Phase 3 uses in-memory lease tracking (Task 26), dedicating the primary DataSource to the target DB is appropriate for now.Here are the steps:Step 1: Configure Spring Boot's Primary DataSource in application-dev.yml

We need to tell Spring Boot's auto-configuration how to connect. We do this using the standard spring.datasource.* properties. These values should mirror the ones you already set under mssm.secrets.db.postgres.*.1.Open /Users/robertocastro/dev/lite-vault/src/main/resources/application-dev.yml.2.Add the following spring.datasource section (or modify it if it exists but was commented out). Make sure the values match your mssm.secrets.db.postgres section.

    # ... (keep server, logging, mssm sections) ...

    # Spring Datasource properties (Used by spring-boot-starter-jdbc for auto-configuration)
    # Configure the PRIMARY DataSource to connect to the TARGET PostgreSQL database
    # where LiteVault will manage dynamic roles.
    spring:
      datasource:
        # These values should match mssm.secrets.db.postgres.*
        url: ${mssm.secrets.db.postgres.connection-url} # Reuse the configured URL
        username: ${mssm.secrets.db.postgres.username} # Reuse the configured admin username
        # !! SECURITY WARNING !! Use the same secure method (env var) as in the mssm section
        password: ${MSSM_DB_POSTGRES_PASSWORD:"defaultpassword"} # Reuse the configured admin password (via env var)
        driver-class-name: org.postgresql.Driver # Specify the driver

        # Optional: Configure HikariCP connection pool properties if needed
        # hikari:
        #   connection-timeout: 30000 # milliseconds
        #   idle-timeout: 600000
        #   max-lifetime: 1800000
        #   maximum-pool-size: 10
        #   minimum-idle: 2
        #   pool-name: LiteVaultPostgresPool

    # ... (keep management section if you have it) ...
    

Explanation:•We explicitly set spring.datasource.url, username, and password using ${...} placeholders to directly reference the values already defined under mssm.secrets.db.postgres. This avoids duplication and ensures consistency.•We set spring.datasource.driver-class-name to org.postgresql.Driver. Spring Boot can often deduce this, but being explicit is good practice.•The commented-out hikari section shows how you could fine-tune the connection pool later if needed. For now, the defaults are usually sufficient.Step 2: Inject JdbcTemplate into PostgresSecretsEngine (Recommended)While you can use the DataSource directly, JdbcTemplate simplifies executing SQL statements, handling connections, and managing exceptions. Spring Boot auto-configures a JdbcTemplate bean based on the primary DataSource.1.Open /Users/robertocastro/dev/lite-vault/src/main/java/tech/yump/vault/secrets/db/PostgresSecretsEngine.java.2.Add JdbcTemplate as a dependency.3.Modify the class to inject JdbcTemplate via the constructor (Lombok's @RequiredArgsConstructor will handle this).

    package tech.yump.vault.secrets.db;

    +import jakarta.annotation.PostConstruct; // For connection test
    import lombok.RequiredArgsConstructor;
    import lombok.extern.slf4j.Slf4j;
    +import org.springframework.jdbc.core.JdbcTemplate; // Import JdbcTemplate
    import org.springframework.stereotype.Service;
    import tech.yump.vault.config.MssmProperties;
    import tech.yump.vault.secrets.DynamicSecretsEngine;
    import tech.yump.vault.secrets.Lease;
    import tech.yump.vault.secrets.LeaseNotFoundException;
    import tech.yump.vault.secrets.RoleNotFoundException;
    import tech.yump.vault.secrets.SecretsEngineException;

    import javax.sql.DataSource;
    +import java.sql.Connection; // For connection test
    +import java.sql.SQLException; // For connection test
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
    +   private final JdbcTemplate jdbcTemplate; // Spring Boot auto-configures this

    -   // TODO: Add fields for connection pool or connection management if not using DataSource directly (Task 24)
    +   // Connection pool is managed by the injected DataSource (HikariCP by default)
        // TODO: Add fields for storing role definitions loaded from properties (Task 23)
        // TODO: Add fields for in-memory lease tracking (Task 26)

    +   /**
    +    * Simple check after initialization to verify DB connection.
    +    */
    +   @PostConstruct
    +   public void checkDbConnection() {
    +       log.info("Checking connection to target PostgreSQL database...");
    +       try (Connection connection = dataSource.getConnection()) {
    +           if (connection.isValid(2)) { // Check validity with a 2-second timeout
    +               log.info("Successfully connected to target PostgreSQL database: {}", connection.getMetaData().getURL());
    +               // Optional: Use jdbcTemplate for a simple query test
    +               // jdbcTemplate.queryForObject("SELECT 1", Integer.class);
    +               // log.info("Successfully executed test query (SELECT 1) on target database.");
    +           } else {
    +               log.error("Failed to establish a valid connection to the target PostgreSQL database (isValid returned false).");
    +               // Consider throwing an exception here to prevent startup if connection is critical
    +           }
    +       } catch (SQLException e) {
    +           log.error("Failed to connect to the target PostgreSQL database: {}", e.getMessage(), e);
    +           // Consider throwing an exception here
    +           // throw new SecretsEngineException("Failed to initialize connection to target PostgreSQL database", e);
    +       } catch (Exception e) {
    +           // Catch other potential errors during connection test (e.g., from jdbcTemplate)
    +           log.error("An unexpected error occurred during database connection check: {}", e.getMessage(), e);
    +           // Consider throwing
    +       }
    +   }
    +
        @Override
        public Lease generateCredentials(String roleName) throws SecretsEngineException, RoleNotFoundException {
            log.warn("PostgresSecretsEngine.generateCredentials for role '{}' is not yet implemented.", roleName);
            // TODO: Implement credential generation logic (Task 25)
            // 1. Look up role configuration (SQL template, TTL) from properties (Task 23)
            // 2. Generate unique username/password
    -       // 3. Get connection from DataSource/pool (Task 24)
    +       // 3. Use injected jdbcTemplate (which uses the DataSource/pool) (Task 24/25)
            // 4. Execute creation SQL
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
    -       // 3. Get connection from DataSource/pool (Task 24)
    +       // 3. Use injected jdbcTemplate (which uses the DataSource/pool) (Task 24/Future)
            // 4. Execute revocation SQL
            // 5. Remove lease from in-memory map (Task 26)
            throw new UnsupportedOperationException("revokeLease not implemented yet");
        }

        // --- Helper methods for DB interaction, password generation etc. will go here ---

    }
    

•We added JdbcTemplate jdbcTemplate as a final field.•We added a @PostConstruct method checkDbConnection which attempts to get a connection from the DataSource and logs success or failure. This helps verify that the configuration in Step 1 is working correctly during application startup.Step 3: Run and Verify1.Ensure Target DB is Running: Make sure your target PostgreSQL database (e.g., klip_db on localhost:5432 based on your application-dev.yml) is running and accessible from where you're running LiteVault.2.Set Environment Variable: Ensure the MSSM_DB_POSTGRES_PASSWORD environment variable is correctly set with the password for your devuser (or configured admin user) in the target database.3.Run the Application: Start LiteVault (mvn spring-boot:run or run the packaged JAR).4.Check Logs: Look for logs indicating:•HikariCP starting up and creating a pool for your target database URL (e.g., HikariDataSource ... - Starting..., ... - Added connection ...).•The log message from our checkDbConnection method:•Success: Successfully connected to target PostgreSQL database: jdbc:postgresql://localhost:5432/klip_db•Failure: Failed to connect... or Failed to establish a valid connection... along with potential error details (e.g., authentication failure, connection refused, database not found).Troubleshooting:•ClassNotFoundException: org.postgresql.Driver: Make sure the postgresql dependency is correctly added in pom.xml (Task 22) and Maven dependencies are refreshed.•Authentication failed: Double-check the username and password (via the environment variable) in application-dev.yml (spring.datasource and mssm.secrets.db.postgres sections) match the actual credentials for the admin user in the target database.•Connection refused: Ensure the database server is running, the hostname/IP and port in the connection-url are correct, and there are no firewall rules blocking the connection.•Database not found: Verify the database name in the connection-url exists on the PostgreSQL server.•HikariCP Errors: Check HikariCP logs for specific pool configuration issues if they arise.Once you see the successful connection message in the logs, Task 24 is complete. The PostgresSecretsEngine is now equipped to interact with the target database using a managed connection pool. The next step (Task 25) will use the injected JdbcTemplate to execute the SQL defined in the role configurations.