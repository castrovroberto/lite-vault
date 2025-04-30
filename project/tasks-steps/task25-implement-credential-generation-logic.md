# Task 25: Implement Credential Generation Logic

Okay, let's implement the core logic for Task 25: Implement Credential Generation Logic within the PostgresSecretsEngine.This involves replacing the UnsupportedOperationException in generateCredentials with the actual steps to:1.Look up the role configuration.2.Generate a unique username and a secure password.3.Replace placeholders in the configured SQL statements.4.Execute the SQL statements using JdbcTemplate.5.Create and return a Lease object containing the credentials and metadata.Here's the step-by-step guide:Step 1: Add Helper Methods for Username/Password GenerationWe need utilities to create unique usernames and secure random passwords. Let's add these as private methods within PostgresSecretsEngine.1.Open /Users/robertocastro/dev/lite-vault/src/main/java/tech/yump/vault/secrets/db/PostgresSecretsEngine.java.2.Add the necessary imports:

    import java.security.SecureRandom;
    import java.time.Instant;
    import java.util.HashMap;
    import java.util.List;
    import java.util.Map;
    import java.util.Objects;
    import org.springframework.dao.DataAccessException; // Import Spring DAO exception
    
3.Add the following private helper methods to the class:

    // Inside PostgresSecretsEngine class

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
        return statements.stream()
                .map(sql -> sql.replace("{{username}}", username)
                               .replace("{{password}}", password)) // Be cautious with password replacement if it contains single quotes
                .toList();
    }
    

Step 2: Implement the generateCredentials Method LogicNow, replace the content of the existing generateCredentials method with the actual logic using the helpers and injected dependencies.

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
        secretData.put("password", password);

        Lease lease = new Lease(
                leaseId,
                "postgres", // Engine name/type
                roleName,
                secretData,
                creationTime,
                ttl,
                false // Renewable: false for now (implement renewal later if needed)
        );

        // 6. Store lease details (in-memory map) - TODO in Task 26
        log.debug("Lease created with ID: {}, TTL: {}", lease.id(), lease.ttl());
        // leaseTracker.addLease(lease); // This will be added in Task 26

        log.info("Successfully generated credentials and lease for DB role: {}", roleName);
        // 7. Return Lease
        return lease;
    }

Step 3: Review and Verify1.Imports: Ensure all necessary imports (java.security.SecureRandom, java.time.Instant, java.util.*, org.springframework.dao.DataAccessException, etc.) are present and resolved.2.Placeholders: Double-check that the placeholders {{username}} and {{password}} in your application-dev.yml creationStatements match the strings used in prepareSqlStatements.3.Error Handling: The code now throws RoleNotFoundException if the role isn't configured and SecretsEngineException if database errors occur during SQL execution.4.Password Logging: Verify that the generated password is not logged anywhere.5.Lease Data: Confirm that the Lease object is created with the correct details (ID, role name, generated username/password in secretData, TTL from config).Step 4: Test (Manual/Integration)1.Run the Application: Make sure your target DB is running and configured correctly (Task 23/24).2.Use curl (or similar): Send a request to the API endpoint created in Task 27.

    # Use a token with appropriate permissions (e.g., dev-root-token)
    # Use a role name configured in application-dev.yml (e.g., readonly-app-role)
    TOKEN="dev-root-token"
    ROLE="readonly-app-role"

    curl -k -H "X-Vault-Token: $TOKEN" https://localhost:8443/v1/db/creds/$ROLE
    

3.Expected Result:•You should receive a JSON response similar to this (IDs, password, and exact duration will vary):

        {
          "leaseId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
          "username": "lv-readonly-app-role-a3b1c2d4",
          "password": "GENERATED_SECURE_PASSWORD",
          "leaseDurationSeconds": 3600
        }
        

•Check the LiteVault application logs for messages indicating successful role lookup, SQL execution, and lease creation.•Check the target PostgreSQL database to confirm that the new user (e.g., lv-readonly-app-role-a3b1c2d4) has been created with the expected permissions.4.Test Failure Cases:•Request an unconfigured role -> Expect 404 Not Found.•If the database connection fails or SQL is invalid -> Expect 500 Internal Server Error (check logs for SecretsEngineException).With these steps, the core logic for generating dynamic PostgreSQL credentials is now implemented, completing Task 25. The next step (Task 26) will focus on tracking these generated leases in memory.