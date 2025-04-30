# Task 23: Configure PostgreSQL Engine via Properties

```
Okay, let's move on to Task 23: Configure PostgreSQL Engine via Properties.This task involves updating our type-safe configuration (MssmProperties) and the example application-dev.yml file to include settings needed by the PostgresSecretsEngine. This includes the connection details for the target PostgreSQL database (where LiteVault will manage users) and the definitions for different roles (SQL statements, TTLs).Here's a step-by-step guide:Step 1: Define Configuration Structure in MssmProperties.javaWe need to add nested classes/records within MssmProperties to represent the configuration structure under mssm.secrets.db.postgres.1.Open /Users/robertocastro/dev/lite-vault/src/main/java/tech/yump/vault/config/MssmProperties.java.2.Add the necessary imports:

    import jakarta.validation.Valid;
    import jakarta.validation.constraints.NotBlank;
    import jakarta.validation.constraints.NotEmpty;
    import jakarta.validation.constraints.NotNull;
    import java.time.Duration;
    import java.util.List;
    import java.util.Map;
    

3.Add a new top-level record/class to hold secrets engine configurations. Let's call it SecretsProperties. Add a field of this type to the main MssmProperties record.4.Inside SecretsProperties, add a record/class for database secrets, DbSecretsProperties.5.Inside DbSecretsProperties, add a record/class specifically for PostgreSQL, PostgresProperties.6.Inside PostgresProperties, define fields for connection details (connectionUrl, username, password) and a map for role definitions.7.Define a nested record PostgresRoleDefinition to hold the details for each role (creationStatements, revocationStatements, defaultTtl).

Here's the combined structure to add/modify within MssmProperties.java:

package tech.yump.vault.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import tech.yump.vault.auth.policy.PolicyDefinition; // Keep existing imports

// Add other existing imports like StaticTokenAuthProperties, StorageProperties etc.
import tech.yump.vault.config.MssmProperties.AuthProperties.StaticTokenAuthProperties;
import tech.yump.vault.config.MssmProperties.StorageProperties.FileSystemStorageProperties;


/**
 * Type-safe configuration properties for the MSSM application, loaded from application.yml/properties.
 * Root prefix: "mssm"
 */
@ConfigurationProperties(prefix = "mssm")
@Validated // Enable validation on this root object and its nested properties
public record MssmProperties(
    @NotNull @Valid MasterKeyProperties master,
    @NotNull @Valid StorageProperties storage,
    @Valid AuthProperties auth, // Keep existing auth properties
    @NotEmpty @Valid List<PolicyDefinition> policies, // Keep existing policies
    @Valid SecretsProperties secrets // Add new secrets engine properties
) {

    // --- Keep existing nested records/classes ---
    public record MasterKeyProperties(@NotBlank String b64) {}

    public record StorageProperties(@NotNull @Valid FileSystemStorageProperties filesystem) {
        public record FileSystemStorageProperties(@NotBlank String path) {}
    }

    public record AuthProperties(@Valid StaticTokenAuthProperties staticTokens) {
        // Keep existing StaticTokenAuthProperties definition
        public record StaticTokenAuthProperties(
            boolean enabled,
            @Valid // Validate the list elements if enabled=true (handled by custom validator or logic)
            List<StaticTokenPolicyMapping> mappings
        ) {}

        // Keep existing StaticTokenPolicyMapping definition
        public record StaticTokenPolicyMapping(
            @NotBlank String token,
            @NotEmpty List<String> policyNames
        ) {}
    }
    // --- End of existing nested records/classes ---


    // --- NEW: Secrets Engine Configuration ---
    public record SecretsProperties(
        @Valid DbSecretsProperties db // Add configuration for DB secrets engines
    ) {}

    public record DbSecretsProperties(
        @Valid PostgresProperties postgres // Configuration specific to PostgreSQL
    ) {}

    /**
     * Configuration properties for the PostgreSQL dynamic secrets engine.
     * Prefix: mssm.secrets.db.postgres
     */
    public record PostgresProperties(
        @NotBlank String connectionUrl, // JDBC URL for the target database
        @NotBlank String username, // Admin username LiteVault uses to connect
        @NotBlank String password, // Admin password LiteVault uses (use env var!)
        @NotEmpty @Valid Map<String, PostgresRoleDefinition> roles // Map of role_name -> definition
    ) {}

    /**
     * Defines a specific role configuration for the PostgreSQL secrets engine.
     */
    public record PostgresRoleDefinition(
        @NotEmpty List<String> creationStatements, // SQL statements to create user/grant perms
                                                   // Use {{username}} and {{password}} placeholders
        @NotEmpty List<String> revocationStatements, // SQL statements to revoke/drop user
                                                     // Use {{username}} placeholder
        @NotNull Duration defaultTtl // Default lease duration for this role
    ) {}
    // --- End of NEW Secrets Engine Configuration ---

}

Explanation of New Parts:•SecretsProperties, DbSecretsProperties, PostgresProperties: Create a clear hierarchy mssm.secrets.db.postgres.•PostgresProperties:•connectionUrl, username, password: Standard JDBC connection details for LiteVault to connect to the target PostgreSQL database with administrative privileges (to create/drop roles). The password here is highly sensitive.•roles: A Map where the key is the logical roleName (e.g., "readonly-app", "migrations-user") that clients will request via the API, and the value is the PostgresRoleDefinition containing the SQL and TTL for that role.•PostgresRoleDefinition:•creationStatements: A List<String> containing one or more SQL statements executed to create a dynamic user. Placeholders {{username}} and {{password}} will be replaced by the engine with generated values. Using a list allows multi-step setup (e.g., CREATE ROLE, then GRANT).•revocationStatements: A List<String> containing SQL statements to clean up (e.g., DROP ROLE). Uses the {{username}} placeholder.•defaultTtl: The default lease duration (e.g., "PT1H" for 1 hour, "PT15M" for 15 minutes) for credentials generated using this role.•Validation Annotations: @NotBlank, @NotEmpty, @NotNull, and @Valid are used to ensure required configuration is provided and that nested objects/maps are also validated.Step 2: Update application-dev.ymlAdd the new configuration section with example values.1.Open /Users/robertocastro/dev/lite-vault/src/main/resources/application-dev.yml.2.Append the following section (adjust example values as needed):

    mssm:
      # ... (keep existing master, storage, policies, auth sections) ...

      secrets: # New top-level section for secrets engines
        db:
          postgres:
            # Connection details for LiteVault to connect to the TARGET PostgreSQL DB
            # This user needs privileges to CREATE/DROP ROLE and GRANT permissions.
            connection-url: "jdbc:postgresql://localhost:5432/target_db" # Example URL
            username: "litevault_admin" # Example admin user LiteVault will use
            # !! SECURITY WARNING !!
            # DO NOT hardcode the password here in production. Use environment variables.
            password: ${MSSM_DB_POSTGRES_PASSWORD:"defaultpassword"} # Example using env var with default

            # Role definitions: Map role names (used in API) to SQL statements and TTL
            roles:
              "readonly-app-role": # Logical name for the role requested via API
                # SQL statements to create the dynamic user.
                # Placeholders {{username}} and {{password}} will be replaced.
                creation-statements:
                  - "CREATE ROLE \"{{username}}\" WITH LOGIN PASSWORD '{{password}}';"
                  - "GRANT CONNECT ON DATABASE target_db TO \"{{username}}\";"
                  - "GRANT USAGE ON SCHEMA public TO \"{{username}}\";"
                  - "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{username}}\";"
                  # Add more GRANTs as needed for specific tables/schemas
                # SQL statements to revoke/clean up the dynamic user.
                # Placeholder {{username}} will be replaced.
                revocation-statements:
                  - "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"{{username}}\";" # Example cleanup
                  - "REVOKE USAGE ON SCHEMA public FROM \"{{username}}\";"
                  - "REVOKE CONNECT ON DATABASE target_db FROM \"{{username}}\";"
                  - "DROP ROLE IF EXISTS \"{{username}}\";"
                # Default lease duration for credentials generated with this role
                default-ttl: PT1H # 1 hour (ISO-8601 duration format)

              "migrations-role": # Another example role
                creation-statements:
                  - "CREATE ROLE \"{{username}}\" WITH LOGIN PASSWORD '{{password}}';"
                  - "GRANT CONNECT ON DATABASE target_db TO \"{{username}}\";"
                  - "GRANT ALL PRIVILEGES ON SCHEMA public TO \"{{username}}\";" # More permissive
                  - "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO \"{{username}}\";"
                  - "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO \"{{username}}\";"
                revocation-statements:
                  - "DROP ROLE IF EXISTS \"{{username}}\";" # Simpler cleanup might be okay sometimes
                default-ttl: PT15M # 15 minutes
    

Step 3: Security Consideration - Admin Password•Crucially, the mssm.secrets.db.postgres.password is the password for a privileged user in the target database.•Never hardcode this password directly in application.yml for production or shared environments.•The example uses ${MSSM_DB_POSTGRES_PASSWORD:"defaultpassword"}. This attempts to read the password from an environment variable MSSM_DB_POSTGRES_PASSWORD and falls back to "defaultpassword" only if the environment variable is not set (useful for local dev, but remove the default for production).•Ensure the mechanism for providing this password aligns with your deployment security practices (e.g., environment variables, Kubernetes secrets, etc.).Step 4: Verify Configuration Loading1.Ensure your project compiles (mvn clean compile).2.Run the application. Check the startup logs. If there are configuration binding errors (e.g., BindException, validation errors), they will usually appear early in the logs, indicating a mismatch between MssmProperties.java and application-dev.yml or missing required properties. Fix any reported errors.With these steps, you have successfully defined the configuration structure for the PostgreSQL secrets engine and provided example settings. The PostgresSecretsEngine (implemented in Task 22) can now be updated in subsequent tasks (like Task 25) to read this configuration from the injected MssmProperties object and use it to connect to the database and execute the appropriate SQL. Task 23 is complete.
```