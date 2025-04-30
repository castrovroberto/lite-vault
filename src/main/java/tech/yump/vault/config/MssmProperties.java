package tech.yump.vault.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import tech.yump.vault.auth.policy.PolicyDefinition;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Configuration properties for the MSSM application under the 'mssm' prefix.
 */
@ConfigurationProperties(prefix = "mssm")
@Validated
public record MssmProperties(

        @Valid
        @NotNull
        MasterKeyProperties master,

        @Valid
        @NotNull
        StorageProperties storage,

        @Valid
        AuthProperties auth,

        @NotEmpty
        @Valid
        List<PolicyDefinition> policies,

        @Valid // Add validation for the new secrets section
        SecretsProperties secrets // Add the new top-level secrets property
) {
    @Validated
    public record MasterKeyProperties(
            @NotBlank(message = "Master key (mssm.master.b64) must be provided.")
            String b64
    ) {}

    @Validated
    public record StorageProperties(
            @Valid
            @NotNull
            FileSystemProperties filesystem
    ) {
        @Validated
        public record FileSystemProperties(
                @NotBlank(message = "Filesystem storage path (mssm.storage.filesystem.path) must be provided.")
                String path
        ) {}
    }

    @Validated
    public record AuthProperties (
            @Valid
            // Removed @NotNull as staticTokens might be optional if auth is disabled,
            // but keep @Valid to validate if present.
            StaticTokenAuthProperties staticTokens
    ) {

        @Validated
        public record StaticTokenPolicyMapping(
                @NotBlank(message = "Static token value cannot be blank")
                String token,

                @NotEmpty(message = "Token must be associated with at least one policy name")
                List<String> policyNames // List of policy names (strings) assigned to this token
        ) {}

        /**
         * Properties specific to static token authentication.
         * Validation ensures mappings are present if enabled.
         */
        @Validated
        public record StaticTokenAuthProperties (
                boolean enabled,

                // Conditionally validate mappings: only required if enabled=true
                // This requires custom validation logic or careful handling in service layer
                // For simplicity with @ConfigurationProperties, we mark it @Valid
                // and rely on @NotEmpty if enabled=true check elsewhere or accept empty list if disabled.
                // Let's keep @NotEmpty for now, assuming enabled=true implies mappings must exist.
                @NotEmpty(message = "Static token mappings (mssm.auth.static-tokens.mappings) cannot be empty when static token auth is enabled.")
                @Valid
                List<StaticTokenPolicyMapping> mappings
        ) {
            // Default constructor logic to handle null list from YAML if section exists but is empty
            public StaticTokenAuthProperties {
                if (mappings == null) {
                    mappings = Collections.emptyList();
                }
            }
        }
    }

    // --- NEW: Secrets Engine Configuration ---
    @Validated // Add validation to the secrets properties container
    public record SecretsProperties(
            @Valid // Validate the nested db properties if present
            DbSecretsProperties db
    ) {}

    @Validated // Add validation to the db properties container
    public record DbSecretsProperties(
            @Valid // Validate the nested postgres properties if present
            PostgresProperties postgres
    ) {}

    /**
     * Configuration properties for the PostgreSQL dynamic secrets engine.
     * Prefix: mssm.secrets.db.postgres
     */
    @Validated // Add validation to the postgres properties
    public record PostgresProperties(
            @NotBlank(message = "PostgreSQL connection URL (mssm.secrets.db.postgres.connection-url) must be provided.")
            String connectionUrl, // JDBC URL for the target database

            @NotBlank(message = "PostgreSQL admin username (mssm.secrets.db.postgres.username) must be provided.")
            String username, // Admin username LiteVault uses to connect

            @NotBlank(message = "PostgreSQL admin password (mssm.secrets.db.postgres.password) must be provided.")
            String password, // Admin password LiteVault uses (use env var!)

            @NotEmpty(message = "At least one PostgreSQL role definition (mssm.secrets.db.postgres.roles) must be provided.")
            @Valid // Validate the map values (PostgresRoleDefinition)
            Map<String, PostgresRoleDefinition> roles // Map of role_name -> definition
    ) {}

    /**
     * Defines a specific role configuration for the PostgreSQL secrets engine.
     */
    @Validated // Add validation to the role definition
    public record PostgresRoleDefinition(
            @NotEmpty(message = "Creation statements cannot be empty for a PostgreSQL role.")
            List<String> creationStatements, // SQL statements to create user/grant perms
            // Use {{username}} and {{password}} placeholders

            @NotEmpty(message = "Revocation statements cannot be empty for a PostgreSQL role.")
            List<String> revocationStatements, // SQL statements to revoke/drop user
            // Use {{username}} placeholder

            @NotNull(message = "Default TTL cannot be null for a PostgreSQL role.")
            Duration defaultTtl // Default lease duration for this role (e.g., PT1H)
    ) {}
    // --- End of NEW Secrets Engine Configuration ---
}