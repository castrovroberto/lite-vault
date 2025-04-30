package tech.yump.vault.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue; // Import AssertTrue
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import tech.yump.vault.auth.policy.PolicyDefinition;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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

        @NotEmpty // Keep this for the top-level policies list
        @Valid
        List<PolicyDefinition> policies,

        @Valid
        SecretsProperties secrets
) {
    // MasterKeyProperties, StorageProperties remain unchanged
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
            StaticTokenAuthProperties staticTokens
    ) {

        // StaticTokenPolicyMapping remains unchanged
        @Validated
        public record StaticTokenPolicyMapping(
                @NotBlank(message = "Static token value cannot be blank")
                String token,

                @NotEmpty(message = "Token must be associated with at least one policy name")
                List<String> policyNames
        ) {}

        /**
         * Properties specific to static token authentication.
         * Validation ensures mappings are present if enabled.
         */
        @Validated
        public record StaticTokenAuthProperties (
                boolean enabled,

                @Valid
                List<StaticTokenPolicyMapping> mappings
        ) {
            // Default constructor logic remains the same
            public StaticTokenAuthProperties {
                if (mappings == null) {
                    mappings = Collections.emptyList();
                }
            }

            @AssertTrue(message = "Static token mappings (mssm.auth.static-tokens.mappings) cannot be empty when static token auth is enabled.")
            public boolean isMappingsValid() {
                // If auth is NOT enabled, mappings can be anything (valid).
                // If auth IS enabled, mappings must NOT be null AND must NOT be empty.
                // (The constructor ensures mappings is not null, but check is harmless)
                return !this.enabled() || (this.mappings() != null && !this.mappings().isEmpty());
            }
        }
    }

    @Validated
    public record SecretsProperties(
            @Valid
            DbSecretsProperties db
    ) {}

    @Validated
    public record DbSecretsProperties(
            @Valid
            PostgresProperties postgres
    ) {}

    @Validated
    public record PostgresProperties(
            @NotBlank(message = "PostgreSQL connection URL (mssm.secrets.db.postgres.connection-url) must be provided.")
            String connectionUrl,

            @NotBlank(message = "PostgreSQL admin username (mssm.secrets.db.postgres.username) must be provided.")
            String username,

            @NotNull(message = "PostgreSQL admin password (mssm.secrets.db.postgres.password) must be provided and cannot be null.") // Changed from @NotBlank
            char[] password,

            @NotEmpty(message = "At least one PostgreSQL role definition (mssm.secrets.db.postgres.roles) must be provided.")
            @Valid
            Map<String, PostgresRoleDefinition> roles
    ) {
        @AssertTrue(message = "PostgreSQL admin password (mssm.secrets.db.postgres.password) must not be empty.")
        private boolean isPasswordNotEmpty() {
            return password != null && password.length > 0;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PostgresProperties that = (PostgresProperties) o;
            return Objects.equals(connectionUrl, that.connectionUrl) &&
                    Objects.equals(username, that.username) &&
                    Arrays.equals(password, that.password) &&
                    Objects.equals(roles, that.roles);
        }

        @Override
        public int hashCode() {
            int result = Objects.hash(connectionUrl, username, roles);
            result = 31 * result + Arrays.hashCode(password);
            return result;
        }

        @Override
        public String toString() {
            // Avoid logging the password in toString()
            return "PostgresProperties[" +
                    "connectionUrl='" + connectionUrl + '\'' +
                    ", username='" + username + '\'' +
                    ", password=******" +
                    ", roles=" + roles +
                    ']';
        }
    }

    @Validated
    public record PostgresRoleDefinition(
            @NotEmpty(message = "Creation statements cannot be empty for a PostgreSQL role.")
            List<String> creationStatements,

            @NotEmpty(message = "Revocation statements cannot be empty for a PostgreSQL role.")
            List<String> revocationStatements,

            @NotNull(message = "Default TTL cannot be null for a PostgreSQL role.")
            Duration defaultTtl
    ) {}
}