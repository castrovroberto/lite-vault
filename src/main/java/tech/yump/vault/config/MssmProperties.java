package tech.yump.vault.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;
import tech.yump.vault.auth.policy.PolicyDefinition;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Configuration properties for the MSSM application under the 'mssm' prefix.
 */
@ConfigurationProperties(prefix = "mssm")
@Validated
public record MssmProperties(

        @Valid
        @NotNull(message = "Master key configuration (mssm.master) is required.")
        MasterKeyProperties master,

        @Valid
        @NotNull(message = "Storage configuration (mssm.storage) is required.")
        StorageProperties storage,

        @Valid
        AuthProperties auth,

        @NotEmpty(message = "At least one policy definition (mssm.policies) must be provided.")
        @Valid
        List<PolicyDefinition> policies,

        @Valid
        SecretsProperties secrets
) {
    // --- MasterKeyProperties ---
    @Validated
    public record MasterKeyProperties(
            @NotBlank(message = "Master key (mssm.master.b64) must be provided.")
            String b64
    ) {}

    // --- StorageProperties ---
    @Validated
    public record StorageProperties(
            @Valid
            @NotNull(message = "Filesystem storage configuration (mssm.storage.filesystem) is required.")
            FileSystemProperties filesystem
    ) {
        // --- FileSystemProperties ---
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
                return !this.enabled() || (this.mappings() != null && !this.mappings().isEmpty());
            }
        }
    }

    @Validated
    public record SecretsProperties(
            @Valid
            DbSecretsProperties db,

            @Valid
            JwtProperties jwt
    ) {}

    @Validated
    public record DbSecretsProperties(
            @NotNull(message = "PostgreSQL secrets configuration (mssm.secrets.db.postgres) is required when 'mssm.secrets.db' is present.")
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

    /**
     * Top-level configuration for JWT secrets engine.
     */
    @Validated
    public record JwtProperties(
            @NotEmpty(message = "At least one JWT key definition (mssm.jwt.keys) must be provided if 'mssm.jwt' section is present.")
            @Valid
            Map<String, JwtKeyDefinition> keys
    ) {}

    /**
     * Defines the type of a JWT signing key.
     */
    public enum JwtKeyType {
        RSA, EC
    }

    /**
     * Defines the configuration for a specific named JWT signing key.
     */
    @Validated
    public record JwtKeyDefinition(
            @NotNull(message = "Key type (type: RSA or EC) must be specified.")
            JwtKeyType type,

            // RSA specific
            @Min(value = 2048, message = "RSA key size must be at least 2048 bits.")
            Integer size, // Optional, validated conditionally

            // EC specific
            String curve, // Optional, validated conditionally

            // Common
            Duration rotationPeriod // Optional, e.g., "30d", "PT720H"
    ) {
        private static final Set<String> ALLOWED_EC_CURVES = Set.of("P-256", "P-384", "P-521");

        @AssertTrue(message = "RSA keys must specify a 'size' (>= 2048) and must not specify a 'curve'.")
        private boolean isRsaConfigValid() {
            if (type == JwtKeyType.RSA) {
                return size != null && size >= 2048 && !StringUtils.hasText(curve);
            }
            return true;
        }

        @AssertTrue(message = "EC keys must specify a valid 'curve' (P-256, P-384, P-521) and must not specify a 'size'.")
        private boolean isEcConfigValid() {
            if (type == JwtKeyType.EC) {
                return StringUtils.hasText(curve) && ALLOWED_EC_CURVES.contains(curve) && size == null;
            }
            return true; // Skip if not EC
        }
    }
}