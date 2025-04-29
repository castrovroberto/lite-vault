package tech.yump.vault.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import tech.yump.vault.auth.policy.PolicyDefinition;

import java.util.Collections;
import java.util.List;

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
        @NotNull
        AuthProperties auth,

        @Valid
        List<PolicyDefinition> policies
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
            @NotNull
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

                @NotEmpty(message = "Static token mappings (mssm.auth.static-tokens.mappings) cannot be empty when static token auth is enabled.")
                @Valid
                List<StaticTokenPolicyMapping> mappings
        ) {
            public StaticTokenAuthProperties {
                if (mappings == null) {
                    mappings = Collections.emptyList();
                }
            }
        }
    }
}