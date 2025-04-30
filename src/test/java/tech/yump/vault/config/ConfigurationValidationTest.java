package tech.yump.vault.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

public class ConfigurationValidationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(TestConfig.class));

    @EnableConfigurationProperties(MssmProperties.class)
    static class TestConfig {}

    @Test
    @DisplayName("Config Validation: Should FAIL when static auth enabled but mappings are empty")
    void validateStaticTokens_enabledTrue_mappingsEmpty_shouldFail() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Dummy key
                        "mssm.storage.filesystem.path=./test-validation-storage",
                        "mssm.policies[0].name=dummy", // Need at least one policy
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ",
                        "mssm.auth.static-tokens.enabled=true",
                        "mssm.auth.static-tokens.mappings=" // Empty list
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause()
                            // --- FIX: Use the actual validation message ---
                            .hasMessageContaining("Static token mappings (mssm.auth.static-tokens.mappings) cannot be empty when static token auth is enabled.");
                    // --- Was: "Your expected validation message here" ---

                    // This assertion is okay, but less specific than the root cause message check
                    assertThat(context.getStartupFailure().getMessage())
                            .contains("Error creating bean with name 'mssm-tech.yump.vault.config.MssmProperties': Could not bind properties to 'MssmProperties' : prefix=mssm, ignoreInvalidFields=false, ignoreUnknownFields=true");
                });
    }

    @Test
    @DisplayName("Config Validation: Should FAIL when static auth enabled but mappings are missing")
    void validateStaticTokens_enabledTrue_mappingsMissing_shouldFail() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "mssm.storage.filesystem.path=./test-validation-storage",
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ",
                        "mssm.auth.static-tokens.enabled=true"
                        // mappings property is completely missing
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(BindValidationException.class);
                    assertThat(context.getStartupFailure().getMessage())
                            .contains("Error creating bean with name 'mssm-tech.yump.vault.config.MssmProperties': Could not bind properties to 'MssmProperties' : prefix=mssm, ignoreInvalidFields=false, ignoreUnknownFields=true");
                });
    }

    @Test
    @DisplayName("Config Validation: Should PASS when static auth enabled and mappings are present")
    void validateStaticTokens_enabledTrue_mappingsPresent_shouldPass() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "mssm.storage.filesystem.path=./test-validation-storage",
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ",
                        "mssm.auth.static-tokens.enabled=true",
                        "mssm.auth.static-tokens.mappings[0].token=valid-token",
                        "mssm.auth.static-tokens.mappings[0].policyNames[0]=dummy"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(MssmProperties.class);
                    MssmProperties props = context.getBean(MssmProperties.class);
                    assertThat(props.auth().staticTokens().enabled()).isTrue();
                    assertThat(props.auth().staticTokens().mappings()).isNotEmpty();
                });
    }

    @Test
    @DisplayName("Config Validation: Should PASS when static auth disabled and mappings are empty")
    void validateStaticTokens_enabledFalse_mappingsEmpty_shouldPass() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "mssm.storage.filesystem.path=./test-validation-storage",
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ",
                        "mssm.auth.static-tokens.enabled=false",
                        "mssm.auth.static-tokens.mappings=" // Empty list
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(MssmProperties.class);
                    MssmProperties props = context.getBean(MssmProperties.class);
                    assertThat(props.auth().staticTokens().enabled()).isFalse();
                    assertThat(props.auth().staticTokens().mappings()).isEmpty();
                });
    }

    @Test
    @DisplayName("Config Validation: Should PASS when static auth disabled and mappings are missing")
    void validateStaticTokens_enabledFalse_mappingsMissing_shouldPass() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "mssm.storage.filesystem.path=./test-validation-storage",
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ",
                        "mssm.auth.static-tokens.enabled=false"
                        // mappings property is completely missing
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(MssmProperties.class);
                    MssmProperties props = context.getBean(MssmProperties.class);
                    assertThat(props.auth().staticTokens().enabled()).isFalse();
                    // The constructor defaults mappings to empty list even if missing in YAML
                    assertThat(props.auth().staticTokens().mappings()).isEmpty();
                });
    }

    @Test
    @DisplayName("Config Validation: Should FAIL when master key config is missing")
    void validateMasterKey_missing_shouldFail() {
        contextRunner
                .withPropertyValues(
                        // "mssm.master.b64=...", // MISSING master section
                        "mssm.storage.filesystem.path=./test-validation-storage",
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                                    .rootCause()
                                    .hasMessageContaining("Master key configuration (mssm.master) is required.");
                });
    }

    @Test
    @DisplayName("Config Validation: Should FAIL when storage config is missing")
    void validateStorage_missing_shouldFail() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        // "mssm.storage.filesystem.path=...", // MISSING storage section
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause()
                            .hasMessageContaining("Storage configuration (mssm.storage) is required.");
                });
    }

    @Test
    @DisplayName("Config Validation: Should FAIL when storage.filesystem config is missing")
    void validateStorageFilesystem_missing_shouldFail() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause()
                            .hasMessageContaining("Storage configuration (mssm.storage) is required.");
                });
    }

    @Test
    @DisplayName("Config Validation: Should FAIL when secrets.db.postgres is incomplete (missing username/password/roles)")
    void validateSecretsDbPostgres_missing_shouldFail() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "mssm.storage.filesystem.path=./test-validation-storage",
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ",
                        // --- REMOVE DUMMY PROPERTY ---
                        // "mssm.secrets.db.force-creation=true"
                        // --- ADD ONE REQUIRED SUB-PROPERTY ---
                        // Provide just enough to force creation of DbSecretsProperties and PostgresProperties
                        "mssm.secrets.db.postgres.connection-url=jdbc:postgresql://dummy:5432/db"
                        // Username, password, and roles are now missing, triggering validation *within* PostgresProperties
                )
                .run(context -> {
                    // Context should now fail due to missing fields in PostgresProperties
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).
                            hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause()
                            // --- UPDATE EXPECTED MESSAGE ---
                            // Expect failure for one of the missing fields inside PostgresProperties
                            .hasMessageContaining("PostgreSQL admin username (mssm.secrets.db.postgres.username) must be provided.");
                    // You could also check for password or roles message depending on validation order.
                });
    }

    @Test
    @DisplayName("Config Validation: Should PASS when secrets.db is missing entirely")
    void validateSecretsDb_missingEntirely_shouldPass() {
        contextRunner
                .withPropertyValues(
                        "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "mssm.storage.filesystem.path=./test-validation-storage",
                        "mssm.policies[0].name=dummy",
                        "mssm.policies[0].rules[0].path=dummy/*",
                        "mssm.policies[0].rules[0].capabilities=READ"
                        // mssm.secrets section is completely absent
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(MssmProperties.class);
                    MssmProperties props = context.getBean(MssmProperties.class);
                    assertThat(props.secrets()).isNull();
                });
    }
}
