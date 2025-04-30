package tech.yump.vault.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.validation.BindException;

import static org.assertj.core.api.Assertions.assertThat;

public class ConfigurationValidationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(TestConfig.class)); // Load MssmProperties

    // Inner class to enable configuration properties scanning for the runner
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
                    assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(BindValidationException.class); // Or ConfigurationPropertiesBindException
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
}
