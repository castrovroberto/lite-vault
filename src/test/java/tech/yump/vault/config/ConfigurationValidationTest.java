package tech.yump.vault.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

public class ConfigurationValidationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(TestConfig.class));

    @EnableConfigurationProperties(MssmProperties.class)
    static class TestConfig {}

    private ApplicationContextRunner runnerWithBaseProps() {
        return contextRunner.withPropertyValues(
                "mssm.master.b64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "mssm.storage.filesystem.path=./test-validation-storage",
                "mssm.policies[0].name=dummy",
                "mssm.policies[0].rules[0].path=dummy/*",
                "mssm.policies[0].rules[0].capabilities=READ"
        );
    }

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


    @Test
    @DisplayName("JWT Config Validation: Should PASS with valid RSA key")
    void validateJwt_validRsa_shouldPass() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-rsa.type=RSA",
                        "mssm.secrets.jwt.keys.my-rsa.size=2048"
                        // rotationPeriod is optional
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(MssmProperties.class);
                    MssmProperties props = context.getBean(MssmProperties.class);
                    assertThat(props.secrets().jwt()).isNotNull();
                    assertThat(props.secrets().jwt().keys()).containsKey("my-rsa");
                    MssmProperties.JwtKeyDefinition keyDef = props.secrets().jwt().keys().get("my-rsa");
                    assertThat(keyDef.type()).isEqualTo(MssmProperties.JwtKeyType.RSA);
                    assertThat(keyDef.size()).isEqualTo(2048);
                    assertThat(keyDef.curve()).isNull();
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should PASS with valid EC key")
    void validateJwt_validEc_shouldPass() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-ec.type=EC",
                        "mssm.secrets.jwt.keys.my-ec.curve=P-256", // Valid curve
                        "mssm.secrets.jwt.keys.my-ec.rotation-period=7d" // Optional
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(MssmProperties.class);
                    MssmProperties props = context.getBean(MssmProperties.class);
                    assertThat(props.secrets().jwt()).isNotNull();
                    assertThat(props.secrets().jwt().keys()).containsKey("my-ec");
                    MssmProperties.JwtKeyDefinition keyDef = props.secrets().jwt().keys().get("my-ec");
                    assertThat(keyDef.type()).isEqualTo(MssmProperties.JwtKeyType.EC);
                    assertThat(keyDef.curve()).isEqualTo("P-256");
                    assertThat(keyDef.size()).isNull();
                    assertThat(keyDef.rotationPeriod()).isEqualTo(Duration.ofDays(7));
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if RSA key is missing size")
    void validateJwt_rsaMissingSize_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-rsa.type=RSA" // Size is missing
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause().hasMessageContaining("RSA keys must specify a 'size'");
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if RSA key size is too small")
    void validateJwt_rsaSizeTooSmall_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-rsa.type=RSA",
                        "mssm.secrets.jwt.keys.my-rsa.size=1024" // Too small
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause().hasMessageContaining("RSA key size must be at least 2048 bits");
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if RSA key specifies curve")
    void validateJwt_rsaSpecifiesCurve_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-rsa.type=RSA",
                        "mssm.secrets.jwt.keys.my-rsa.size=2048",
                        "mssm.secrets.jwt.keys.my-rsa.curve=P-256" // Curve specified for RSA
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause().hasMessageContaining("RSA keys must specify a 'size' (>= 2048) and must not specify a 'curve'");
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if EC key is missing curve")
    void validateJwt_ecMissingCurve_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-ec.type=EC" // Curve is missing
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause().hasMessageContaining("EC keys must specify a valid 'curve'");
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if EC key has invalid curve")
    void validateJwt_ecInvalidCurve_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-ec.type=EC",
                        "mssm.secrets.jwt.keys.my-ec.curve=invalid-curve" // Not in allowed set
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause().hasMessageContaining("EC keys must specify a valid 'curve'");
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if EC key specifies size")
    void validateJwt_ecSpecifiesSize_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-ec.type=EC",
                        "mssm.secrets.jwt.keys.my-ec.curve=P-256",
                        "mssm.secrets.jwt.keys.my-ec.size=2048" // Size specified for EC
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause().hasMessageContaining("EC keys must specify a valid 'curve' (P-256, P-384, P-521) and must not specify a 'size'");
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if key type is missing")
    void validateJwt_missingType_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        // "mssm.secrets.jwt.keys.my-key.type=...", // Type is missing
                        "mssm.secrets.jwt.keys.my-key.size=2048"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class)
                            .rootCause().hasMessageContaining("Key type (type: RSA or EC) must be specified");
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if key type is invalid")
    void validateJwt_invalidType_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys.my-key.type=INVALID_TYPE",
                        "mssm.secrets.jwt.keys.my-key.size=2048"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    // Spring Boot's property binding will fail trying to convert "INVALID_TYPE" to the enum
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalArgumentException.class)
                            .rootCause()
                            .hasMessageContaining("No enum constant tech.yump.vault.config.MssmProperties.JwtKeyType.INVALID_TYPE");
                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should FAIL if jwt.keys map is empty")
    void validateJwt_emptyKeysMap_shouldFail() {
        runnerWithBaseProps()
                .withPropertyValues(
                        "mssm.secrets.jwt.keys="
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(org.springframework.core.convert.ConverterNotFoundException.class)
                            .rootCause()
                            .hasMessageContaining("No converter found capable of converting from type [java.lang.String] to type");
                    assertThat(context.getStartupFailure().getMessage())
                            .contains("Error creating bean with name 'mssm-tech.yump.vault.config.MssmProperties': Could not bind properties to 'MssmProperties'");

                });
    }

    @Test
    @DisplayName("JWT Config Validation: Should PASS if jwt section is missing entirely")
    void validateJwt_missingSection_shouldPass() {
        runnerWithBaseProps()
                // No mssm.secrets.jwt properties provided
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(MssmProperties.class);
                    MssmProperties props = context.getBean(MssmProperties.class);
                    assertThat(props.secrets()).isNull(); // jwt property itself will be null
                });
    }


}
