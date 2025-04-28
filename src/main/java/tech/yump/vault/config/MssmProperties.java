package tech.yump.vault.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
// import jakarta.validation.constraints.NotEmpty; // REMOVE this import
import jakarta.validation.constraints.NotNull;
import java.util.Collections;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import tech.yump.vault.config.validation.ValidStaticTokenConfig; // IMPORT the custom annotation

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
    AuthProperties auth
) {

  // --- MasterKeyProperties and StorageProperties remain the same ---

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

  // --- AuthProperties remains the same ---
  @Validated
  public record AuthProperties (
      @Valid
      @NotNull
      StaticTokenAuthProperties staticTokens
  ) {

    /**
     * Properties specific to static token authentication.
     * Applies conditional validation: tokens are required only if enabled=true.
     */
    @Validated
    @ValidStaticTokenConfig // APPLY the custom class-level validation annotation
    public record StaticTokenAuthProperties (
        boolean enabled, // Defaults to false if omitted

        // REMOVE @NotEmpty from the field level
        // ADD @NotNull to ensure the binder provides an empty set if the key exists but is empty, preventing NPEs.
        // The actual "not empty if enabled" check is handled by @ValidStaticTokenConfig.
        @NotNull(message = "Token set (mssm.auth.static-tokens.tokens) must be present, even if empty when disabled.")
        Set<String> tokens
    ) {
      // Ensure tokens defaults to an empty set if omitted in YAML
      // (The binder often does this, but explicit initialization adds safety)
      public StaticTokenAuthProperties {
        if (tokens == null) {
          tokens = Collections.emptySet();
        }
      }
    }
  }
}