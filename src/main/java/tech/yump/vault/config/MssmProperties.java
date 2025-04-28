package tech.yump.vault.config;

import jakarta.validation.Valid; // For nested validation
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated; // Enable validation

/**
 * Configuration properties for the MSSM application under the 'mssm' prefix.
 */
@ConfigurationProperties(prefix = "mssm")
@Validated // Enable validation on this properties class
public record MssmProperties(
    @Valid // Enable validation on nested properties
    MasterKeyProperties master,

    @Valid // Enable validation on nested properties
    StorageProperties storage
) {

  /**
   * Properties related to the master encryption key.
   */
  @Validated
  public record MasterKeyProperties(
      @NotBlank(message = "Master key (mssm.master.key.b64) must be provided.")
      String b64 // Corresponds to mssm.master.key.b64
  ) {}

  /**
   * Properties related to the storage backend.
   */
  @Validated
  public record StorageProperties(
      @Valid // Enable validation on nested properties
      FileSystemProperties filesystem
  ) {
    /**
     * Properties specific to the filesystem storage backend.
     */
    @Validated
    public record FileSystemProperties(
        @NotBlank(message = "Filesystem storage path (mssm.storage.filesystem.path) must be provided.")
        String path // Corresponds to mssm.storage.filesystem.path
    ) {}
  }
}
