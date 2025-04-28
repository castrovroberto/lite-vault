package tech.yump.vault.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import tech.yump.vault.config.MssmProperties;

@Slf4j
@Component // Register as a Spring component
public class FileSystemStorageBackend implements StorageBackend {

  private final Path basePath;
  private final ObjectMapper objectMapper;
  private final MssmProperties properties;


  public FileSystemStorageBackend(
      final ObjectMapper objectMapper,
      final MssmProperties properties
  ) {
    this.objectMapper = objectMapper;
    this.properties = properties;
    this.basePath = Paths.get(properties.storage().filesystem().path()).toAbsolutePath();
    log.info("FileSystemStorageBackend initialized with base path: {}", this.basePath);
  }

  /**
   * Validates the base path after bean creation and property injection.
   */
  @PostConstruct
  private void validateBasePath() {
    try {
      if (Files.exists(basePath)) {
        if (!Files.isDirectory(basePath)) {
          throw new StorageException("Configured base path exists but is not a directory: " + basePath);
        }
        if (!Files.isReadable(basePath) || !Files.isWritable(basePath)) {
          throw new StorageException("Configured base path directory lacks read/write permissions: " + basePath);
        }
        log.debug("Base path validation successful: {}", basePath);
      } else {
        log.warn("Base path directory does not exist, attempting to create: {}", basePath);
        Files.createDirectories(basePath); // Create if not exists
        log.info("Successfully created base path directory: {}", basePath);
      }
    } catch (IOException e) {
      log.error("Failed to validate or create base path: {}", basePath, e);
      throw new StorageException("Failed to initialize storage base path: " + basePath, e);
    }
  }


  @Override
  public void put(String key, EncryptedData data) throws StorageException {
    // FIX: Use StringUtils.hasText for key validation
    if (!StringUtils.hasText(key) || data == null) {
      throw new IllegalArgumentException("Key cannot be null or empty, and data cannot be null for put operation.");
    }
    Path filePath = resolveFilePath(key);
    log.debug("Putting data for key '{}' at path: {}", key, filePath);

    try {
      // Ensure parent directories exist
      Files.createDirectories(filePath.getParent());

      // Write JSON data to the file, overwriting if it exists
      try (OutputStream out = Files.newOutputStream(filePath, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
        objectMapper.writeValue(out, data);
      }
      log.info("Successfully stored data for key '{}'", key);
    } catch (IOException e) {
      log.error("Failed to put data for key '{}' at path {}: {}", key, filePath, e.getMessage(), e);
      throw new StorageException("Failed to write data for key: " + key, e);
    }
  }

  @Override
  public Optional<EncryptedData> get(String key) throws StorageException {
    // FIX: Use StringUtils.hasText for key validation
    if (!StringUtils.hasText(key)) {
      throw new IllegalArgumentException("Key cannot be null or empty for get operation.");
    }
    Path filePath = resolveFilePath(key);
    log.debug("Getting data for key '{}' from path: {}", key, filePath);

    if (!Files.exists(filePath) || !Files.isRegularFile(filePath)) {
      log.debug("Data not found for key '{}' (path {} does not exist or is not a file)", key, filePath);
      return Optional.empty();
    }

    try (InputStream in = Files.newInputStream(filePath, StandardOpenOption.READ)) {
      EncryptedData data = objectMapper.readValue(in, EncryptedData.class);
      log.info("Successfully retrieved data for key '{}'", key);
      return Optional.of(data);
    } catch (NoSuchFileException e) {
      // Should be caught by Files.exists check, but handle defensively
      log.warn("Data not found for key '{}' during read attempt (NoSuchFileException): {}", key, filePath);
      return Optional.empty();
    } catch (IOException e) {
      log.error("Failed to get data for key '{}' from path {}: {}", key, filePath, e.getMessage(), e);
      throw new StorageException("Failed to read or parse data for key: " + key, e);
    }
  }

  @Override
  public void delete(String key) throws StorageException {
    // FIX: Use StringUtils.hasText for key validation
    if (!StringUtils.hasText(key)) {
      throw new IllegalArgumentException("Key cannot be null or empty for delete operation.");
    }
    Path filePath = resolveFilePath(key);
    log.debug("Deleting data for key '{}' at path: {}", key, filePath);

    try {
      boolean deleted = Files.deleteIfExists(filePath);
      if (deleted) {
        log.info("Successfully deleted data for key '{}'", key);
      } else {
        log.debug("No data found to delete for key '{}' (path {} did not exist)", key, filePath);
      }
      // Optional: Clean up empty parent directories if desired (more complex)

    } catch (AccessDeniedException e) {
      log.error("Permission denied while trying to delete file for key '{}' at path {}: {}", key, filePath, e.getMessage(), e);
      throw new StorageException("Permission denied deleting data for key: " + key, e);
    } catch (IOException e) {
      // Catch other IO errors, e.g., trying to delete a directory
      log.error("Failed to delete data for key '{}' at path {}: {}", key, filePath, e.getMessage(), e);
      throw new StorageException("Failed to delete data for key: " + key, e);
    }
  }

  /**
   * Resolves the logical key to an absolute file path within the base directory.
   * Performs basic sanitization to prevent path traversal.
   *
   * @param key The logical key.
   * @return The absolute Path object for the file.
   * @throws StorageException if the key is invalid or results in a path outside the base directory.
   */
  private Path resolveFilePath(String key) {
    // Basic sanitization: replace backslashes, remove leading/trailing slashes, disallow ".."
    // FIX: Added check for empty key here too, although StringUtils.hasText should catch it earlier
    String sanitizedKey = key.replace('\\', '/').trim();
    if (sanitizedKey.startsWith("/") || sanitizedKey.endsWith("/") || sanitizedKey.contains("..") || sanitizedKey.isEmpty()) {
      log.error("Invalid storage key provided: '{}'", key);
      throw new StorageException("Invalid storage key format: " + key);
    }

    // Append ".json" extension
    Path relativePath = Paths.get(sanitizedKey + ".json");

    // Resolve against the base path
    Path absolutePath = this.basePath.resolve(relativePath).normalize();

    // Security check: Ensure the resolved path is still within the base path
    if (!absolutePath.startsWith(this.basePath)) {
      log.error("Path traversal attempt detected for key '{}', resolved path '{}' is outside base path '{}'", key, absolutePath, this.basePath);
      throw new StorageException("Invalid key resulting in path traversal attempt: " + key);
    }

    return absolutePath;
  }
}