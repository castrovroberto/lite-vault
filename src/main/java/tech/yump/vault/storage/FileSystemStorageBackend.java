package tech.yump.vault.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import tech.yump.vault.config.MssmProperties;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component // Register as a Spring component
public class FileSystemStorageBackend implements StorageBackend {

  private final Path basePath;
  private final ObjectMapper objectMapper;
  // private final MssmProperties properties; // Keep for basePath initialization

  public FileSystemStorageBackend(
          final ObjectMapper objectMapper,
          final MssmProperties properties // Keep for basePath initialization
  ) {
    this.objectMapper = objectMapper;
    // this.properties = properties;
    this.basePath = Paths.get(properties.storage().filesystem().path())
            .toAbsolutePath()
            .normalize();
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
    if (!StringUtils.hasText(key) || data == null) {
      throw new IllegalArgumentException("Key cannot be null or empty, and data cannot be null for put operation.");
    }
    Path filePath = resolveFilePath(key); // Uses updated resolveFilePath -> resolvePath
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
    if (!StringUtils.hasText(key)) {
      throw new IllegalArgumentException("Key cannot be null or empty for get operation.");
    }
    Path filePath = resolveFilePath(key); // Uses updated resolveFilePath -> resolvePath
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
    if (!StringUtils.hasText(key)) {
      throw new IllegalArgumentException("Key cannot be null or empty for delete operation.");
    }
    Path filePath = resolveFilePath(key); // Uses updated resolveFilePath -> resolvePath
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

  // --- Added Methods ---

  @Override
  public boolean isDirectory(String relativePath) throws StorageException {
    if (!StringUtils.hasText(relativePath)) {
      throw new IllegalArgumentException("Relative path cannot be null or empty for isDirectory check.");
    }
    Path absolutePath = resolvePath(relativePath); // Use a generalized resolve method
    log.debug("Checking if path is directory: {}", absolutePath);
    // Check existence and isDirectory without following symlinks for safety
    return Files.isDirectory(absolutePath, LinkOption.NOFOLLOW_LINKS);
  }

  @Override
  public List<String> listDirectory(String relativeDirPath) throws StorageException {
    if (!StringUtils.hasText(relativeDirPath)) {
      throw new IllegalArgumentException("Relative directory path cannot be null or empty for list operation.");
    }
    Path absoluteDirPath = resolvePath(relativeDirPath); // Use a generalized resolve method
    log.debug("Listing directory contents for path: {}", absoluteDirPath);

    if (!Files.isDirectory(absoluteDirPath, LinkOption.NOFOLLOW_LINKS)) {
      log.warn("Attempted to list non-directory or non-existent path: {}", absoluteDirPath);
      // Return empty list consistent with how Files.newDirectoryStream behaves for non-existent paths
      // after initial check, though we might throw if we expect it to exist.
      // Let's return empty for simplicity, callers might need to check isDirectory first if existence is mandatory.
      return List.of();
    }

    List<String> entries = new ArrayList<>();
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(absoluteDirPath)) {
      for (Path entry : stream) {
        entries.add(entry.getFileName().toString());
      }
      log.debug("Found {} entries in directory {}", entries.size(), absoluteDirPath);
      return entries;
    } catch (IOException e) {
      log.error("Failed to list directory contents for path {}: {}", absoluteDirPath, e.getMessage(), e);
      throw new StorageException("Failed to list directory: " + relativeDirPath, e);
    }
  }

  /**
   * Resolves a relative path against the base storage path and performs security checks.
   * This method is suitable for resolving both files and directories.
   *
   * @param relativePath The logical relative path (e.g., "secrets/myapp/db-password" or "jwt/keys/my-key").
   * @return The absolute Path object.
   * @throws StorageException if the path is invalid or results in a path outside the base directory.
   */
  private Path resolvePath(String relativePath) throws StorageException {
    // Basic sanitization: replace backslashes, remove leading/trailing slashes, disallow ".."
    String sanitizedPath = relativePath.replace('\\', '/').trim();
    if (sanitizedPath.startsWith("/") || sanitizedPath.endsWith("/") || sanitizedPath.contains("..") || sanitizedPath.isEmpty()) {
      log.error("Invalid storage path provided: '{}'", relativePath);
      throw new StorageException("Invalid storage path format: " + relativePath);
    }

    // Resolve against the base path
    Path absolutePath = this.basePath.resolve(sanitizedPath).normalize();

    // Security check: Ensure the resolved path is still within the base path
    if (!absolutePath.startsWith(this.basePath)) {
      log.error("Path traversal attempt detected for path '{}', resolved path '{}' is outside base path '{}'", relativePath, absolutePath, this.basePath);
      throw new StorageException("Invalid path resulting in path traversal attempt: " + relativePath);
    }

    return absolutePath;
  }


  /**
   * Resolves the logical key to an absolute file path within the base directory.
   * Appends ".json" extension.
   * Performs basic sanitization to prevent path traversal.
   *
   * @param key The logical key.
   * @return The absolute Path object for the file.
   * @throws StorageException if the key is invalid or results in a path outside the base directory.
   */
  private Path resolveFilePath(String key) throws StorageException {
    // This method now specifically handles *keys* which map to *files* with .json extension
    if (!StringUtils.hasText(key)) {
      throw new IllegalArgumentException("Key cannot be null or empty.");
    }
    String relativeFilePath = key + ".json"; // Append .json here
    return resolvePath(relativeFilePath); // Delegate sanitization and resolution
  }
  // --- End Added/Modified Methods ---
}