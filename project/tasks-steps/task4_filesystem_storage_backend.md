
# Task 4: Implement Basic File System Storage Backend

## Goal
Create a simple storage mechanism that saves and retrieves encrypted data (`EncryptedData` JSON objects) as files on the local disk. This implementation should adhere to an interface to allow for different backends later (e.g., cloud storage).

## Prerequisites
- **Task 2** (EncryptionService) completed
- **Task 3** (EncryptedData DTO) completed
- Jackson library available (via spring-boot-starter-web)

## Step-by-Step Implementation

### Step 1: Define the StorageBackend Interface

**File:** `src/main/java/tech/yump/vault/storage/StorageBackend.java`

```java
package tech.yump.vault.storage;

import java.util.Optional;

public interface StorageBackend {

    void put(String key, EncryptedData data) throws StorageException;

    Optional<EncryptedData> get(String key) throws StorageException;

    void delete(String key) throws StorageException;
}
```

**Explanation:** Defines the basic operations needed for any storage backend.

---

### Step 2: Create the Custom StorageException

**File:** `src/main/java/tech/yump/vault/storage/StorageException.java`

```java
package tech.yump.vault.storage;

public class StorageException extends RuntimeException {

    public StorageException(String message) {
        super(message);
    }

    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

**Explanation:** Provides a consistent way to handle storage-related errors.

---

### Step 3: Implement the FileSystemStorageBackend

**File:** `src/main/java/tech/yump/vault/storage/FileSystemStorageBackend.java`

```java
package tech.yump.vault.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.*;
import java.util.Optional;

@Slf4j
@Component
public class FileSystemStorageBackend implements StorageBackend {

    private final Path basePath;
    private final ObjectMapper objectMapper;

    public FileSystemStorageBackend(
            @Value("${mssm.storage.filesystem.path:./vault-data}") String basePathStr,
            ObjectMapper objectMapper) {
        if (!StringUtils.hasText(basePathStr)) {
            throw new IllegalArgumentException("Base storage path cannot be empty.");
        }
        this.basePath = Paths.get(basePathStr).toAbsolutePath();
        this.objectMapper = objectMapper;
        log.info("FileSystemStorageBackend initialized at: {}", this.basePath);
    }

    @PostConstruct
    private void validateBasePath() {
        try {
            if (Files.notExists(basePath)) {
                Files.createDirectories(basePath);
                log.info("Created storage base directory: {}", basePath);
            } else if (!Files.isDirectory(basePath)) {
                throw new StorageException("Configured path is not a directory: " + basePath);
            }
        } catch (IOException e) {
            throw new StorageException("Failed to initialize storage base path: " + basePath, e);
        }
    }

    @Override
    public void put(String key, EncryptedData data) throws StorageException {
        Path filePath = resolveFilePath(key);
        try {
            Files.createDirectories(filePath.getParent());
            try (OutputStream out = Files.newOutputStream(filePath, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                objectMapper.writeValue(out, data);
            }
            log.info("Stored encrypted data for key: {}", key);
        } catch (IOException e) {
            throw new StorageException("Failed to write data for key: " + key, e);
        }
    }

    @Override
    public Optional<EncryptedData> get(String key) throws StorageException {
        Path filePath = resolveFilePath(key);
        if (Files.notExists(filePath)) {
            return Optional.empty();
        }
        try (InputStream in = Files.newInputStream(filePath)) {
            return Optional.of(objectMapper.readValue(in, EncryptedData.class));
        } catch (IOException e) {
            throw new StorageException("Failed to read data for key: " + key, e);
        }
    }

    @Override
    public void delete(String key) throws StorageException {
        Path filePath = resolveFilePath(key);
        try {
            Files.deleteIfExists(filePath);
            log.info("Deleted data for key: {}", key);
        } catch (IOException e) {
            throw new StorageException("Failed to delete data for key: " + key, e);
        }
    }

    private Path resolveFilePath(String key) {
        String sanitizedKey = key.replace('\', '/').trim();
        if (sanitizedKey.contains("..") || sanitizedKey.startsWith("/") || sanitizedKey.isEmpty()) {
            throw new StorageException("Invalid storage key: " + key);
        }
        Path path = basePath.resolve(sanitizedKey + ".json").normalize();
        if (!path.startsWith(basePath)) {
            throw new StorageException("Path traversal detected for key: " + key);
        }
        return path;
    }
}
```

---

## Explanation

- **StorageBackend Interface:** Defines a clear contract for persistence operations.
- **StorageException:** A specialized exception for storage operations.
- **FileSystemStorageBackend:** 
  - Stores encrypted data in JSON format.
  - Securely resolves file paths to prevent traversal attacks.
  - Uses Jackson for JSON serialization.
  - Provides robust error handling and clear logging.

---

## Configuration

In your `application.properties`, configure:

```properties
mssm.storage.filesystem.path=./vault-data
```

(defaults to `./vault-data` if not set)

---

# Task 4 Completion

With the interface, exception, and file system backend implemented, **Task 4 is complete**. 

✅ Ready for Task 10: Write Unit Tests for Encryption & Storage.

✅ Next: Task 5: Implement Core Seal/Unseal Logic.
