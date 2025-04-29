
# Task 12: Implement Static Secrets Engine (KV v1)

## Goal
Create an engine that:
- Takes a logical path and a map of key-value pairs.
- Serializes the map, encrypts it using `EncryptionService`.
- Stores the `EncryptedData` using the `StorageBackend` with the logical path as the key.
- Reverses the process for reads.

---

## Step 1: Define the `KVSecretEngine` Interface

```java
// src/main/java/tech/yump/vault/secrets/kv/KVSecretEngine.java
package tech.yump.vault.secrets.kv;

import java.util.Map;
import java.util.Optional;
import tech.yump.vault.core.EncryptionService;
import tech.yump.vault.storage.StorageException;

/**
 * Interface for a Key/Value (KV) secrets engine.
 */
public interface KVSecretEngine {

    Optional<Map<String, String>> read(String path) throws KVEngineException;
    void write(String path, Map<String, String> secrets) throws KVEngineException;
    void delete(String path) throws KVEngineException;
}
```

---

## Step 2: Create `KVEngineException`

```java
// src/main/java/tech/yump/vault/secrets/kv/KVEngineException.java
package tech.yump.vault.secrets.kv;

public class KVEngineException extends RuntimeException {
    public KVEngineException(String message) { super(message); }
    public KVEngineException(String message, Throwable cause) { super(message, cause); }
}
```

---

## Step 3: Implement `FileSystemKVSecretEngine`

```java
// src/main/java/tech/yump/vault/secrets/kv/FileSystemKVSecretEngine.java
package tech.yump.vault.secrets.kv;

// Imports ...

@Slf4j
@Service
@RequiredArgsConstructor
public class FileSystemKVSecretEngine implements KVSecretEngine {

    private final StorageBackend storageBackend;
    private final EncryptionService encryptionService;
    private final ObjectMapper objectMapper;
    private static final TypeReference<Map<String, String>> MAP_TYPE_REFERENCE = new TypeReference<>() {};

    @Override
    public Optional<Map<String, String>> read(String path) throws KVEngineException {
        // Implementation...
    }

    @Override
    public void write(String path, Map<String, String> secrets) throws KVEngineException {
        // Implementation...
    }

    @Override
    public void delete(String path) throws KVEngineException {
        // Implementation...
    }

    private void validatePath(String path) {
        // Implementation...
    }
}
```

- Uses encryption for secure storage.
- Serializes maps into JSON.
- Handles all operations through `StorageBackend`.

---

## Step 4: Update `CHANGELOG.md`

```markdown
### Added
- Static Secrets Engine (KV v1 - Task 12):
  - Defined `KVSecretEngine` interface.
  - Implemented `FileSystemKVSecretEngine`.
  - Added `KVEngineException`.
  - Registered as a Spring `@Service`.
```

---

## Step 5: Update `README.md` (Optional)

```markdown
## Current Status & Features (In Progress)

- Secrets Engines:
  - Implemented (KV v1): A static Key/Value secrets engine (`FileSystemKVSecretEngine`) encrypting and storing arbitrary key-value pairs.
```

---

## Explanation

1. **Interface (`KVSecretEngine`)**:
   - Standard operations (`read`, `write`, `delete`).
   - Optional handling of missing paths.
2. **Exception (`KVEngineException`)**:
   - Custom exception for engine-specific errors.
3. **Implementation (`FileSystemKVSecretEngine`)**:
   - Encrypts/decrypts using `EncryptionService`.
   - Serializes/deserializes using `ObjectMapper`.
   - Delegates storage operations to `StorageBackend`.
4. **Security**:
   - Encrypted JSON blobs are persisted.
   - Basic validation of logical paths.
5. **Next Step**:
   - Use this service in API controllers (Task 13).

---
