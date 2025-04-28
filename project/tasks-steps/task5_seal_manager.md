
# Task 5: Implement Core Seal/Unseal Logic

## Goal
Introduce a "sealed" state where the application cannot perform cryptographic operations because it lacks the master key, and an "unseal" process (initially using a configured key) to load the key and enable operations. This directly addresses requirement **F-CORE-140**.

---

## Prerequisites
- Task 2 (EncryptionService) is completed.
- Task 4 (FileSystemStorageBackend) is completed (though not directly used here).
- Spring Boot context is set up.

---

## Step-by-Step Implementation

### Step 1: Define SealStatus Enum
Create a clear representation of the vault's operational state.

```java
package tech.yump.vault.core;

/**
 * Represents the operational state of the vault concerning its master key.
 */
public enum SealStatus {
    SEALED,   // The vault is sealed.
    UNSEALED  // The vault is unsealed.
}
```

### Step 2: Create VaultSealedException
Custom runtime exception thrown when operations are attempted while sealed.

```java
package tech.yump.vault.core;

/**
 * Exception thrown when an operation requiring the master key is attempted while sealed.
 */
public class VaultSealedException extends RuntimeException {
    public VaultSealedException(String message) {
        super(message);
    }
}
```

### Step 3: Create SealManager Service
Central service managing the seal status and holding the master key.

```java
package tech.yump.vault.core;

import jakarta.annotation.PostConstruct;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Slf4j
@Service
public class SealManager {
    private final AtomicReference<SealStatus> currentStatus = new AtomicReference<>(SealStatus.SEALED);
    private final AtomicReference<SecretKey> masterKey = new AtomicReference<>(null);
    private static final int EXPECTED_KEY_LENGTH = 32;
    @Value("${mssm.master.key.b64:#{null}}")
    private String initialMasterKeyBase64;

    @PostConstruct
    private void initializeSealStatus() { ... }

    public synchronized void unseal(String base64Key) { ... }
    public synchronized void seal() { ... }
    public boolean isSealed() { ... }
    public SealStatus getSealStatus() { ... }
    public SecretKey getMasterKey() throws VaultSealedException { ... }
}
```

### Step 4: Configure the Initial Master Key (Environment Variable)
Generate a secure 32-byte key using:

```bash
openssl rand 32 | base64
```

Set the key via environment variable:

```bash
export MSSM_MASTER_KEY_B64="YOUR_GENERATED_BASE64_KEY_HERE"
```

Or optionally via `application.properties`.

---

## Step 5: Modify EncryptionService to Use SealManager

- Remove static, hardcoded key usage.
- Inject `SealManager` via constructor.
- Fetch the master key dynamically from `SealManager` in `encrypt` and `decrypt` methods.
- Handle `VaultSealedException` when the vault is sealed.

---

## Completion of Task 5

- **SealStatus** enum created.
- **VaultSealedException** created.
- **SealManager** service managing sealed/unsealed states.
- **EncryptionService** updated to dynamically retrieve the master key.

### What's Achieved
- Application now honors "sealed" vs "unsealed" states.
- EncryptionService operations are blocked when sealed.
- Automatic unsealing via environment configuration is supported.

---

## Next Steps

1. **Task 10**: Write unit/integration tests for `SealManager` and `EncryptionService`.
2. **Task 6 & 7**: Setup HTTP server and `/sys/seal-status` endpoint.
3. **Future Enhancements**:
   - API-based unseal using Shamir's Secret Sharing.
   - API-based manual sealing `/sys/seal`.
