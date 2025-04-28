
# Task 2: Implement Core Encryption/Decryption Logic (AES-GCM)

## Goal
Create reusable Java functions/methods that can securely encrypt and decrypt arbitrary byte arrays using the AES-GCM algorithm, fulfilling requirements F-CORE-100 and NFR-SEC-100.

## What's Needed

### 1. Create a Dedicated Cryptography Service/Utility Class
- **Action:** Create `EncryptionService.java` inside `src/main/java/tech/yump/vault/crypto/`.
- **Rationale:** Encapsulates cryptographic logic, making it reusable and testable. It can later be turned into a Spring `@Service` if needed.

### 2. Register BouncyCastle Provider
- **Action:** Add a static initializer block in `EncryptionService` or `LiteVaultApplication`.

```java
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        Security.addProvider(new BouncyCastleProvider());
    }
}
```

- **Rationale:** Ensures AES-GCM is available via Java Cryptography Extension (JCE).

### 3. Define Constants and Key Handling (Temporary)
- **Action:** Define constants for algorithm, tag length, nonce length. Define a temporary 256-bit AES key for initial testing.

```java
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class EncryptionService {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int NONCE_LENGTH_BYTE = 12;
    private static final String AES = "AES";
    
    private static final byte[] TEMP_HARDCODED_KEY_BYTES = new byte[32];
    static {
        new SecureRandom().nextBytes(TEMP_HARDCODED_KEY_BYTES);
    }
    private static final SecretKey AES_KEY = new SecretKeySpec(TEMP_HARDCODED_KEY_BYTES, AES);
    private final SecureRandom secureRandom = new SecureRandom();
}
```

- **Rationale:** Sets up cryptographic parameters and key for encryption/decryption.

### 4. Implement the `encrypt` Method
- **Action:** Create `public byte[] encrypt(byte[] plaintext)` method.
  - Generate nonce
  - Create GCMParameterSpec
  - Get Cipher instance and initialize for encrypt mode
  - Encrypt using `cipher.doFinal(plaintext)`
  - Combine nonce and ciphertext
- **Rationale:** Performs secure encryption, ensures nonce uniqueness.

### 5. Implement the `decrypt` Method
- **Action:** Create `public byte[] decrypt(byte[] nonceAndCiphertext)` method.
  - Extract nonce and ciphertext
  - Create GCMParameterSpec
  - Get Cipher instance and initialize for decrypt mode
  - Decrypt using `cipher.doFinal(ciphertextBytes)`
- **Rationale:** Verifies and decrypts data securely.

### 6. Add Basic Logging (Optional)
- **Action:** Add SLF4j logging without exposing sensitive data.

```java
private static final Logger log = LoggerFactory.getLogger(EncryptionService.class);
```

- **Rationale:** Helps trace flow during development.

## Completion Criteria
- `EncryptionService.java` exists.
- Functional `encrypt` and `decrypt` methods using AES-GCM.
- Unique nonce per encryption.
- Nonce and ciphertext correctly combined/split.
- Temporary 256-bit AES key used (must be replaced later).
- Basic exception handling is present.

## Next Steps
- (Task 10) Write unit tests for encryption/decryption roundtrip and failure modes (wrong key, tampered data).

## Final Note
This provides the fundamental cryptographic building block needed for subsequent tasks like secret storage (Task 4) and master key sealing (Task 5). **Remember to replace the hardcoded key with secure key management later!**
