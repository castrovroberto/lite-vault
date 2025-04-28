# Task 3: Define Encrypted Storage Format

## Goal

Decide on a consistent structure to store encrypted data (ciphertext) along with necessary decryption information (nonce), and optional metadata like version and timestamp.

This format will be used by Task 4 (Storage Backend).

## Recap from Task 2

- `EncryptionService.encrypt(plaintext)` returns a `byte[]` containing `nonce || ciphertext`.
- `EncryptionService.decrypt(nonceAndCiphertext)` expects a `byte[]` in the format `nonce || ciphertext`.

## Requirements Analysis

| Aspect              | Decision |
|:--------------------|:---------|
| Format              | JSON |
| Mandatory Content   | Nonce, Ciphertext |
| Optional Content    | Metadata (Version, Timestamp) |
| Rationale           | Structured, extensible, human-readable format |

## Why JSON?

- **Extensibility:** Easily add metadata fields later (e.g., key ID for rotation).
- **Readability:** Easy debugging with Base64-encoded fields.
- **Tooling:** Native support with Jackson (already included via Spring Boot Web).
- **Versioning:** Easy to introduce format versioning with minimal disruption.

## Chosen JSON Structure

```json
{
  "v": 1,
  "n": "BASE64_ENCODED_NONCE",
  "c": "BASE64_ENCODED_CIPHERTEXT",
  "ts": 1678886400
}
```

| Field | Type | Description |
|:------|:-----|:------------|
| `v`   | Integer | Version number of the storage format (mandatory) |
| `n`   | String  | Base64-encoded nonce (mandatory) |
| `c`   | String  | Base64-encoded ciphertext (mandatory) |
| `ts`  | Long    | Unix timestamp (optional) |

## Implementation Plan

### 1. Create `EncryptedData` DTO Class

- **Location:** `src/main/java/tech/yump/vault/storage/EncryptedData.java`
- **Contents:** Fields for `v`, `n`, `c`, and `ts`.
- **Annotations:** Use Lombok and Jackson annotations for simplicity.

```java
package tech.yump.vault.storage;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.Base64;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents the structured format for storing encrypted data persistently.
 * Serialized to/deserialized from JSON.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EncryptedData {
    @JsonProperty("v")
    private int version = 1;

    @JsonProperty("n")
    private String nonceBase64;

    @JsonProperty("c")
    private String ciphertextBase64;

    @JsonProperty("ts")
    private Instant timestamp;

    public EncryptedData(byte[] nonce, byte[] ciphertext) {
        if (nonce == null || ciphertext == null) {
            throw new IllegalArgumentException("Nonce and ciphertext cannot be null.");
        }
        this.version = 1;
        this.nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        this.ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);
        this.timestamp = Instant.now();
    }

    public byte[] getNonceBytes() {
        if (this.nonceBase64 == null) {
            throw new IllegalStateException("Nonce Base64 string is null.");
        }
        return Base64.getDecoder().decode(this.nonceBase64);
    }

    public byte[] getCiphertextBytes() {
        if (this.ciphertextBase64 == null) {
            throw new IllegalStateException("Ciphertext Base64 string is null.");
        }
        return Base64.getDecoder().decode(this.ciphertextBase64);
    }
}
```

### 2. Document and Validate

- **Javadoc:** Each field is documented, explaining Base64 encoding and intended usage.
- **Validation:** Constructor checks for nulls.

## Completion Criteria

- The JSON format is defined.
- The `EncryptedData` DTO is implemented.
- Base64 encoding/decoding is encapsulated.
- Ready for integration with Task 4 (Storage Backend).

## Future Enhancements

- Support for key rotation metadata (e.g., key IDs).
- Extended audit metadata (creator, expiration policies).
- Version 2+ format if structure evolves.

---
*Generated on April 28, 2025*
