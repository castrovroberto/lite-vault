package tech.yump.vault.storage;

import com.fasterxml.jackson.annotation.JsonProperty; // Optional but good practice
import java.time.Instant; // Use Instant for timestamps
import java.util.Base64; // For Base64 encoding/decoding logic (used later)
import lombok.AllArgsConstructor;
import lombok.Data; // Includes @Getter, @Setter, @ToString, @EqualsAndHashCode, @RequiredArgsConstructor
import lombok.NoArgsConstructor;

/**
 * Represents the structured format for storing encrypted data persistently.
 * This object is typically serialized to/deserialized from JSON.
 *
 * <pre>
 * {
 *   "v": 1,
 *   "n": "BASE64_ENCODED_NONCE",
 *   "c": "BASE64_ENCODED_CIPHERTEXT",
 *   "ts": 1678886400
 * }
 * </pre>
 */
@Data // Lombok: Generates getters, setters, toString, equals, hashCode
@NoArgsConstructor // Needed for Jackson deserialization
@AllArgsConstructor // Convenient for creating instances
public class EncryptedData {

  /**
   * Version number of this storage format. Starts at 1.
   * Mandatory.
   */
  @JsonProperty("v") // Explicit mapping (optional if field name matches)
  private int version = 1; // Default to version 1

  /**
   * The encryption nonce (12 bytes for AES-GCM), encoded as a Base64 String.
   * Mandatory.
   */
  @JsonProperty("n")
  private String nonceBase64;

  /**
   * The encrypted data (ciphertext), encoded as a Base64 String.
   * Mandatory.
   */
  @JsonProperty("c")
  private String ciphertextBase64;

  /**
   * Optional: Unix timestamp (seconds since epoch) when the data was encrypted.
   * Represented using Java's Instant internally, serialized as epoch seconds.
   */
  @JsonProperty("ts")
  private Instant timestamp; // Use Instant for better time handling

  // --- Convenience methods (to be used in Task 4/Storage layer) ---

  /**
   * Convenience constructor to create an EncryptedData object from raw nonce and ciphertext.
   * Handles Base64 encoding internally. Sets the timestamp to now.
   *
   * @param nonce      Raw nonce bytes (must be 12 bytes for AES-GCM).
   * @param ciphertext Raw ciphertext bytes.
   */
  public EncryptedData(byte[] nonce, byte[] ciphertext) {
    if (nonce == null || ciphertext == null) {
      throw new IllegalArgumentException("Nonce and ciphertext cannot be null.");
    }
    this.version = 1;
    // Use standard Base64 encoding
    this.nonceBase64 = Base64.getEncoder().encodeToString(nonce);
    this.ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);
    this.timestamp = Instant.now(); // Set timestamp on creation
  }

  /**
   * Decodes the Base64 nonce string back into raw bytes.
   *
   * @return Raw nonce bytes.
   * @throws IllegalArgumentException if nonceBase64 is null or not valid Base64.
   */
  public byte[] getNonceBytes() {
    if (this.nonceBase64 == null) {
      throw new IllegalStateException("Nonce Base64 string is null.");
    }
    return Base64.getDecoder().decode(this.nonceBase64);
  }

  /**
   * Decodes the Base64 ciphertext string back into raw bytes.
   *
   * @return Raw ciphertext bytes.
   * @throws IllegalArgumentException if ciphertextBase64 is null or not valid Base64.
   */
  public byte[] getCiphertextBytes() {
    if (this.ciphertextBase64 == null) {
      throw new IllegalStateException("Ciphertext Base64 string is null.");
    }
    return Base64.getDecoder().decode(this.ciphertextBase64);
  }
}