package tech.yump.vault.crypto;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import tech.yump.vault.core.SealManager;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

@Slf4j
@Service
public class EncryptionService {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
      log.info("BouncyCastle provider added successfully.");
    }
  }

  private static final String ALGORITHM = "AES/GCM/NoPadding";
  private static final int TAG_LENGTH_BIT = 128; // Standard for GCM

  public static final int NONCE_LENGTH_BYTE = 12; // Recommended for GCM

  private final SecureRandom secureRandom = new SecureRandom();
  private final SealManager sealManager;

  public EncryptionService(SealManager sealManager) {
    this.sealManager = sealManager;
    log.info("EncryptionService initialized.");
  }

  // ... encryption/decryption methods will go here ...
  /**
   * Encrypts the given plaintext using AES-GCM with a unique nonce.
   * The nonce is prepended to the resulting ciphertext.
   *
   * @param plaintext The byte array to encrypt. Cannot be null.
   * @return A byte array containing the nonce prepended to the ciphertext (nonce || ciphertext).
   * @throws EncryptionException If any cryptographic error occurs during encryption.
   */
  public byte[] encrypt(byte[] plaintext) {
    if (plaintext == null) {
      throw new EncryptionException("Plaintext cannot be null.");
    }
    log.debug("Attempting to encrypt {} bytes of data.", plaintext.length);

    // --- Get Master Key (Checks Seals Status) ---
    SecretKey currentMasterKey = sealManager.getMasterKey();
    // --

    // 1. Generate unique nonce (IV)
    byte[] nonce = new byte[NONCE_LENGTH_BYTE];
    secureRandom.nextBytes(nonce);
    log.trace("Generated nonce ({} bytes).", nonce.length); // Avoid logging nonce value itself

    // 2. Create GCMParameterSpec
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, nonce);

    try {
      // 3. Get Cipher instance
      // Using default provider resolution, BC should be picked up if needed
      Cipher cipher = Cipher.getInstance(ALGORITHM);
      // 4. Initialize Cipher for encryption
      // --- Use Dynamic Key ---
      cipher.init(Cipher.ENCRYPT_MODE, currentMasterKey, gcmParameterSpec); // <-- ENCRYPT_MODE
      log.trace("Cipher initialized for encryption (AES/GCM/NoPadding).");

      // 5. Perform encryption
      byte[] ciphertext = cipher.doFinal(plaintext);
      log.debug("Encryption successful, ciphertext length: {} bytes.", ciphertext.length);

      // 6. Combine nonce and ciphertext
      // Result = nonce + ciphertext
      ByteBuffer byteBuffer = ByteBuffer.allocate(nonce.length + ciphertext.length);
      byteBuffer.put(nonce);
      byteBuffer.put(ciphertext);
      byte[] nonceAndCiphertext = byteBuffer.array();
      log.trace("Combined nonce and ciphertext, total length: {} bytes.", nonceAndCiphertext.length);

      // 7. Return combined result
      return nonceAndCiphertext;

    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
             InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
      // 8. Handle exceptions
      log.error("Encryption failed: {}", e.getMessage(), e);
      // Wrap in a custom runtime exception
      throw new EncryptionException("Failed to encrypt data.", e);
    }
  }

  /**
   * Decrypts the given byte array (expected format: nonce || ciphertext) using AES-GCM.
   * Verifies the integrity and authenticity using the embedded GCM tag.
   *
   * @param nonceAndCiphertext The byte array containing the nonce prepended to the ciphertext.
   *                           Must not be null and must be at least NONCE_LENGTH_BYTE bytes long.
   * @return The original plaintext byte array if decryption and authentication are successful.
   * @throws EncryptionException If decryption fails due to invalid input, incorrect key,
   *                             tampered data (bad authentication tag), or other cryptographic errors.
   */
  public byte[] decrypt(byte[] nonceAndCiphertext) {
    // 1. Validate input
    if (nonceAndCiphertext == null || nonceAndCiphertext.length < NONCE_LENGTH_BYTE) {
      throw new EncryptionException("Invalid input: Nonce and ciphertext array is null or too short.");
    }
    log.debug("Attempting to decrypt {} bytes of combined nonce and ciphertext.", nonceAndCiphertext.length);

    // --- Get Master Key (Checks Seal Status) ---
    SecretKey currentMasterKey = sealManager.getMasterKey();
    // --

    // Use ByteBuffer for easier extraction
    // 2. Extract nonce
    ByteBuffer bb = ByteBuffer.wrap(nonceAndCiphertext);
    byte[] nonce = new byte[NONCE_LENGTH_BYTE];
    bb.get(nonce);
    log.trace("Extracted nonce ({} bytes).", nonce.length);

    // 3. Extract ciphertext (the rest of the bytes)
    byte[] ciphertext = new byte[bb.remaining()];
    bb.get(ciphertext);
    log.trace("Extracted ciphertext ({} bytes).", ciphertext.length);

    // 4. Create GCMParameterSpec using the extracted nonce
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, nonce);

    try {
      // 5. Get Cipher instance
      Cipher cipher = Cipher.getInstance(ALGORITHM);
      // --- Use Dynamic Key ---
      cipher.init(Cipher.DECRYPT_MODE, currentMasterKey, gcmParameterSpec);
      log.trace("Cipher initialized for decryption (AES/GCM/NoPadding).");

      // 7. Perform decryption (includes authentication tag verification)
      byte[] plaintext = cipher.doFinal(ciphertext); // Use extracted ciphertext
      log.debug("Decryption successful, plaintext length: {} bytes.", plaintext.length);

      // 8. Return plaintext
      return plaintext;

    } catch (AEADBadTagException e) { // <-- Catch specific GCM tag failure
      // This is a critical security failure - indicates tampering or wrong key/nonce!
      log.error("Decryption failed due to invalid authentication tag (potential tampering or wrong key/nonce): {}", e.getMessage());
      throw new EncryptionException("Decryption failed: Invalid authentication tag. Data may be corrupt or tampered with.", e);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
             InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
      // Handle other potential crypto errors
      log.error("Decryption failed due to other cryptographic error: {}", e.getMessage(), e);
      throw new EncryptionException("Failed to decrypt data.", e);
    }
  }

  // --- Helper Exception Class ---
  /**
   * Custom runtime exception for encryption/decryption errors.
   */
  public static class EncryptionException extends RuntimeException {
    public EncryptionException(String message) {
      super(message);
    }
    public EncryptionException(String message, Throwable cause) {
      super(message, cause);
    }
  }

}
