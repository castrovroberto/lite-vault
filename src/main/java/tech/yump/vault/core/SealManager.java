package tech.yump.vault.core;

import jakarta.annotation.PostConstruct;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Slf4j
@Service // Singleton bean to manage the global seal state
public class SealManager {

  // Use AtomicReference for thread-safe updates and visibility
  private final AtomicReference<SealStatus> currentStatus = new AtomicReference<>(SealStatus.SEALED);
  private final AtomicReference<SecretKey> masterKey = new AtomicReference<>(null);

  private static final String AES = "AES";
  private static final int EXPECTED_KEY_LENGTH = 32; // For AES-256

  // Inject the master key from environment/properties (Base64 encoded)
  // Defaults to null if not provided.
  @Value("${mssm.master.key.b64:#{null}}")
  private String initialMasterKeyBase64;

  /**
   * Attempts to automatically unseal the vault on startup if a master key is provided
   * via configuration (environment variable or application property).
   */
  @PostConstruct
  private void initializeSealStatus() {
    log.info("Initializing SealManager...");
    if (StringUtils.hasText(initialMasterKeyBase64)) {
      log.info("Attempting automatic unseal using provided configuration key...");
      try {
        unseal(initialMasterKeyBase64);
        // Success logged within unseal method
      } catch (Exception e) {
        // Log error but remain sealed. Manual unseal might be needed via API later.
        log.error("Automatic unseal failed: {}. Vault remains SEALED.", e.getMessage());
        // Ensure state is definitely sealed if unseal failed partially (though unlikely here)
        seal();
      }
    } else {
      log.warn("No initial master key provided via 'mssm.master.key.b64'. Vault remains SEALED.");
      // Ensure state is sealed (should be default, but explicit)
      seal();
    }
  }

  /**
   * Attempts to unseal the vault using the provided Base64 encoded master key.
   *
   * @param base64Key The Base64 encoded AES-256 master key (32 bytes raw).
   * @throws IllegalArgumentException if the key is invalid (null, empty, bad Base64, wrong length).
   * @throws VaultSealedException if already unsealed (or handle differently if re-keying is desired later).
   */
  public synchronized void unseal(String base64Key) { // Synchronized for atomicity of check-then-act
    if (currentStatus.get() == SealStatus.UNSEALED) {
      log.warn("Vault is already unsealed. Ignoring unseal request.");
      // Or throw new VaultSealedException("Vault is already unsealed.");
      return;
    }

    log.info("Attempting to unseal vault...");
    if (!StringUtils.hasText(base64Key)) {
      throw new IllegalArgumentException("Master key cannot be null or empty.");
    }

    byte[] keyBytes;
    try {
      keyBytes = Base64.getDecoder().decode(base64Key);
    } catch (IllegalArgumentException e) {
      log.error("Failed to decode Base64 master key.");
      throw new IllegalArgumentException("Invalid Base64 encoding for master key.", e);
    }

    if (keyBytes.length != EXPECTED_KEY_LENGTH) {
      log.error("Invalid master key length. Expected {} bytes, but got {}.", EXPECTED_KEY_LENGTH, keyBytes.length);
      throw new IllegalArgumentException("Invalid master key length. Expected " + EXPECTED_KEY_LENGTH + " bytes for AES-256.");
    }

    // Create the SecretKey object
    SecretKey newMasterKey = new SecretKeySpec(keyBytes, AES);

    // Atomically set the key and status
    this.masterKey.set(newMasterKey);
    this.currentStatus.set(SealStatus.UNSEALED);

    // Clear the raw key bytes from memory ASAP (though SecretKeySpec likely copies it)
    java.util.Arrays.fill(keyBytes, (byte) 0);

    log.info("Vault successfully UNSEALED.");
  }

  /**
   * Seals the vault, clearing the master key from memory.
   */
  public synchronized void seal() { // Synchronized for atomicity
    if (currentStatus.get() == SealStatus.SEALED) {
      log.debug("Vault is already sealed.");
      return;
    }
    log.warn("Sealing the vault. Master key will be cleared from memory.");
    this.masterKey.set(null); // Clear the key reference
    this.currentStatus.set(SealStatus.SEALED);
    log.info("Vault is now SEALED.");
    // Suggest GC, though no guarantee it runs immediately or clears the actual old key object memory
    System.gc();
  }

  /**
   * Checks if the vault is currently sealed.
   *
   * @return true if sealed, false otherwise.
   */
  public boolean isSealed() {
    return currentStatus.get() == SealStatus.SEALED;
  }

  /**
   * Gets the current seal status.
   *
   * @return The current SealStatus (SEALED or UNSEALED).
   */
  public SealStatus getSealStatus() {
    return currentStatus.get();
  }

  /**
   * Retrieves the master key if the vault is unsealed.
   *
   * @return The SecretKey instance.
   * @throws VaultSealedException if the vault is currently sealed.
   */
  public SecretKey getMasterKey() throws VaultSealedException {
    SecretKey key = masterKey.get(); // Get current reference
    if (key == null || currentStatus.get() == SealStatus.SEALED) {
      // Check status again in case of race condition, though AtomicReference helps
      if (currentStatus.get() == SealStatus.SEALED) {
        log.warn("Attempted to access master key while vault is SEALED.");
        throw new VaultSealedException("Vault is sealed. Cannot perform operation requiring the master key.");
      } else {
        // Should not happen if key is null but status is UNSEALED, indicates an issue.
        log.error("Inconsistent state: Vault is UNSEALED but master key reference is null!");
        seal(); // Force back to a consistent sealed state
        throw new VaultSealedException("Vault state inconsistent, forcing seal. Operation failed.");
      }
    }
    return key;
  }
}