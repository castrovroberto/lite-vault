package tech.yump.vault.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tech.yump.vault.core.SealManager;
import tech.yump.vault.core.VaultSealedException; // Import for testing sealed state

import javax.crypto.AEADBadTagException; // For checking cause
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays; // For array comparison

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*; // Import Mockito static methods

@ExtendWith(MockitoExtension.class) // Enable Mockito integration with JUnit 5
class EncryptionServiceTest {

  @Mock // Create a mock instance of SealManager
  private SealManager mockSealManager;

  @InjectMocks // Create an instance of EncryptionService and inject mocks into it
  private EncryptionService encryptionService;

  private SecretKey testKey; // A fixed key for predictable tests
  private byte[] samplePlaintext;

  @BeforeEach
  void setUp() {
    // Create a fixed, known key for testing purposes
    byte[] keyBytes = new byte[32]; // 32 bytes for AES-256
    // Use a fixed seed for reproducibility if needed, or just random for each run
    new SecureRandom().nextBytes(keyBytes);
    testKey = new SecretKeySpec(keyBytes, "AES");

    samplePlaintext = "This is my secret data!".getBytes();

    // Default mock behavior: Assume vault is unsealed and return the test key
    // This setup runs before each @Test method
    // 'lenient()' prevents Mockito from complaining if a test doesn't use this specific mock interaction
    lenient().when(mockSealManager.getMasterKey()).thenReturn(testKey);
  }

  @Test
  @DisplayName("Encrypt then Decrypt should return original plaintext when unsealed")
  void encryptDecrypt_RoundTrip_Success() {
    // Arrange (already done in setUp)

    // Act
    byte[] encryptedData = encryptionService.encrypt(samplePlaintext);
    assertNotNull(encryptedData, "Encrypted data should not be null");
    // AES-GCM adds 12 bytes nonce + 16 bytes tag = 28 bytes overhead minimum
    assertTrue(encryptedData.length > samplePlaintext.length, "Encrypted data should be longer than plaintext");

    byte[] decryptedData = encryptionService.decrypt(encryptedData);

    // Assert
    assertNotNull(decryptedData, "Decrypted data should not be null");
    assertArrayEquals(samplePlaintext, decryptedData, "Decrypted data should match original plaintext");

    // Verify that getMasterKey was called (once for encrypt, once for decrypt)
    verify(mockSealManager, times(2)).getMasterKey();
  }

  @Test
  @DisplayName("Encrypt should throw VaultSealedException when vault is sealed")
  void encrypt_WhenSealed_ThrowsVaultSealedException() {
    // Arrange
    // Override default mock behavior for this test: throw exception when sealed
    when(mockSealManager.getMasterKey()).thenThrow(new VaultSealedException("Vault is sealed"));

    // Act & Assert
    VaultSealedException exception = assertThrows(VaultSealedException.class, () -> {
      encryptionService.encrypt(samplePlaintext);
    }, "Encryption should throw VaultSealedException when sealed");

    assertEquals("Vault is sealed", exception.getMessage(), "Exception message should indicate sealed state");

    // Verify getMasterKey was called
    verify(mockSealManager, times(1)).getMasterKey();
  }

  @Test
  @DisplayName("Decrypt should throw VaultSealedException when vault is sealed")
  void decrypt_WhenSealed_ThrowsVaultSealedException() {
    // Arrange
    // Encrypt first (using default unsealed mock setup) to get valid encrypted data
    byte[] encryptedData = encryptionService.encrypt(samplePlaintext);
    assertNotNull(encryptedData);

    // Now, configure mock to throw exception for the decrypt call
    when(mockSealManager.getMasterKey()).thenThrow(new VaultSealedException("Vault is sealed"));

    // Act & Assert
    VaultSealedException exception = assertThrows(VaultSealedException.class, () -> {
      encryptionService.decrypt(encryptedData);
    }, "Decryption should throw VaultSealedException when sealed");

    assertEquals("Vault is sealed", exception.getMessage(), "Exception message should indicate sealed state");

    // Verify getMasterKey was called (once for encrypt, once for decrypt attempt)
    verify(mockSealManager, times(2)).getMasterKey();
  }

  @Test
  @DisplayName("Decrypt should throw EncryptionException for tampered ciphertext (bad tag)")
  void decrypt_WhenCiphertextTampered_ThrowsEncryptionException() {
    // Arrange
    byte[] encryptedData = encryptionService.encrypt(samplePlaintext);
    assertNotNull(encryptedData);

    // Tamper with the ciphertext part (after the 12-byte nonce)
    // Flip a bit in the first byte of the actual ciphertext
    final int nonceLength = 12; // As defined in EncryptionService
    if (encryptedData.length > nonceLength) {
      encryptedData[nonceLength] = (byte) (encryptedData[nonceLength] ^ 1); // XOR to flip a bit
    } else {
      fail("Encrypted data is too short to tamper with ciphertext part");
    }

    // Act & Assert
    EncryptionService.EncryptionException exception = assertThrows(EncryptionService.EncryptionException.class, () -> {
      encryptionService.decrypt(encryptedData);
    }, "Decryption should throw EncryptionException for tampered data");

    // Check if the message or cause indicates a tag mismatch
    assertTrue(exception.getMessage().contains("Invalid authentication tag"), "Exception message should indicate tag issue");
    assertNotNull(exception.getCause(), "Exception should have a cause");
    // More specific check for the underlying JCE exception
    assertTrue(exception.getCause() instanceof AEADBadTagException, "Cause should be AEADBadTagException");

    // Verify getMasterKey was called (once for encrypt, once for decrypt attempt)
    verify(mockSealManager, times(2)).getMasterKey();
  }

  @Test
  @DisplayName("Encrypt should throw EncryptionException for null plaintext")
  void encrypt_NullPlaintext_ThrowsEncryptionException() {
    // Arrange
    byte[] nullPlaintext = null;

    // Act & Assert
    EncryptionService.EncryptionException exception = assertThrows(EncryptionService.EncryptionException.class, () -> {
      encryptionService.encrypt(nullPlaintext);
    });

    assertTrue(exception.getMessage().contains("Plaintext cannot be null"));
    // Verify getMasterKey was NOT called because validation happens first
    verify(mockSealManager, never()).getMasterKey();
  }

  @Test
  @DisplayName("Decrypt should throw EncryptionException for null input")
  void decrypt_NullInput_ThrowsEncryptionException() {
    // Arrange
    byte[] nullInput = null;

    // Act & Assert
    EncryptionService.EncryptionException exception = assertThrows(EncryptionService.EncryptionException.class, () -> {
      encryptionService.decrypt(nullInput);
    });

    assertTrue(exception.getMessage().contains("Invalid input"));
    // Verify getMasterKey was NOT called
    verify(mockSealManager, never()).getMasterKey();
  }

  @Test
  @DisplayName("Decrypt should throw EncryptionException for input shorter than nonce length")
  void decrypt_InputTooShort_ThrowsEncryptionException() {
    // Arrange
    byte[] shortInput = new byte[EncryptionService.NONCE_LENGTH_BYTE - 1]; // One byte too short

    // Act & Assert
    EncryptionService.EncryptionException exception = assertThrows(EncryptionService.EncryptionException.class, () -> {
      encryptionService.decrypt(shortInput);
    });

    assertTrue(exception.getMessage().contains("too short"));
    // Verify getMasterKey was NOT called
    verify(mockSealManager, never()).getMasterKey();
  }
}