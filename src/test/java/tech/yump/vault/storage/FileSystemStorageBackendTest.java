package tech.yump.vault.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule; // Import JavaTimeModule
import java.time.Instant;
import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tech.yump.vault.config.MssmProperties; // Import

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class FileSystemStorageBackendTest {

  @TempDir // JUnit 5 creates a temporary directory for each test
  Path tempStorageDir;

  private FileSystemStorageBackend storageBackend;
  private ObjectMapper objectMapper;
  private MssmProperties testProperties;

  private final String testKey = "my/secret/path"; // Use a key with subdirectories
  private EncryptedData testData;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
    objectMapper.registerModule(new JavaTimeModule());

    MssmProperties.StorageProperties.FileSystemProperties fsProps =
        new MssmProperties.StorageProperties.FileSystemProperties(tempStorageDir.toString());

    MssmProperties.StorageProperties storageProps = new MssmProperties.StorageProperties(fsProps);

    MssmProperties.MasterKeyProperties masterKeyProps = new MssmProperties.MasterKeyProperties("dummy-base64-key-for-test-setup");

    MssmProperties.AuthProperties.StaticTokenAuthProperties dummyStaticTokenProps =
        new MssmProperties.AuthProperties.StaticTokenAuthProperties(false, Collections.emptySet()); // enabled=false, empty tokens

    MssmProperties.AuthProperties dummyAuthProps =
        new MssmProperties.AuthProperties(dummyStaticTokenProps);

    testProperties = new MssmProperties(masterKeyProps, storageProps, dummyAuthProps);

    storageBackend = new FileSystemStorageBackend(objectMapper, testProperties);

    String nonceB64 = Base64.getEncoder().encodeToString("test-nonce-123".getBytes(StandardCharsets.UTF_8));
    String ciphertextB64 = Base64.getEncoder().encodeToString("test-ciphertext-abc".getBytes(StandardCharsets.UTF_8));
    int version = 1;
    Instant timestamp = Instant.now();

    testData = new EncryptedData(
        version,
        nonceB64,
        ciphertextB64,
        timestamp
    );
  }

  @Test
  @DisplayName("Put then Get should retrieve the stored data")
  void putAndGet_Success() throws IOException {
    // Act
    storageBackend.put(testKey, testData);

    // Assert file exists (optional but good check)
    // Path should be relative to tempStorageDir
    Path expectedFile = tempStorageDir.resolve(testKey + ".json");
    assertTrue(Files.exists(expectedFile), "Storage file should be created at " + expectedFile);
    assertTrue(Files.isRegularFile(expectedFile), "Path should point to a regular file");

    // Verify content (optional, more thorough)
    String fileContent = Files.readString(expectedFile, StandardCharsets.UTF_8);
    assertTrue(fileContent.contains(testData.getCiphertextBase64()), "File content should contain ciphertext");
    assertTrue(fileContent.contains(testData.getNonceBase64()), "File content should contain nonce");
    // Optional: Verify timestamp format in file if needed

    // Act - Get the data
    Optional<EncryptedData> retrievedDataOpt = storageBackend.get(testKey);

    // Assert
    assertTrue(retrievedDataOpt.isPresent(), "Data should be found for the key");
    // Compare relevant fields, timestamp might differ slightly if re-serialized
    assertEquals(testData.getNonceBase64(), retrievedDataOpt.get().getNonceBase64(), "Nonce should match");
    assertEquals(testData.getCiphertextBase64(), retrievedDataOpt.get().getCiphertextBase64(), "Ciphertext should match");
    assertEquals(testData.getVersion(), retrievedDataOpt.get().getVersion(), "Version should match");
    // Compare timestamps - Instant comparison should work with JavaTimeModule
    assertEquals(testData.getTimestamp(), retrievedDataOpt.get().getTimestamp(), "Timestamp should match");
  }

  @Test
  @DisplayName("Get should return empty Optional for non-existent key")
  void get_NonExistentKey_ReturnsEmpty() {
    // Arrange (no put call)
    String nonExistentKey = "this/key/does/not/exist";

    // Act
    Optional<EncryptedData> retrievedDataOpt = storageBackend.get(nonExistentKey);

    // Assert
    assertTrue(retrievedDataOpt.isEmpty(), "Optional should be empty for non-existent key");
  }

  @Test
  @DisplayName("Put should overwrite existing data for the same key")
  void put_OverwritesExistingData() throws IOException {
    // Arrange - Put initial data
    storageBackend.put(testKey, testData);

    String nonceB64 = Base64.getEncoder().encodeToString("new-nonce".getBytes(StandardCharsets.UTF_8));
    String cipherTextB64 = Base64.getEncoder().encodeToString("new-ciphertext".getBytes(StandardCharsets.UTF_8));
    int version = 2;
    Instant timestamp = Instant.now();

    // Create new data
    EncryptedData newData = new EncryptedData(
        version,
        nonceB64,
        cipherTextB64,
        timestamp
    );

    // Act - Put new data with the same key
    storageBackend.put(testKey, newData);

    // Assert - Get should return the new data
    Optional<EncryptedData> retrievedDataOpt = storageBackend.get(testKey);
    assertTrue(retrievedDataOpt.isPresent(), "Data should still be found");
    assertEquals(newData.getNonceBase64(), retrievedDataOpt.get().getNonceBase64(), "Nonce should match new data");
    assertEquals(newData.getCiphertextBase64(), retrievedDataOpt.get().getCiphertextBase64(), "Ciphertext should match new data");
    assertEquals(newData.getVersion(), retrievedDataOpt.get().getVersion(), "Version should match new data");
    assertEquals(newData.getTimestamp(), retrievedDataOpt.get().getTimestamp(), "Timestamp should match new data");
  }


  @Test
  @DisplayName("Delete should remove the stored data file")
  void putThenDelete_RemovesData() throws IOException {
    // Arrange - Put data first
    storageBackend.put(testKey, testData);
    Path expectedFile = tempStorageDir.resolve(testKey + ".json");
    assertTrue(Files.exists(expectedFile), "Storage file should exist after put");

    // Act - Delete the data
    storageBackend.delete(testKey);

    // Assert - File should be gone
    assertFalse(Files.exists(expectedFile), "Storage file should be deleted");

    // Assert - Get should now return empty
    Optional<EncryptedData> retrievedDataOpt = storageBackend.get(testKey);
    assertTrue(retrievedDataOpt.isEmpty(), "Optional should be empty after delete");
  }

  @Test
  @DisplayName("Delete should not throw error for non-existent key")
  void delete_NonExistentKey_DoesNotThrow() {
    // Arrange (no put call)
    String nonExistentKey = "this/key/also/does/not/exist";

    // Act & Assert
    assertDoesNotThrow(() -> {
      storageBackend.delete(nonExistentKey);
    }, "Deleting a non-existent key should not throw an exception");

    // Also check that no unexpected files were created/deleted
    // (Difficult to assert definitively without listing directory, but absence of error is primary goal)
  }

  @Test
  @DisplayName("Put should throw StorageException for invalid key (directory traversal attempt)")
  void put_InvalidKeyTraversal_ThrowsStorageException() {
    // Arrange
    String invalidKey = "../../etc/passwd"; // Classic traversal attempt

    // Act & Assert
    StorageException exception = assertThrows(StorageException.class, () -> {
      storageBackend.put(invalidKey, testData);
    }, "Putting with a traversal key should throw StorageException");

    assertTrue(exception.getMessage().contains("Invalid storage key format"), "Exception message should indicate invalid path");
  }

  @Test
  @DisplayName("Get should throw StorageException for invalid key (directory traversal attempt)")
  void get_InvalidKeyTraversal_ThrowsStorageException() {
    // Arrange
    String invalidKey = "../secrets/somefile";

    // Act & Assert
    StorageException exception = assertThrows(StorageException.class, () -> {
      storageBackend.get(invalidKey);
    }, "Getting with a traversal key should throw StorageException");

    assertTrue(exception.getMessage().contains("Invalid storage key format"), "Exception message should indicate invalid path");
  }

  @Test
  @DisplayName("Delete should throw StorageException for invalid key (directory traversal attempt)")
  void delete_InvalidKeyTraversal_ThrowsStorageException() {
    // Arrange
    String invalidKey = "valid/path/../../../etc/shadow";

    // Act & Assert
    StorageException exception = assertThrows(StorageException.class, () -> {
      storageBackend.delete(invalidKey);
    }, "Deleting with a traversal key should throw StorageException");

    assertTrue(exception.getMessage().contains("Invalid storage key format"), "Exception message should indicate invalid path");
  }

  @Test
  @DisplayName("Put should throw IllegalArgumentException for null key")
  void put_NullKey_ThrowsIllegalArgumentException() {
    // FIX 2: Assert IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.put(null, testData);
    });
  }

  @Test
  @DisplayName("Put should throw IllegalArgumentException for null data")
  void put_NullData_ThrowsIllegalArgumentException() {
    // FIX 2: Assert IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.put(testKey, null);
    });
  }

  @Test
  @DisplayName("Get should throw IllegalArgumentException for null key")
  void get_NullKey_ThrowsIllegalArgumentException() {
    // This test was already correct
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.get(null);
    });
  }

  @Test
  @DisplayName("Delete should throw IllegalArgumentException for null key")
  void delete_NullKey_ThrowsIllegalArgumentException() {
    // FIX 2: Assert IllegalArgumentException
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.delete(null);
    });
  }

  // Optional: Add tests for empty string keys if StringUtils.hasText allows them
  @Test
  @DisplayName("Put should throw IllegalArgumentException for empty key")
  void put_EmptyKey_ThrowsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.put("", testData);
    });
  }

  @Test
  @DisplayName("Get should throw IllegalArgumentException for empty key")
  void get_EmptyKey_ThrowsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.get("");
    });
  }

  @Test
  @DisplayName("Delete should throw IllegalArgumentException for empty key")
  void delete_EmptyKey_ThrowsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.delete("");
    });
  }
}