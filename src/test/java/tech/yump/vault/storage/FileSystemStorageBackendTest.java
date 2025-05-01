package tech.yump.vault.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tech.yump.vault.auth.policy.PolicyDefinition;
import tech.yump.vault.config.MssmProperties;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileSystemStorageBackendTest {

  @TempDir // JUnit 5 creates a temporary directory for each test
  Path tempStorageDir;

  private FileSystemStorageBackend storageBackend;
  private ObjectMapper objectMapper;

  private final String testKey = "my/secret/path"; // Use a key with subdirectories
  private EncryptedData testData;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
    objectMapper.registerModule(new JavaTimeModule());

    // --- Corrected MssmProperties Instantiation ---

    // 1. Filesystem Properties
    MssmProperties.StorageProperties.FileSystemProperties fsProps =
            new MssmProperties.StorageProperties.FileSystemProperties(tempStorageDir.toString());

    // 2. Storage Properties
    MssmProperties.StorageProperties storageProps = new MssmProperties.StorageProperties(fsProps);

    // 3. Master Key Properties
    MssmProperties.MasterKeyProperties masterKeyProps =
            new MssmProperties.MasterKeyProperties("dummy-base64-key-for-test-setup");

    // 4. Static Token Auth Properties (Use emptyList for mappings)
    MssmProperties.AuthProperties.StaticTokenAuthProperties dummyStaticTokenProps =
            new MssmProperties.AuthProperties.StaticTokenAuthProperties(
                    false, // enabled=false
                    Collections.emptyList() // Use emptyList() for List<StaticTokenPolicyMapping>
            );

    // 5. Auth Properties
    MssmProperties.AuthProperties dummyAuthProps =
            new MssmProperties.AuthProperties(dummyStaticTokenProps);

    // 6. Top-level Policies List (Use emptyList)
    List<PolicyDefinition> dummyPolicies = Collections.emptyList();

    // 7. Create dummy Secrets Properties (since FileSystemStorageBackend doesn't use it)
    MssmProperties.SecretsProperties dummySecretsProps = new MssmProperties.SecretsProperties(null);

    // 8. Create dummy jwt props
    MssmProperties.JwtProperties dummyJwtProperties = new MssmProperties.JwtProperties(null);

    // 9. MssmProperties (Add dummySecretsProps as the 5th argument)
    MssmProperties testProperties = new MssmProperties(
            masterKeyProps,
            storageProps,
            dummyAuthProps,
            dummyPolicies,
            dummySecretsProps,
            dummyJwtProperties
    );

    // Instantiate the backend with the correctly structured properties
    storageBackend = new FileSystemStorageBackend(objectMapper, testProperties);

    // --- Test Data Setup (remains the same) ---
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

  // --- All other test methods (@Test ...) remain unchanged ---
  // They test the storageBackend directly, which now gets initialized correctly.

  @Test
  @DisplayName("Put then Get should retrieve the stored data")
  void putAndGet_Success() throws IOException {
    // Act
    storageBackend.put(testKey, testData);

    // Assert file exists (optional but good check)
    Path expectedFile = tempStorageDir.resolve(testKey + ".json");
    assertTrue(Files.exists(expectedFile), "Storage file should be created at " + expectedFile);
    assertTrue(Files.isRegularFile(expectedFile), "Path should point to a regular file");

    // Verify content (optional, more thorough)
    String fileContent = Files.readString(expectedFile, StandardCharsets.UTF_8);
    assertTrue(fileContent.contains(testData.getCiphertextBase64()), "File content should contain ciphertext");
    assertTrue(fileContent.contains(testData.getNonceBase64()), "File content should contain nonce");

    // Act - Get the data
    Optional<EncryptedData> retrievedDataOpt = storageBackend.get(testKey);

    // Assert
    assertTrue(retrievedDataOpt.isPresent(), "Data should be found for the key");
    assertEquals(testData.getNonceBase64(), retrievedDataOpt.get().getNonceBase64(), "Nonce should match");
    assertEquals(testData.getCiphertextBase64(), retrievedDataOpt.get().getCiphertextBase64(), "Ciphertext should match");
    assertEquals(testData.getVersion(), retrievedDataOpt.get().getVersion(), "Version should match");
    assertEquals(testData.getTimestamp(), retrievedDataOpt.get().getTimestamp(), "Timestamp should match");
  }

  @Test
  @DisplayName("Get should return empty Optional for non-existent key")
  void get_NonExistentKey_ReturnsEmpty() {
    String nonExistentKey = "this/key/does/not/exist";
    Optional<EncryptedData> retrievedDataOpt = storageBackend.get(nonExistentKey);
    assertTrue(retrievedDataOpt.isEmpty(), "Optional should be empty for non-existent key");
  }

  @Test
  @DisplayName("Put should overwrite existing data for the same key")
  void put_OverwritesExistingData() throws IOException {
    storageBackend.put(testKey, testData);
    String nonceB64 = Base64.getEncoder().encodeToString("new-nonce".getBytes(StandardCharsets.UTF_8));
    String cipherTextB64 = Base64.getEncoder().encodeToString("new-ciphertext".getBytes(StandardCharsets.UTF_8));
    EncryptedData newData = new EncryptedData(2, nonceB64, cipherTextB64, Instant.now());
    storageBackend.put(testKey, newData);
    Optional<EncryptedData> retrievedDataOpt = storageBackend.get(testKey);
    assertTrue(retrievedDataOpt.isPresent(), "Data should still be found");
    assertEquals(newData.getNonceBase64(), retrievedDataOpt.get().getNonceBase64(), "Nonce should match new data");
    assertEquals(newData.getCiphertextBase64(), retrievedDataOpt.get().getCiphertextBase64(), "Ciphertext should match new data");
  }


  @Test
  @DisplayName("Delete should remove the stored data file")
  void putThenDelete_RemovesData() throws IOException {
    storageBackend.put(testKey, testData);
    Path expectedFile = tempStorageDir.resolve(testKey + ".json");
    assertTrue(Files.exists(expectedFile), "Storage file should exist after put");
    storageBackend.delete(testKey);
    assertFalse(Files.exists(expectedFile), "Storage file should be deleted");
    Optional<EncryptedData> retrievedDataOpt = storageBackend.get(testKey);
    assertTrue(retrievedDataOpt.isEmpty(), "Optional should be empty after delete");
  }

  @Test
  @DisplayName("Delete should not throw error for non-existent key")
  void delete_NonExistentKey_DoesNotThrow() {
    String nonExistentKey = "this/key/also/does/not/exist";
    assertDoesNotThrow(() -> {
      storageBackend.delete(nonExistentKey);
    }, "Deleting a non-existent key should not throw an exception");
  }

  @Test
  @DisplayName("Put should throw StorageException for invalid key (directory traversal attempt)")
  void put_InvalidKeyTraversal_ThrowsStorageException() {
    String invalidKey = "../../etc/passwd";
    StorageException exception = assertThrows(StorageException.class, () -> {
      storageBackend.put(invalidKey, testData);
    }, "Putting with a traversal key should throw StorageException");
    // Check message based on the actual implementation (might check for "Invalid storage key format" or "path traversal")
    assertTrue(exception.getMessage().contains("Invalid storage key format") || exception.getMessage().contains("path traversal attempt"),
            "Exception message should indicate invalid path or traversal attempt");
  }

  @Test
  @DisplayName("Get should throw StorageException for invalid key (directory traversal attempt)")
  void get_InvalidKeyTraversal_ThrowsStorageException() {
    String invalidKey = "../secrets/somefile";
    StorageException exception = assertThrows(StorageException.class, () -> {
      storageBackend.get(invalidKey);
    }, "Getting with a traversal key should throw StorageException");
    assertTrue(exception.getMessage().contains("Invalid storage key format") || exception.getMessage().contains("path traversal attempt"),
            "Exception message should indicate invalid path or traversal attempt");
  }

  @Test
  @DisplayName("Delete should throw StorageException for invalid key (directory traversal attempt)")
  void delete_InvalidKeyTraversal_ThrowsStorageException() {
    String invalidKey = "valid/path/../../../etc/shadow";
    StorageException exception = assertThrows(StorageException.class, () -> {
      storageBackend.delete(invalidKey);
    }, "Deleting with a traversal key should throw StorageException");
    assertTrue(exception.getMessage().contains("Invalid storage key format") || exception.getMessage().contains("path traversal attempt"),
            "Exception message should indicate invalid path or traversal attempt");
  }

  @Test
  @DisplayName("Put should throw IllegalArgumentException for null key")
  void put_NullKey_ThrowsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.put(null, testData);
    });
  }

  @Test
  @DisplayName("Put should throw IllegalArgumentException for null data")
  void put_NullData_ThrowsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.put(testKey, null);
    });
  }

  @Test
  @DisplayName("Get should throw IllegalArgumentException for null key")
  void get_NullKey_ThrowsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.get(null);
    });
  }

  @Test
  @DisplayName("Delete should throw IllegalArgumentException for null key")
  void delete_NullKey_ThrowsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> {
      storageBackend.delete(null);
    });
  }

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