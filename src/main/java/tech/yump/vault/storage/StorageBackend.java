package tech.yump.vault.storage;

import java.util.Optional;

/**
 * Interface defining the contract for persistent storage backends.
 * Implementations handle the physical storage and retrieval of encrypted data blobs.
 */
public interface StorageBackend {

  /**
   * Persists the encrypted data associated with the given key.
   * If data already exists for the key, it should be overwritten.
   *
   * @param key  The unique logical key identifying the data (e.g., "secrets/myapp/db-password").
   *             Must not be null or empty.
   * @param data The EncryptedData object to store. Must not be null.
   * @throws StorageException If an error occurs during persistence (e.g., I/O error, serialization error).
   */
  void put(String key, EncryptedData data) throws StorageException;

  /**
   * Retrieves the encrypted data associated with the given key.
   *
   * @param key The unique logical key identifying the data. Must not be null or empty.
   * @return An Optional containing the EncryptedData if found, otherwise Optional.empty().
   * @throws StorageException If an error occurs during retrieval (e.g., I/O error, deserialization error).
   */
  Optional<EncryptedData> get(String key) throws StorageException;

  /**
   * Deletes the encrypted data associated with the given key.
   * If the key does not exist, this method should do nothing and not throw an error.
   *
   * @param key The unique logical key identifying the data to delete. Must not be null or empty.
   * @throws StorageException If an error occurs during deletion (e.g., I/O error).
   */
  void delete(String key) throws StorageException;

  // Optional: Add methods like list(String prefix) later if needed.
}