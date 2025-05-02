package tech.yump.vault.storage;

import java.util.List; // <-- Added import
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

  /**
   * Checks if the given relative path corresponds to a directory within the storage backend.
   *
   * @param relativePath The path relative to the storage root (e.g., "jwt/keys/my-key/versions").
   * Must not be null or empty, and should not contain ".." or leading/trailing slashes.
   * @return true if the path exists and is a directory, false otherwise.
   * @throws StorageException If an error occurs accessing the storage or if the path is invalid.
   */
  boolean isDirectory(String relativePath) throws StorageException; // <-- Added this method

  /**
   * Lists the entries (files and directories) within the specified relative directory path.
   *
   * @param relativeDirPath The path relative to the storage root (e.g., "jwt/keys/my-key/versions").
   * Must not be null or empty, and should not contain ".." or leading/trailing slashes.
   * @return A list of entry names (filenames or subdirectory names) within the specified directory.
   * Returns an empty list if the directory is empty or does not exist.
   * @throws StorageException If an error occurs accessing the storage or if the path is invalid or not a directory.
   */
  List<String> listDirectory(String relativeDirPath) throws StorageException; // <-- Added this method

}