package tech.yump.vault.secrets.kv;

import java.util.Map;
import java.util.Optional;

/**
 * Interface for a Key/Value (KV) secrets engine.
 * Implementations handle the storage and retrieval of arbitrary key-value pairs
 * at specified logical paths, leveraging underlying encryption and storage backends.
 */
public interface KVSecretEngine {

    /**
     * Reads the secret data (key-value map) stored at the specified logical path.
     *
     * @param path The logical path where the secrets are stored (e.g., "kv/data/myapp/config").
     *             Must not be null or empty.
     * @return An Optional containing the Map of secrets if found, otherwise Optional.empty().
     * @throws KVEngineException If an error occurs during retrieval (e.g., decryption error, storage error).
     * @throws IllegalArgumentException if the path is invalid.
     */
    Optional<Map<String, String>> read(String path) throws KVEngineException;

    /**
     * Writes (creates or updates) the secret data (key-value map) at the specified logical path.
     * The entire map is stored as a single encrypted blob.
     *
     * @param path    The logical path where the secrets should be stored (e.g., "kv/data/myapp/config").
     *                Must not be null or empty.
     * @param secrets The Map of key-value pairs to store. Must not be null.
     * @throws KVEngineException If an error occurs during storage (e.g., encryption error, storage error).
     * @throws IllegalArgumentException if the path or secrets map is invalid.
     */
    void write(String path, Map<String, String> secrets) throws KVEngineException;

    /**
     * Deletes the secret data stored at the specified logical path.
     *
     * @param path The logical path of the secrets to delete (e.g., "kv/data/myapp/config").
     *             Must not be null or empty.
     * @throws KVEngineException If an error occurs during deletion (e.g., storage error).
     * @throws IllegalArgumentException if the path is invalid.
     */
    void delete(String path) throws KVEngineException;
}