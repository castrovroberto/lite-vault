package tech.yump.vault.storage;

/**
 * Custom runtime exception for errors occurring within the StorageBackend implementation.
 */
public class StorageException extends RuntimeException {

  public StorageException(String message) {
    super(message);
  }

  public StorageException(String message, Throwable cause) {
    super(message, cause);
  }
}