package tech.yump.vault.core;

/**
 * Exception thrown when an operation requiring the master key is attempted
 * while the vault is in a SEALED state.
 */
public class VaultSealedException extends RuntimeException {
  public VaultSealedException(String message) {
    super(message);
  }
}