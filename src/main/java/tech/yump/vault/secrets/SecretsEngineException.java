package tech.yump.vault.secrets;

/**
 * Base exception for errors occurring within any SecretsEngine implementation.
 */
public class SecretsEngineException extends RuntimeException {
    public SecretsEngineException(String message) {
        super(message);
    }

    public SecretsEngineException(String message, Throwable cause) {
        super(message, cause);
    }
}