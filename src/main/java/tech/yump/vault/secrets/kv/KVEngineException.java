package tech.yump.vault.secrets.kv;

/**
 * Custom exception for errors occurring within the KVSecretEngine.
 */
public class KVEngineException extends RuntimeException {

    public KVEngineException(String message) {
        super(message);
    }

    public KVEngineException(String message, Throwable cause) {
        super(message, cause);
    }
}