package tech.yump.vault.secrets;

/**
 * Exception thrown when a requested role configuration is not found.
 */
public class RoleNotFoundException extends SecretsEngineException {
    public RoleNotFoundException(String roleName) {
        super("Role not found or configured: " + roleName);
    }
}