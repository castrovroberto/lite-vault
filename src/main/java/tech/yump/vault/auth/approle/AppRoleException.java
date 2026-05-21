package tech.yump.vault.auth.approle;

public class AppRoleException extends RuntimeException {

    public AppRoleException(String message) {
        super(message);
    }

    public AppRoleException(String message, Throwable cause) {
        super(message, cause);
    }

    public static class RoleNotFoundException extends AppRoleException {
        public RoleNotFoundException(String roleName) {
            super("AppRole not found: " + roleName);
        }
    }

    public static class InvalidCredentialsException extends AppRoleException {
        public InvalidCredentialsException(String reason) {
            super("Invalid AppRole credentials: " + reason);
        }
    }

    public static class SecretIdExhaustedException extends AppRoleException {
        public SecretIdExhaustedException() {
            super("Secret ID has already been used");
        }
    }
}
