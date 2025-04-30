package tech.yump.vault.audit;

/**
 * Interface for audit logging backends.
 * Defines the contract for recording audit events.
 */
public interface AuditBackend {

    /**
     * Logs a given audit event.
     * Implementations determine *how* the event is logged (e.g., to console, file, database).
     *
     * @param event The AuditEvent to log. Must not be null.
     */
    void logEvent(AuditEvent event);

}