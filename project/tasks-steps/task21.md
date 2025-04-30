# Task 21: Define Core Secrets Engine Interfaces

Okay, let's move on to Phase 3 and tackle Task 21: Define Core Secrets Engine Interfaces.This task is about setting up the foundational Java interfaces and data structures that all secrets engines (both the existing KV one and the future dynamic ones like PostgreSQL) will adhere to. This promotes consistency and makes it easier to add new engines later (NFR-MTN-500).Here's a step-by-step guide to accomplish Task 21:Step 1: Create the Base Secrets PackageIf it doesn't exist already, create the base package where secrets engine-related interfaces and classes will reside. Based on your existing structure (tech.yump.vault.secrets.kv), a good place would be:

src/main/java/tech/yump/vault/secrets/

Step 2: Define the Generic SecretsEngine InterfaceThis will be the top-level interface that all secrets engines implement. For now, it can be a simple marker interface, establishing the type. We can add common methods later if needed (e.g., getType()).Create the file src/main/java/tech/yump/vault/secrets/SecretsEngine.java:

package tech.yump.vault.secrets;

/**
 * Base marker interface for all secrets engines within LiteVault.
 * Implementations manage different types of secrets (static, dynamic, etc.).
 */
public interface SecretsEngine {
    // Currently a marker interface.
    // Common methods like String getType() or boolean isDynamic() could be added later.
}

Step 3: Define the Lease Data StructureThis object will hold information about dynamically generated secrets and their lifetime. A Java record is a good fit here.Create the file src/main/java/tech/yump/vault/secrets/Lease.java:

package tech.yump.vault.secrets;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Represents a lease associated with a dynamically generated secret.
 * Contains the secret data, metadata about its lifetime, and renewal status.
 *
 * @param id           A unique identifier for this specific lease instance.
 * @param engineName   The name or type of the secrets engine that generated this lease (e.g., "postgres").
 * @param roleName     The specific role configuration used to generate the secret.
 * @param secretData   The actual generated secret credentials or data (e.g., username, password).
 *                     Using Map<String, Object> for flexibility across different secret types.
 * @param creationTime The timestamp when the lease (and secret) was created.
 * @param ttl          The initial time-to-live duration granted to the lease.
 * @param renewable    Flag indicating if this lease can be renewed.
 */
public record Lease(
    UUID id,
    String engineName,
    String roleName,
    Map<String, Object> secretData,
    Instant creationTime,
    Duration ttl,
    boolean renewable
) {
    /**
     * Calculates the expiration time based on creation time and TTL.
     *
     * @return The Instant when this lease expires.
     */
    public Instant getExpirationTime() {
        return creationTime.plus(ttl);
    }
}

•UUID id: Ensures unique identification for revocation/renewal.•String engineName, String roleName: Context about how the secret was generated.•Map<String, Object> secretData: Flexible storage for credentials (e.g., {"username": "user123", "password": "..."}).•Instant creationTime: Standard Java time.•Duration ttl: Standard Java duration.•boolean renewable: Simple flag.Step 4: Define the DynamicSecretsEngine InterfaceThis interface extends the base SecretsEngine and adds methods specific to engines that generate secrets dynamically with leases.Create the file src/main/java/tech/yump/vault/secrets/DynamicSecretsEngine.java:

package tech.yump.vault.secrets;

import java.util.UUID;

/**
 * Interface for secrets engines that generate dynamic secrets with leases.
 * Extends the base SecretsEngine interface.
 */
public interface DynamicSecretsEngine extends SecretsEngine {

    /**
     * Generates new credentials based on a configured role.
     *
     * @param roleName The name of the role configuration to use for generation.
     * @return A Lease object containing the generated secret data and lease metadata.
     * @throws SecretsEngineException If credential generation fails (e.g., configuration error, backend error).
     * @throws RoleNotFoundException If the specified roleName does not exist or is not configured.
     */
    Lease generateCredentials(String roleName) throws SecretsEngineException, RoleNotFoundException;

    /**
     * Revokes an existing lease, invalidating the associated secret.
     * Implementations should attempt to clean up the generated secret (e.g., drop DB user).
     *
     * @param leaseId The unique ID of the lease to revoke.
     * @throws SecretsEngineException If revocation fails (e.g., backend error).
     * @throws LeaseNotFoundException If the specified leaseId does not exist or is not managed by this engine.
     */
    void revokeLease(UUID leaseId) throws SecretsEngineException, LeaseNotFoundException;

    // Potential future methods:
    // Lease renewLease(UUID leaseId, Duration requestedDuration) throws SecretsEngineException, LeaseNotFoundException, LeaseNotRenewableException;
}

•It extends SecretsEngine.•generateCredentials returns the Lease object defined in Step 3.•revokeLease takes the UUID from the Lease.•We define placeholder exceptions (SecretsEngineException, RoleNotFoundException, LeaseNotFoundException) that we'll need to create.Step 5: Create Base Exception ClassesCreate the necessary exception classes used in DynamicSecretsEngine.Create src/main/java/tech/yump/vault/secrets/SecretsEngineException.java:

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

Create src/main/java/tech/yump/vault/secrets/RoleNotFoundException.java:

package tech.yump.vault.secrets;

/**
 * Exception thrown when a requested role configuration is not found.
 */
public class RoleNotFoundException extends SecretsEngineException {
    public RoleNotFoundException(String roleName) {
        super("Role not found or configured: " + roleName);
    }
}

Create src/main/java/tech/yump/vault/secrets/LeaseNotFoundException.java:

package tech.yump.vault.secrets;

import java.util.UUID;

/**
 * Exception thrown when a requested lease ID is not found.
 */
public class LeaseNotFoundException extends SecretsEngineException {
    public LeaseNotFoundException(UUID leaseId) {
        super("Lease not found: " + leaseId);
    }
}

Step 6: Update Existing KVSecretEngine (Optional but Recommended)Modify the existing KVSecretEngine to also implement the base SecretsEngine interface for consistency.Open src/main/java/tech/yump/vault/secrets/kv/KVSecretEngine.java and change its definition:

 package tech.yump.vault.secrets.kv;

 import java.util.Map;
 import java.util.Optional;
+import tech.yump.vault.secrets.SecretsEngine; // Import the base interface

 /**
  * Interface for a Key/Value (KV) secrets engine.
  * Implementations handle the storage and retrieval of arbitrary key-value pairs
  * at specified logical paths, leveraging underlying encryption and storage backends.
  */
-public interface KVSecretEngine {
+public interface KVSecretEngine extends SecretsEngine { // Extend the base interface

     /**
      * Reads the secret data (key-value map) stored at the specified logical path.


(No other changes needed inside KVSecretEngine.java)Summary of Created/Modified Files:•src/main/java/tech/yump/vault/secrets/SecretsEngine.java (New)•src/main/java/tech/yump/vault/secrets/Lease.java (New)•src/main/java/tech/yump/vault/secrets/DynamicSecretsEngine.java (New)•src/main/java/tech/yump/vault/secrets/SecretsEngineException.java (New)•src/main/java/tech/yump/vault/secrets/RoleNotFoundException.java (New)•src/main/java/tech/yump/vault/secrets/LeaseNotFoundException.java (New)•src/main/java/tech/yump/vault/secrets/kv/KVSecretEngine.java (Modified)With these steps completed, you have successfully defined the core interfaces and data structures required for implementing dynamic secrets engines, fulfilling Task 21. You can now commit these changes before proceeding to Task 22 (Implement PostgreSQL Secrets Engine Core).