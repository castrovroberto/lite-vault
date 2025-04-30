# Task 26: Implement Basic Lease Management (In-Memory)

Okay, let's implement Task 26: Implement Basic Lease Management (In-Memory).The goal is to store the details of the Lease objects generated in Task 25 within the PostgresSecretsEngine itself, using a simple in-memory map. This allows us to associate a unique ID with each generated credential set and its lifetime, which is crucial for future revocation (even though we won't implement the full revocation logic in this task).Here are the steps:Step 1: Add Lease Storage Field1.Open /Users/robertocastro/dev/lite-vault/src/main/java/tech/yump/vault/secrets/db/PostgresSecretsEngine.java.2.Add an import for java.util.concurrent.ConcurrentHashMap.3.Declare a ConcurrentHashMap field to store the active leases. The key will be the UUID of the lease, and the value will be the Lease object itself. Using ConcurrentHashMap ensures thread safety if multiple requests generate leases concurrently.

 // ... other imports ...
 import java.util.UUID;
+import java.util.concurrent.ConcurrentHashMap; // Import ConcurrentHashMap

 /**
  * Secrets Engine implementation for dynamically generating PostgreSQL credentials.
@@ -20,8 +21,8 @@
     private final JdbcTemplate jdbcTemplate; // Spring Boot auto-configures this based on primary DataSource

     // Connection pool is managed by the injected DataSource (HikariCP by default)
-    // TODO: Add fields for storing role definitions loaded from properties (Task 23) - maybe cache them?
-    // TODO: Add fields for in-memory lease tracking (Task 26)
+    // TODO: Cache role definitions loaded from properties (Task 23) for performance?
+    private final ConcurrentHashMap<UUID, Lease> activeLeases = new ConcurrentHashMap<>(); // Task 26: In-memory lease tracking

     /**
      * Simple check after initialization to verify DB connection using the configured DataSource.

Step 2: Store Lease in generateCredentials1.Locate the generateCredentials method.2.After the Lease object is successfully created (near the end of the method), add the code to put it into the activeLeases map.

 // ... inside generateCredentials method ...

         Lease lease = new Lease(
                 leaseId,
                 "postgres", // Engine name/type
                 roleName,
                 secretData,
                 creationTime,
                 ttl,
                 false // Renewable: false for now (implement renewal later if needed)
         );

-        // 6. Store lease details (in-memory map) - TODO in Task 26
-        log.debug("Lease created with ID: {}, TTL: {}", lease.id(), lease.ttl());
-        // leaseTracker.addLease(lease); // This will be added in Task 26
+        // 6. Store lease details in the in-memory map (Task 26)
+        activeLeases.put(lease.id(), lease);
+        log.debug("Lease {} added to active lease tracker. Current active leases: {}", lease.id(), activeLeases.size());

         log.info("Successfully generated credentials and lease for DB role: {}", roleName);
         // 7. Return Lease

Step 3: Implement Lease Retrieval Helper1.Add a private helper method to retrieve a lease by its ID from the map. This will be used by the revokeLease method.

    // --- Helper methods ---

    /**
     * Retrieves an active lease by its ID from the in-memory tracker.
     *
     * @param leaseId The UUID of the lease to retrieve.
     * @return An Optional containing the Lease if found, otherwise Optional.empty().
     */
    private Optional<Lease> getLeaseById(UUID leaseId) {
        return Optional.ofNullable(activeLeases.get(leaseId));
    }

    // ... other helper methods (generatePassword, generateUsername, etc.) ...

Step 4: Update revokeLease Placeholder1.Modify the revokeLease method to use the getLeaseById helper.2.Retrieve the lease details (especially the username) needed for the (future) revocation SQL.3.Add the logic to remove the lease from the activeLeases map after the (future) successful execution of revocation SQL. For now, we'll keep the actual removal commented out until the SQL part is implemented, but we'll perform the lookup.

     @Override
     public void revokeLease(UUID leaseId) throws SecretsEngineException, LeaseNotFoundException {
-        log.warn("PostgresSecretsEngine.revokeLease for lease ID '{}' is not yet implemented.", leaseId);
-        // TODO: Implement lease revocation logic (Future Task, beyond Phase 3 initial scope)
-        // 1. Look up lease details (username) from in-memory map using leaseId (Task 26)
+        log.info("Attempting to revoke lease with ID: {}", leaseId);
+
+        // 1. Look up lease details from in-memory map using leaseId (Task 26)
+        Lease lease = getLeaseById(leaseId)
+                .orElseThrow(() -> {
+                    log.warn("Lease not found in active tracker: {}", leaseId);
+                    return new LeaseNotFoundException(leaseId);
+                });
+
+        String username = (String) lease.secretData().get("username");
+        if (username == null) {
+             // Should not happen if lease was stored correctly, but handle defensively
+             log.error("Cannot revoke lease {}: username missing in lease data.", leaseId);
+             // Remove the potentially corrupted lease entry anyway?
+             activeLeases.remove(leaseId);
+             throw new SecretsEngineException("Internal error: Username not found for lease " + leaseId);
+        }
+        log.debug("Found lease {} for username '{}'. Proceeding with revocation logic.", leaseId, username);
+
         // 2. Look up role configuration (revocation SQL) (Task 23)
-        // 3. Get connection from DataSource/pool (Task 24)
-        // 4. Execute revocation SQL
-        // 5. Remove lease from in-memory map (Task 26)
-        throw new UnsupportedOperationException("revokeLease not implemented yet");
+        MssmProperties.PostgresRoleDefinition roleDefinition = properties.secrets().db().postgres().roles().get(lease.roleName());
+        if (roleDefinition == null) {
+            // Role might have been removed from config since lease was created. Still try to revoke.
+            log.warn("Role definition '{}' not found for revoking lease {}, but proceeding with generic cleanup attempt if possible.", lease.roleName(), leaseId);
+            // Or should we fail here? For now, let's allow attempting revocation without specific statements if needed later.
+            // For now, we need the statements defined in the task.
+             throw new SecretsEngineException("Role definition '" + lease.roleName() + "' not found, cannot determine revocation SQL for lease " + leaseId);
+        }
+
+        // 3. Prepare revocation SQL (using username, no password needed)
+        // Note: Using a simplified version of prepareSqlStatements for revocation
+        List<String> revocationSqlStatements = roleDefinition.revocationStatements().stream()
+                .map(sql -> sql.replace("{{username}}", username))
+                .toList();
+
+        // 4. Execute revocation SQL statements using jdbcTemplate
+        log.debug("Executing revocation SQL statements for lease '{}', username '{}'", leaseId, username);
+        try {
+            for (String sql : revocationSqlStatements) {
+                log.trace("Executing SQL: {}", sql); // Log SQL only at TRACE level
+                jdbcTemplate.execute(sql);
+            }
+            log.info("Successfully executed revocation SQL for lease '{}', username '{}'", leaseId, username);
+
+            // 5. Remove lease from in-memory map AFTER successful revocation (Task 26)
+            activeLeases.remove(leaseId);
+            log.info("Successfully revoked and removed lease: {}. Remaining active leases: {}", leaseId, activeLeases.size());
+
+        } catch (DataAccessException e) {
+            log.error("Database error executing revocation SQL for lease '{}', username '{}': {}",
+                    leaseId, username, e.getMessage(), e);
+            // If revocation fails, should we keep the lease in the map?
+            // Yes, probably. The credential might still exist in the DB.
+            throw new SecretsEngineException("Failed to execute credential revocation SQL for lease: " + leaseId, e);
+        }
+        // Remove the old placeholder exception
+        // throw new UnsupportedOperationException("revokeLease SQL execution not implemented yet");
     }

Self-correction: Task 26 description says "Actual revocation might be deferred or implemented simply". Let's actually implement the SQL execution part for revokeLease now, as it's straightforward using the configured revocationStatements and completes the basic dynamic secret lifecycle (create -> revoke). We'll use the same pattern as in generateCredentials.Step 5: Test1.Run the Application.2.Generate a Credential: Use curl to hit the GET /v1/db/creds/{role_name} endpoint (Task 27). Note the leaseId returned in the response.

    TOKEN="dev-root-token"
    ROLE="readonly-app-role"
    RESPONSE=$(curl -s -k -H "X-Vault-Token: $TOKEN" https://localhost:8443/v1/db/creds/$ROLE)
    echo "Response: $RESPONSE"
    LEASE_ID=$(echo $RESPONSE | jq -r '.leaseId') # Requires jq tool
    USERNAME=$(echo $RESPONSE | jq -r '.username')
    echo "Generated Lease ID: $LEASE_ID"
    echo "Generated Username: $USERNAME"
    

3.Check Logs: Verify that the application logs show the lease being added to the tracker (e.g., Lease ... added to active lease tracker. Current active leases: 1).4.Check Database: Verify the user (e.g., lv-readonly-app-role-...) exists in the target PostgreSQL database.5.(Optional) Implement Revocation Endpoint (Task Not Explicitly Defined, but needed for testing): To test revocation easily, we need an API endpoint. Let's quickly add one to DbController.•Add a DELETE /leases/{leaseId} endpoint to DbController.java:

        // Inside DbController.java

        /**
         * Revokes a specific database credential lease.
         * Requires authentication and likely specific admin/revocation capabilities.
         *
         * @param leaseId The UUID of the lease to revoke.
         * @return ResponseEntity indicating success (204 No Content) or failure.
         */
        @DeleteMapping("/leases/{leaseId}") // Use DELETE for revocation
        @ResponseStatus(HttpStatus.NO_CONTENT) // Return 204 on success
        public void revokeDbLease(@PathVariable UUID leaseId) {
            log.info("Received request to revoke DB lease: {}", leaseId);
            try {
                postgresSecretsEngine.revokeLease(leaseId); // Call the engine method
                log.info("Successfully processed revocation request for lease: {}", leaseId);
            } catch (LeaseNotFoundException | SecretsEngineException e) {
                // Let exception handlers defined in this controller handle the response
                throw e;
            }
            // No body needed for 204 response
        }
        

•Add Policy (if needed): Ensure a policy exists that grants DELETE capability on a path like db/leases/* and assign it to your test token in application-dev.yml.

        # In mssm.policies:
        - name: "db-admin-policy" # Example new policy
          rules:
            - path: "db/leases/*"
              capabilities: [DELETE] # Or maybe UPDATE/WRITE depending on convention

        # In mssm.auth.static-tokens.mappings (add to root token or create specific token):
        - token: "dev-root-token"
          policyNames: ["root-policy", "db-admin-policy"] # Add the new policy
        

6.Test Revocation: Use curl to hit the new revocation endpoint with the leaseId obtained earlier.

    echo "Attempting to revoke lease: $LEASE_ID"
    curl -s -k -X DELETE -H "X-Vault-Token: $TOKEN" https://localhost:8443/v1/db/leases/$LEASE_ID -o /dev/null -w "%{http_code}\n"
    # Expected output: 204
    

7.Check Logs: Verify logs show the lease being found, revocation SQL executing, and the lease being removed from the tracker (e.g., Successfully revoked and removed lease... Remaining active leases: 0).8.Check Database: Verify the user (e.g., lv-readonly-app-role-...) has been dropped from the target PostgreSQL database.With these steps, you have implemented basic in-memory lease tracking and integrated it into the generation and revocation flow, completing Task 26 and the core dynamic secret lifecycle for PostgreSQL.