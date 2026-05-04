# Detailed Implementation Plan: Task #42 - DB Lease Revocation

This plan elaborates on the verification and refinement steps for the existing DB Lease Revocation functionality, ensuring robustness, testability, and security within the LiteVault layered architecture.

---

## Phase 1: Verify & Refine Core Engine Logic (PostgresSecretsEngine)

### 1. Review Existing `revokeLease` Method

* **Goal:** Ensure the existing method in `PostgresSecretsEngine` correctly and robustly handles lease revocation based on configured SQL statements.
* **File:** `lite-vault/src/main/java/tech/yump/vault/secrets/db/PostgresSecretsEngine.java`

* **Detailed Actions & Recommendations:**

    1.  **Lease Existence Check:**
        * **Verify:** The method starts by fetching the lease using `activeLeases.get(leaseId)`.
        * **Code Snippet (Conceptual):**
            ```java
            // Inside revokeLease(String leaseId)
            Lease lease = activeLeases.get(leaseId);
            if (lease == null) {
                auditHelper.logInternalEvent(
                    "DB Lease Revocation Failed: Lease not found",
                    Map.of("leaseId", leaseId, "engine", "Postgres")
                );
                throw new LeaseNotFoundException("Lease not found with ID: " + leaseId);
            }
            ```
        * **Recommendation:** Ensure the `LeaseNotFoundException` is thrown *before* any database interaction attempts if the lease ID is invalid. Confirm the audit log captures this specific failure case.

    2.  **Role Definition Retrieval:**
        * **Verify:** The code correctly retrieves the `PostgresRoleDefinition` using `properties.secrets().db().postgres().roles().get(lease.roleName())`.
        * **Code Snippet (Conceptual):**
            ```java
            // After finding the lease
            PostgresRoleDefinition roleDefinition = properties.secrets().db().postgres().roles().get(lease.roleName());
            if (roleDefinition == null) {
                 auditHelper.logInternalEvent(
                     "DB Lease Revocation Failed: Role definition missing",
                     Map.of("leaseId", leaseId, "roleName", lease.roleName(), "engine", "Postgres")
                 );
                throw new SecretsEngineException("Role definition not found for role: " + lease.roleName());
            }
            ```
        * **Recommendation:** Confirm that a missing role definition results in a `SecretsEngineException` and an appropriate audit log entry. This prevents errors later when trying to access `revocationStatements`.

    3.  **Revocation Statements Processing:**
        * **Verify:** Confirm `roleDefinition.revocationStatements()` returns the expected `List<String>`.
        * **Recommendation:** Consider the case where `revocationStatements` might be null or empty in the configuration. While perhaps not strictly an error (maybe revocation isn't needed), it's worth deciding if this should log a warning or proceed silently. Current logic seems to handle an empty list gracefully (loop won't execute).
            ```java
            List<String> revocationStmts = roleDefinition.revocationStatements();
            if (revocationStmts == null || revocationStmts.isEmpty()) {
                log.warn("No revocation statements found for role '{}', lease '{}'. Lease entry will be removed, but no DB actions taken.", lease.roleName(), leaseId);
                // Or potentially throw, depending on desired strictness.
                // For now, proceeding likely makes sense.
            } else {
               // ... process statements ...
            }
            ```

    4.  **Placeholder Replacement & Quoting:**
        * **Verify:** The replacement logic `sql.replace("{{username}}", quotedUsername)` is used. Crucially, verify that `quotedUsername` is derived correctly using `quotePostgresIdentifier(lease.username())`.
        * **Method:** `quotePostgresIdentifier(String identifier)`
        * **Code Snippet (Inside `quotePostgresIdentifier`):**
            ```java
            // Example logic (ensure it matches yours):
            if (identifier == null) {
                return null; // Or handle as error
            }
            // Replace existing double quotes with escaped double quotes and wrap in double quotes
            return "\"" + identifier.replace("\"", "\"\"") + "\"";
            ```
        * **Recommendation:** Double-check the `quotePostgresIdentifier` implementation against PostgreSQL identifier rules. The main concern is handling embedded double quotes (`""`) correctly. Usernames like `user"name` or `user's name` (if allowed) should be handled. The current approach seems reasonable for standard quoted identifiers. Ensure it doesn't inadvertently quote *already quoted* identifiers if that's a possibility.

    5.  **SQL Execution:**
        * **Verify:** Each statement is executed via `jdbcTemplate.execute(sql)`.
        * **Recommendation:** For roles with multiple revocation statements, consider if they need to be executed transactionally. Currently, they run independently. If statement 1 succeeds but statement 2 fails, the resource might be partially revoked. For simple `DROP ROLE` / `DROP USER` type statements, transactional execution might not be critical, but for more complex cleanup, it could be. This is likely *not* required for typical revocation scenarios but worth a thought.
            ```java
            // Current (non-transactional loop):
            for (String rawSql : revocationStmts) {
                 // ... replacement ...
                 jdbcTemplate.execute(finalSql);
            }

            // Alternative (transactional - more complex):
            // transactionTemplate.execute(status -> {
            //    for (String rawSql : revocationStmts) {
            //       // ... replacement ...
            //       jdbcTemplate.execute(finalSql);
            //    }
            //    return null; // Indicate success
            // });
            ```
        * **Stick with the current non-transactional approach unless a strong need for atomicity across *multiple* revocation statements is identified.**

    6.  **Error Handling (Database):**
        * **Verify:** `DataAccessException` from `jdbcTemplate.execute` is caught and wrapped in a `SecretsEngineException`.
        * **Code Snippet (Conceptual):**
            ```java
            catch (DataAccessException e) {
                auditHelper.logInternalEvent(
                    "DB Lease Revocation Failed: Database error",
                    Map.of("leaseId", leaseId, "roleName", lease.roleName(), "username", lease.username(), "error", e.getMessage(), "engine", "Postgres")
                );
                throw new SecretsEngineException("Failed to execute revocation statement for lease " + leaseId + ": " + e.getMessage(), e);
            }
            ```
        * **Recommendation:** Ensure the wrapped exception includes enough context (lease ID, potentially the failing SQL *without sensitive data*) and the original `DataAccessException` as the cause. Ensure the audit log captures the error.

    7.  **Lease Removal:**
        * **Verify:** `activeLeases.remove(leaseId)` is called *only after* all configured revocation SQL statements have executed successfully.
        * **Recommendation:** This is critical. If the lease is removed before successful SQL execution, a subsequent retry (manual or automated) might fail because the lease metadata is gone, even if the underlying DB resource still exists.

    8.  **Auditing:**
        * **Verify:** `auditHelper.logInternalEvent` is called for both successful revocation and all failure scenarios (lease not found, role missing, DB error).
        * **Recommendation:** Ensure audit messages are distinct and provide sufficient context (lease ID, username, role, engine type, success/failure status, error message if applicable).

* **Rationale:** These checks confirm the engine's core responsibility: translating a lease ID into correct, safe SQL execution against the database, updating internal state, and logging appropriately.

---

### 2. Enhance Unit Tests (`PostgresSecretsEngineTest`)

* **Goal:** Achieve comprehensive, isolated unit testing of the `revokeLease` method's logic and edge cases.
* **File:** `lite-vault/src/test/java/tech/yump/vault/secrets/db/PostgresSecretsEngineTest.java`

* **Detailed Actions & Recommendations:**

    1.  **Review Existing Tests:** The tests `revokeLease_Success`, `revokeLease_LeaseNotFound`, `revokeLease_RoleDefinitionMissing`, `revokeLease_DbErrorOnRevocation` provide a good foundation.

    2.  **Test Case: Special Characters in Username:**
        * **Action:** Add a test specifically for usernames requiring quoting.
        * **Code Example (Mockito/JUnit 5):**
            ```java
            @Test
            void revokeLease_whenUsernameRequiresQuoting_thenExecutesQuotedSql() {
                // Arrange
                String leaseId = "l-123";
                String roleName = "test-role";
                String username = "user\"with\"quotes"; // Username needing quotes
                String expectedQuotedUsername = "\"user\"\"with\"\"quotes\""; // How it should look in SQL
                Lease lease = new Lease(leaseId, /* other fields */, username, roleName);
                PostgresRoleDefinition roleDef = new PostgresRoleDefinition(/*...*/, List.of("DROP ROLE {{username}};"));
                Map<String, Lease> activeLeases = new ConcurrentHashMap<>();
                activeLeases.put(leaseId, lease);

                when(properties.secrets().db().postgres().roles().get(roleName)).thenReturn(roleDef);
                // Inject mock jdbcTemplate, auditHelper, properties, and the activeLeases map

                // Use ArgumentCaptor to capture the SQL executed
                ArgumentCaptor<String> sqlCaptor = ArgumentCaptor.forClass(String.class);

                // Act
                postgresSecretsEngine.revokeLease(leaseId); // Assuming engine is set up with mocks and the map

                // Assert
                verify(jdbcTemplate).execute(sqlCaptor.capture());
                String executedSql = sqlCaptor.getValue();
                assertEquals("DROP ROLE " + expectedQuotedUsername + ";", executedSql); // Verify exact SQL
                assertFalse(activeLeases.containsKey(leaseId)); // Verify lease removed
                verify(auditHelper).logInternalEvent(eq("DB Lease Revoked Successfully"), anyMap()); // Verify success audit
            }
            ```

    3.  **Verify SQL Execution:**
        * **Recommendation:** Always use `ArgumentCaptor` as shown above to capture the *exact* string passed to `jdbcTemplate.execute`. This verifies both placeholder replacement and quoting logic simultaneously. Verify it's called the correct number of times if multiple statements exist.

    4.  **Verify State (`activeLeases`):**
        * **Recommendation:** Inject the `activeLeases` map into the test subject (perhaps using reflection if direct injection isn't feasible, or by making it package-private for testing). Assert that the lease ID is present before the call (in failure cases) or absent after the call (in the success case). Mocking `activeLeases.remove` and verifying the call is also a valid approach.
            ```java
            // Inside a test
            // ... setup ...
            postgresSecretsEngine.revokeLease(leaseId);
            // ... verify jdbcTemplate etc ...

            // Option 1: If map is accessible
            // assertFalse(activeLeasesUsedByEngine.containsKey(leaseId));

            // Option 2: Mocking the map (if injected as a mock)
            // verify(mockActiveLeases).remove(leaseId);
            ```

    5.  **Verify Audit Logs:**
        * **Recommendation:** Use `verify` with `eq()` matchers for the event type string and potentially `anyMap()` or more specific map matchers for the details, depending on how critical the exact audit content is for the test. Verify *no* audit logs are sent if the operation should fail silently (though usually revocation failures *should* be logged).
            ```java
            // Example: Verify specific failure audit
             verify(auditHelper).logInternalEvent(
                 eq("DB Lease Revocation Failed: Lease not found"),
                 argThat(map -> map.containsKey("leaseId") && map.get("leaseId").equals(leaseId))
             );
            ```

* **Rationale:** Thorough unit tests isolate the engine's logic, ensuring it behaves correctly under various conditions (valid input, invalid input, errors, special characters) without needing a real database or other components.

---

## Phase 2: Verify Service Layer (DbCredentialServiceImpl)

### 1. Review Existing `revokeCredentialLease` Method

* **Goal:** Confirm the service layer correctly and simply delegates revocation to the engine.
* **File:** `lite-vault/src/main/java/tech/yump/vault/service/DbCredentialServiceImpl.java`

* **Detailed Actions & Recommendations:**

    1.  **Verify Delegation:**
        * **Action:** Check that the method body consists primarily of a single call: `postgresSecretsEngine.revokeLease(leaseId);`.
        * **Code Snippet (Should look like this):**
            ```java
            @Override
            public void revokeCredentialLease(String leaseId) {
                // Optional: Add Seal Check if desired, though likely handled by engine/controller advice
                // sealManager.ensureUnsealed(); // Or similar check

                log.info("Revoking database credential lease: {}", leaseId);
                try {
                    postgresSecretsEngine.revokeLease(leaseId);
                    log.info("Successfully revoked database credential lease: {}", leaseId);
                    // Note: Success audit logging happens in the Controller or Engine layer typically.
                } catch (LeaseNotFoundException | SecretsEngineException e) {
                    log.error("Failed to revoke lease {}: {}", leaseId, e.getMessage());
                    throw e; // Propagate specific exceptions
                } catch (Exception e) {
                    // Catch unexpected exceptions if necessary, but usually let framework handle
                    log.error("Unexpected error revoking lease {}: {}", leaseId, e.getMessage(), e);
                    throw new RuntimeException("Unexpected error during lease revocation", e); // Or specific service exception
                }
            }
            ```
        * **Recommendation:** Avoid adding complex logic here. The service layer's primary role is orchestration and transaction management (if needed, though not typical for single revocations). Ensure logging provides basic visibility.

    2.  **Exception Propagation:**
        * **Verify:** Confirm that `LeaseNotFoundException` and `SecretsEngineException` thrown by the engine are propagated upwards (not caught and swallowed or unnecessarily wrapped).
        * **Recommendation:** If a `VaultSealedException` could theoretically occur (e.g., if the engine or its dependencies check the seal status), ensure it's also propagated correctly. Currently, the plan notes the engine doesn't check, so this might be handled implicitly by the `ControllerAdvice` if other layers trigger it.

* **Rationale:** Keeps the service layer thin and focused on delegation for this specific action, relying on lower layers for core logic and upper layers/advice for request/response handling.

---

### 2. Review Unit Tests (`DbCredentialServiceImplTest`)

* **Goal:** Ensure the service layer's delegation and exception propagation are correctly tested.
* **File:** `lite-vault/src/test/java/tech/yump/vault/service/DbCredentialServiceImplTest.java`

* **Detailed Actions & Recommendations:**

    1.  **Review Existing Tests:** The tests `revokeCredentialLease_Success`, `revokeCredentialLease_PropagatesLeaseNotFound`, `revokeCredentialLease_PropagatesVaultSealed` (if applicable), `revokeCredentialLease_PropagatesSecretsEngineException` seem appropriate.

    2.  **Verify Mock Interaction:**
        * **Action:** Ensure all tests rigorously verify that `postgresSecretsEngine.revokeLease(leaseId)` was called exactly once with the correct `leaseId`.
        * **Code Example (Mockito):**
            ```java
            @Test
            void revokeCredentialLease_Success_delegatesToEngine() {
                // Arrange
                String leaseId = "l-abc";
                // Configure mock postgresSecretsEngine to do nothing on revokeLease
                doNothing().when(postgresSecretsEngine).revokeLease(leaseId);

                // Act
                dbCredentialService.revokeCredentialLease(leaseId);

                // Assert
                verify(postgresSecretsEngine, times(1)).revokeLease(leaseId);
            }
            ```

    3.  **Verify Exception Propagation:**
        * **Action:** For each exception type the service is expected to propagate, configure the mock engine to throw it and assert that the service call results in that same exception being thrown.
        * **Code Example (Mockito/JUnit 5):**
            ```java
            @Test
            void revokeCredentialLease_whenEngineThrowsLeaseNotFound_propagatesException() {
                // Arrange
                String leaseId = "l-not-found";
                LeaseNotFoundException expectedException = new LeaseNotFoundException("Test not found");
                doThrow(expectedException).when(postgresSecretsEngine).revokeLease(leaseId);

                // Act & Assert
                LeaseNotFoundException thrown = assertThrows(LeaseNotFoundException.class, () -> {
                    dbCredentialService.revokeCredentialLease(leaseId);
                });
                assertSame(expectedException, thrown); // Assert it's the *same* exception instance
                verify(postgresSecretsEngine, times(1)).revokeLease(leaseId);
            }
            ```

* **Rationale:** These tests confirm the service layer behaves as a simple pass-through for this functionality, correctly invoking the engine and handling its outcomes as expected.

---

## Phase 3: Verify API Layer (DbController) & Security

### 1. Review Existing `revokeDbLease` Endpoint

* **Goal:** Confirm the controller correctly exposes the revocation functionality via `DELETE /v1/db/leases/{leaseId}` and handles responses/errors appropriately.
* **File:** `lite-vault/src/main/java/tech/yump/vault/api/DbController.java`

* **Detailed Actions & Recommendations:**

    1.  **Verify Mapping:**
        * **Action:** Ensure the method is annotated correctly.
        * **Code Snippet (Annotations):**
            ```java
            @DeleteMapping("/leases/{leaseId}")
            @ResponseStatus(HttpStatus.NO_CONTENT) // Can be here or use ResponseEntity
            // Consider adding OpenAPI annotations for documentation
            // @Operation(summary = "Revoke a database credential lease")
            // @Parameter(name = "leaseId", description = "ID of the lease to revoke", required = true)
            // @ApiResponse(responseCode = "204", description = "Lease revoked successfully")
            // @ApiResponse(responseCode = "404", description = "Lease not found")
            // @ApiResponse(responseCode = "403", description = "Permission denied")
            // @ApiResponse(responseCode = "500", description = "Internal server error")
            // @ApiResponse(responseCode = "503", description = "Vault is sealed")
            public ResponseEntity<Void> revokeDbLease(
                    @PathVariable String leaseId,
                    HttpServletRequest request // Inject request for audit context
            ) { // ... implementation ... }
            ```

    2.  **Verify Delegation:**
        * **Action:** Confirm the method calls `dbCredentialService.revokeCredentialLease(leaseId)`.

    3.  **Verify Success Response:**
        * **Action:** Ensure a successful revocation returns an HTTP 204 No Content response.
        * **Code Snippet (Return):**
            ```java
            dbCredentialService.revokeCredentialLease(leaseId);
            // Success audit log should happen *after* the service call returns without exception
            auditHelper.logHttpEvent(request, Map.of("leaseId", leaseId), 204, "DB Lease Revoked");
            return ResponseEntity.noContent().build();
            ```
        * **Recommendation:** Return `ResponseEntity<Void>` and use `ResponseEntity.noContent().build()`.

    4.  **Verify Exception Handling:**
        * **Action:** Confirm the controller does *not* have explicit `try-catch` blocks for `LeaseNotFoundException`, `SecretsEngineException`, `VaultSealedException`, or security exceptions. Instead, verify reliance on the `GlobalExceptionHandler` (`@ControllerAdvice`).
        * **File:** `lite-vault/src/main/java/tech/yump/vault/api/advice/GlobalExceptionHandler.java`
        * **Recommendation:** Review `GlobalExceptionHandler` to ensure these mappings exist:
            * `LeaseNotFoundException` -> `HttpStatus.NOT_FOUND` (404)
            * `SecretsEngineException` -> `HttpStatus.INTERNAL_SERVER_ERROR` (500)
            * `VaultSealedException` -> `HttpStatus.SERVICE_UNAVAILABLE` (503)
            * `AccessDeniedException` (Spring Security) -> `HttpStatus.FORBIDDEN` (403)
            * Ensure the exception handlers also call `auditHelper.logHttpEvent` to record the failed request and its response code.

    5.  **Verify Audit Logging:**
        * **Action:** Confirm `auditHelper.logHttpEvent` is called within the controller method *only on the success path*.
        * **Recommendation:** As mentioned above, ensure failure path auditing (4xx, 5xx errors) is handled consistently within the `GlobalExceptionHandler`. Pass relevant context like the `leaseId` to the audit helper.

* **Rationale:** Ensures the API endpoint is correctly wired, follows REST conventions (DELETE method, 204 success code), delegates to the service, and relies on centralized exception handling and auditing for cleaner code.

---

### 2. Define and Verify Security Policy (ACLs)

* **Goal:** Ensure the revocation endpoint (`DELETE /v1/db/leases/{leaseId}`) is protected by the policy system and requires specific, documented permissions.
* **Files:**
    * Policy definitions (likely `application.yml` or a dedicated policy store/file).
    * `lite-vault/src/main/java/tech/yump/vault/config/SecurityConfig.java` (where filters are wired).
    * `lite-vault/src/main/java/tech/yump/vault/auth/PolicyEnforcementFilter.java` (where enforcement happens).

* **Detailed Actions & Recommendations:**

    1.  **Identify/Define Policy Rule:**
        * **Action:** Locate or define the policy rule governing this endpoint. The path needs to match the API route.
        * **Path Matching:** The policy path should likely be `db/leases/*` or `db/leases/{leaseId}` (depending on the matching system's capabilities - glob `*` is common). Remember that API paths often map to logical policy paths which might not be identical but should correspond clearly. Assume `/v1` is stripped before policy matching, so `db/leases/*` seems appropriate.
        * **Capability:** The required capability is `DELETE` (or potentially `UPDATE` if `DELETE` isn't granular enough, but `DELETE` is conventional for revocation).
        * **Code Example (YAML Policy Snippet in `application.yml`):**
            ```yaml
            mssm:
              policies:
                # Example: Policy for DB Operators
                db-operator:
                  rules:
                    # Allow creating/reading leases
                    - path: "db/creds/*"
                      capabilities: ["CREATE", "READ"]
                    # Allow reading/listing/deleting leases
                    - path: "db/leases/*" # Matches /v1/db/leases/{leaseId}
                      capabilities: ["READ", "LIST", "DELETE"] # Explicitly add DELETE
                    # ... other rules ...
                # Example: Root token policy (implicitly covers it)
                root:
                  rules:
                    - path: "*"
                      capabilities: ["*"] # Or list all capabilities explicitly

              tokens:
                # Example: Token associated with the db-operator policy
                - token: "t.dboperator_token_value"
                  policies: ["db-operator"]
                # Root token
                - token: "t.root_token_value" # Make sure this is loaded securely
                  policies: ["root"]
            ```
        * **Recommendation:** Define explicit, least-privilege policies for roles that need to revoke leases rather than solely relying on the root token for operations.

    2.  **Document Requirements:**
        * **Action:** Clearly state in documentation (e.g., API docs, admin manual) that revoking a lease requires a token with the `DELETE` capability on the `db/leases/*` path.

    3.  **Verify `PolicyEnforcementFilter`:**
        * **Action:** Briefly review `PolicyEnforcementFilter.java` to confirm it correctly maps the HTTP `DELETE` method to the internal `PolicyCapability.DELETE` enum value when checking permissions.
        * **Code Snippet (Conceptual Check in Filter):**
            ```java
            // Inside PolicyEnforcementFilter.doFilterInternal
            String httpMethod = request.getMethod();
            String requestPath = //... extract relevant path ... ;
            PolicyCapability requiredCapability = mapHttpMethodToCapability(httpMethod); // Ensure DELETE maps correctly

            // ... load token's policies ...
            boolean allowed = checkPermission(tokenPolicies, requestPath, requiredCapability);

            if (!allowed) {
               // Throw AccessDeniedException or set 403 response
            }
            ```
        * **Recommendation:** Ensure the path matching logic in the filter correctly handles path variables (like `{leaseId}`) or uses a pattern matching system (like AntPathMatcher) consistent with the policy definitions.

* **Rationale:** Explicitly defines and verifies the security boundary for the revocation API, ensuring only authorized clients can perform this potentially destructive action.

---

### 3. Review and Enhance Integration Tests (`DbControllerIntegrationTest`)

* **Goal:** Ensure robust end-to-end testing covering success, errors (404, 500), security (403), and potentially seal status (503).
* **File:** `lite-vault/src/test/java/tech/yump/vault/api/DbControllerIntegrationTest.java`

* **Detailed Actions & Recommendations:**

    1.  **Review Existing Tests:** Acknowledge the value of:
        * `revokeLease_whenValidLeaseId_thenNoContentAndDropRole`: Excellent happy-path test, including DB verification.
        * `revokeLease_whenInvalidLeaseId_thenNotFound`: Tests the 404 path (likely via `LeaseNotFoundException`).
        * `revokeLease_whenTokenLacksPermission_thenForbidden`: Tests the 403 security path.

    2.  **Consider Adding Seal/Unseal Test:**
        * **Action:** Implement the suggested test flow if feasible and relevant.
        * **Code Outline (Spring MockMvc / Testcontainers):**
            ```java
            @Test
            void revokeLease_whenVaultSealed_thenServiceUnavailable_thenSuccessAfterUnseal() throws Exception {
                // 1. Arrange: Create a lease first (using API or direct engine call)
                String leaseId = createLeaseViaApi("my-role"); // Helper method

                // 2. Seal the Vault (Requires access to SealManager bean)
                sealManager.seal(); // Assuming sealManager is available in the test context
                assertTrue(sealManager.isSealed());

                // 3. Act & Assert (Sealed): Attempt revocation, expect 503
                mockMvc.perform(delete("/v1/db/leases/" + leaseId)
                                .header("X-Vault-Token", ROOT_TOKEN)) // Use a valid token
                        .andExpect(status().isServiceUnavailable()); // 503

                // 4. Unseal the Vault (Requires unseal keys)
                // Provide necessary unseal keys...
                // sealManager.unseal(key1); ... sealManager.unseal(keyN);
                // assertFalse(sealManager.isSealed()); // Ensure unsealed

                // 5. Act & Assert (Unsealed): Attempt revocation again, expect 204
                mockMvc.perform(delete("/v1/db/leases/" + leaseId)
                                .header("X-Vault-Token", ROOT_TOKEN))
                        .andExpect(status().isNoContent()); // 204

                // 6. Assert (Optional but good): Verify DB role is actually dropped
                assertFalse(doesRoleExistInDb(getUsernameForLease(leaseId))); // Helper DB check method
            }
            ```
        * **Caveat:** This test relies on the `SealManager` being accessible and the seal status actually blocking the DB operation or being checked by an involved component (e.g., `DataSource` proxy, service layer check). If sealing *doesn't* prevent DB access in your setup, this test might not be relevant for the 503 code, but testing revocation *after* an unseal cycle might still be valuable.

    3.  **Testcontainers Database Environment:**
        * **Verify:** Ensure the PostgreSQL container started by Testcontainers (`@Container`, `PostgreSQLContainer`) is configured similarly to the target environment, especially regarding the privileges of the main application user (defined in `application-test.yml`'s datasource).
        * **Recommendation:** The application user connecting via `jdbcTemplate` needs sufficient permissions *in the test container* to execute the configured `revocationStatements` (e.g., `DROP ROLE`). This might require granting specific privileges during container startup or ensuring the user is a superuser (common in test containers, but less ideal if mimicking production privileges).

* **Rationale:** Integration tests provide the highest level of confidence by testing the entire request flow, from HTTP endpoint through service and engine layers, including security filters and interaction with a real (containerized) database.

---

## Phase 4: Documentation & Cleanup

### 1. Update Task Status

* **Action:** Mark **Task #42** as completed in `lite-vault/project/tasks/mssm-atomic-tasks-v0-5-0.md`.
* **Recommendation:** Add a brief note referencing the relevant commit(s) if possible.

### 2. Update User/Admin Documentation (Task #47)

* **Goal:** Inform users and administrators how to use the new API endpoint.
* **File(s):** Relevant sections in admin/API documentation (e.g., `mssm_admin_application_journeys.md` or a dedicated API reference).

* **Detailed Actions & Recommendations:**

    1.  **Add API Endpoint Section:** Create a new section or update an existing one for "Database Secrets Engine" or "Lease Management".
    2.  **Endpoint Details:**
        * **Method:** `DELETE`
        * **Path:** `/v1/db/leases/{leaseId}`
        * **Description:** Explicitly revokes a database credential lease immediately, terminating its validity and attempting to run configured cleanup SQL (e.g., dropping the temporary user/role).
        * **Path Parameters:**
            * `leaseId` (string, required): The ID of the lease to revoke (obtained when the lease was created).
        * **Headers:**
            * `X-Vault-Token` (string, required): A valid token with appropriate permissions.
        * **Required Permissions:** A token associated with a policy granting the `DELETE` capability on the path `db/leases/*`.
        * **Success Response:** `204 No Content`.
        * **Error Responses:**
            * `403 Forbidden`: Token lacks permission or is invalid.
            * `404 Not Found`: Lease ID does not exist or has already been revoked/expired.
            * `500 Internal Server Error`: Failed to execute revocation statements or other unexpected engine error.
            * `503 Service Unavailable`: Vault is sealed.
    3.  **Provide Example:**
        * **Code Example (`curl`):**
            ```bash
            # Replace {VAULT_ADDR}, {LEASE_ID}, and {TOKEN} with actual values
            VAULT_ADDR="http://localhost:8080"
            LEASE_ID="l-postgres-my-role-abc123xyz"
            TOKEN="t.root_token_value" # Or a token with db-operator policy

            curl --request DELETE \
                 --header "X-Vault-Token: $TOKEN" \
                 $VAULT_ADDR/v1/db/leases/$LEASE_ID
            ```

* **Rationale:** Clear documentation makes the feature usable and helps administrators manage permissions correctly.

### 3. Code Review & Cleanup

* **Goal:** Ensure code quality, consistency, and maintainability.
* **Files:** All files modified during this task.

* **Detailed Actions & Recommendations:**
    * **Clarity:** Are variable names clear? Is the logic easy to follow?
    * **Consistency:** Does the code style match the surrounding project code? Are exceptions handled consistently? Is logging applied uniformly?
    * **Logging:** Are log levels appropriate (e.g., `INFO` for standard operations, `DEBUG` for detailed flow, `WARN` for potential issues, `ERROR` for failures)? Do logs provide enough context? Avoid logging sensitive information.
    * **Comments:** Remove any temporary debugging comments (`// TODO`, `// FIXME`, `System.out.println`). Add explanatory comments only where the logic is complex or non-obvious.
    * **Tests:** Ensure all tests pass and cover the implemented logic adequately.
    * **Dependencies:** Were any new dependencies added? Are they necessary?

* **Rationale:** Maintains the health and quality of the codebase.

---

## Deferred Items

* **Background Lease Expiration/Revocation:** As noted, automatically revoking leases when their TTL expires involves a different mechanism (likely a scheduled task, careful state management, locking, and robust error handling for background processes). This remains deferred to a future task to keep the scope of Task #42 focused on the explicit `DELETE` API endpoint.

---

This detailed plan provides specific verification points, code examples, and recommendations to ensure Task #42 is completed robustly and securely, leveraging the existing implementation.