# Synthesized Actionable Tasks for Improvement

Based on the improvement suggestions, here is a synthesized list of actionable tasks, grouped by category:

## Code Organization & Layering

1.  **Refactor DB Logic to Service Layer:** Extract database credential generation and revocation logic from `DbController` and `PostgresSecretsEngine` into a dedicated service class (e.g., `DbCredentialService`) to separate concerns.
2.  **Centralize Exception Handling:** Implement a global `@ControllerAdvice` component to handle common application exceptions (`VaultSealedException`, `RoleNotFoundException`, `LeaseNotFoundException`, `SecretsEngineException`, etc.) consistently, removing duplicate `@ExceptionHandler` blocks from individual controllers (`KVController`, `DbController`).
3.  **Refactor Audit Logging:** Create a reusable audit logging helper component or utilize AOP (Aspect-Oriented Programming) to centralize the logic for creating and logging `AuditEvent` instances, reducing boilerplate code in filters (`StaticTokenAuthFilter`, `PolicyEnforcementFilter`), controllers (`KVController`, `DbController`), and engines (`PostgresSecretsEngine`).

## Configuration & Validation

4.  **Implement Conditional Validation for Static Tokens:** Add custom validation logic (e.g., using a JSR-303 validator or `@AssertTrue` on `MssmProperties.AuthProperties.StaticTokenAuthProperties`) to ensure the `mappings` list is not empty only when `enabled` is `true`.
5.  **Secure Sensitive Config in Memory:** Investigate techniques (e.g., using `char[]`, manual clearing) to zero-out or discard sensitive configuration values (like the master key in `SealManager` and the DB admin password used by `PostgresSecretsEngine`) from memory as soon as they are consumed.
6.  **Enhance Configuration Property Validation:** Review all fields within `MssmProperties` and its nested records (`MasterKeyProperties`, `StorageProperties`, `AuthProperties`, `SecretsProperties`, etc.) and add explicit `@NotNull`, `@NotBlank`, or `@NotEmpty` annotations where constraints are missing but required.

## Security Hardening

7.  **Remove `System.gc()` Call:** Delete the explicit `System.gc()` call within the `SealManager.seal()` method.
8.  **Harden PostgreSQL DDL Execution:** Refactor the SQL statement execution in `PostgresSecretsEngine` (`creationStatements`, `revocationStatements`). Replace the current string replacement for `{{username}}` and `{{password}}` with a safer method, such as using prepared statements if possible for DDL with the specific driver/DB version, or implementing strict input validation/escaping/whitelisting for the generated values.
9.  **Implement MDC for Request ID:** Modify `StaticTokenAuthFilter` (or add a dedicated filter) to place the generated `auditRequestId` into the SLF4J MDC (Mapped Diagnostic Context) at the beginning of each request and clear it at the end, so all log lines for a request share the ID.

## Testing & Resilience

10. **Enhance Filter Negative Path Tests:** Review and expand unit/integration tests for `StaticTokenAuthFilter` and `PolicyEnforcementFilter` (`StaticTokenAuthFilterTest`, `PolicyEnforcementFilterTest`) to explicitly cover more negative paths: missing tokens, invalid token formats, requests made when the vault is sealed, and various policy denial scenarios (wrong capability, wrong path).
11. **Implement Lease Map Stress Tests:** Create tests for `PostgresSecretsEngine` that simulate high concurrency scenarios involving simultaneous calls to `generateCredentials` and `revokeLease` to verify the thread-safety and performance of the `activeLeases` map.
12. **Implement Lease TTL Cleanup & Testing:** Add functionality to `PostgresSecretsEngine` (e.g., using a scheduled task or background thread) to automatically identify and revoke expired leases based on their `creationTime` and `ttl`. Include tests to verify this cleanup mechanism works correctly.
13. **Expand Testcontainers Coverage:** Review `DbControllerIntegrationTest` and potentially add more integration tests using `Testcontainers` to cover edge cases and partial failure scenarios during PostgreSQL credential generation and revocation (e.g., DB connection issues mid-operation, revocation statement failures).

## Observability & Operations

14. **Integrate Spring Actuator & Micrometer:** Add the `spring-boot-starter-actuator` dependency. Configure `Micrometer` and expose relevant Actuator endpoints (e.g., `/health`,