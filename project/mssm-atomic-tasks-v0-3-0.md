# Minimal Secure Secrets Manager (MSSM) v0.3.0

## Atomic Tasks Roadmap: Phase 3 - Dynamic DB Secrets (PostgreSQL)

> **Goal:** Implement the first dynamic secrets engine, focusing on PostgreSQL credential generation and basic lease management, fulfilling requirements F-DB-*.

---

### Phase 3 Atomic Tasks (21-30)

#### 21. [x] Define Core Secrets Engine Interfaces
- **Description:**
    - Define a generic `SecretsEngine` interface (if not implicitly done).
    - Define a more specific `DynamicSecretsEngine` interface extending the base, potentially including methods for `generateCredentials(roleName)`, `revokeLease(leaseId)`.
    - Define a `Lease` object structure (lease ID, secret data, creation time, TTL, renewable flag).
- **Rationale:**
    - Establishes a common contract for all secrets engines (NFR-MTN-500).
    - Provides specific methods needed for dynamic secret generation and management.

#### 22. [x] Implement PostgreSQL Secrets Engine Core
- **Description:**
    - Create `PostgresSecretsEngine.java` implementing `DynamicSecretsEngine`.
    - Add necessary dependencies (e.g., PostgreSQL JDBC driver).
    - Implement basic structure, constructor injection for dependencies (e.g., `EncryptionService`, `StorageBackend` if needed for state, configuration).
- **Rationale:**
    - Creates the specific component responsible for PostgreSQL interactions.

#### 23. [x] Configure PostgreSQL Engine via Properties
- **Description:**
    - Update `MssmProperties` to include configuration for the PostgreSQL engine:
        - Connection URL (`mssm.db.postgres.connection_url`).
        - Static admin username/password (to manage roles) - *Note: Securely providing this admin credential needs careful consideration, maybe via env vars or later, another secret*.
        - Role definitions (map of `role_name` to SQL creation/revocation statements, default TTL).
    - Add validation for these properties.
    - Update `application-dev.yml` with example configuration pointing to a test database.
- **Rationale:**
    - Makes the engine configurable for different DB instances and roles (F-DB-200).

#### 24. [x] Implement PostgreSQL Connection Management
- **Description:**
    - Implement logic within `PostgresSecretsEngine` to establish and manage connections to the target PostgreSQL database using the configured admin credentials.
    - Consider using a connection pool (e.g., HikariCP, managed by Spring Boot if possible) for efficiency.
- **Rationale:**
    - Enables the engine to interact with the target database.

#### 25. [x] Implement Credential Generation Logic
- **Description:**
    - Implement the `generateCredentials(roleName)` method.
    - Retrieve the configured SQL creation template for the given `roleName`.
    - Generate a unique username and secure password.
    - Execute the SQL template against the target DB using the managed connection to create the temporary user/role.
    - Handle potential SQL errors gracefully.
- **Rationale:**
    - Core logic for creating dynamic credentials on demand (F-DB-220, F-DB-241).

#### 26. [ ] Implement Basic Lease Management (In-Memory)
- **Description:**
    - Implement basic, in-memory tracking (e.g., using a `ConcurrentHashMap`) within `PostgresSecretsEngine` or a dedicated `LeaseManager` service.
    - When credentials are generated (Task 25), create a `Lease` object with a unique ID, the generated username/password, TTL from config, and store it in the map.
    - Return the `Lease` object (or relevant parts) to the caller.
    - *Initial Scope:* Focus on tracking creation and TTL. Actual revocation might be deferred or implemented simply.
- **Rationale:**
    - Associates a lifetime with generated credentials (F-DB-210, F-DB-230 - initial).

#### 27. [ ] Create API Endpoints for DB Credentials
- **Description:**
    - Implement a `DbController` (e.g., under `/v1/db`).
    - Create endpoint `GET /creds/{role_name}` (or POST) to request new credentials for a configured role.
    - Inject `PostgresSecretsEngine` and call `generateCredentials`.
    - Return the generated username, password, and lease details (ID, duration) in the API response.
    - Protect this endpoint using the existing Auth (Task 11) and ACL (Task 15) mechanisms. Update policies if needed.
- **Rationale:**
    - Exposes dynamic credential generation via the API.

#### 28. [ ] Integrate Audit Logging for DB Actions
- **Description:**
    - Inject the `AuditBackend` (Task 16).
    - Log audit events for:
        - Credential generation requests (success/failure, requested role, authenticated user).
        - Lease creation (lease ID, associated role).
    - Ensure generated passwords are *not* logged.
- **Rationale:**
    - Provides audit trail for dynamic secret generation (F-CORE-130).

#### 29. [ ] Write Unit Tests for PostgreSQL Engine
- **Description:**
    - Write unit tests for `PostgresSecretsEngine`.
    - Mock database interactions (JDBC calls) to test SQL template rendering and parameter substitution logic.
    - Test lease object creation.
    - Test error handling for invalid roles or DB connection issues.
- **Rationale:**
    - Verifies the engine's internal logic without requiring a live database.

#### 30. [ ] Write Integration Tests for DB Credential API
- **Description:**
    - Write Spring Boot integration tests (`@SpringBootTest`).
    - Consider using Testcontainers to spin up a temporary PostgreSQL instance.
    - Configure the application context for the test DB.
    - Send authenticated requests to `GET /v1/db/creds/{role_name}`.
    - Verify successful credential generation and response structure.
    - Verify that credentials actually work against the test DB (optional but valuable).
    - Test ACL enforcement (requests with insufficient permissions should fail).
- **Rationale:**
    - Validates the end-to-end flow from API request to credential generation against a real (test) database.

---

## Result After Phase 3 Completion

- A functional dynamic secrets engine for PostgreSQL is implemented.
- Users/applications can request temporary DB credentials via the API.
- Basic lease information (ID, duration) is returned with credentials.
- Configuration allows defining connection details and role templates.
- Generation events are audited.
- Unit and integration tests (potentially using Testcontainers) validate the engine.

---

## Suggested Improvements for Next Steps (Phase 4 / v0.4.0)

- **JWT Key Rotation:** Implement the JWT secrets engine.
- **Lease Revocation:** Implement robust lease revocation for DB credentials.
- **Lease Renewal:** Add API endpoints and logic for renewing leases.
- **MySQL Support:** Add a similar dynamic secrets engine for MySQL.

---