# Minimal Secure Secrets Manager (MSSM) v0.2.0

## Atomic Tasks Roadmap: Phase 2 - Authentication, KV Secrets & Auditing

> **Goal:** Build upon the core foundation by adding essential security layers (authentication, basic authorization), the first usable secrets engine (Key/Value v1), and foundational audit logging.

---

### Phase 2 Atomic Tasks (11-20)

#### 11. [ ] Implement Basic Static Token Authentication
- **Description:**
    - Define a simple static token authentication mechanism.
    - Load a list of valid, non-expiring tokens from configuration (`mssm.auth.static_tokens: ["token1", "token2"]`).
    - Implement a Spring Security filter or `HandlerInterceptor` to check for an `X-Vault-Token` header on incoming API requests.
    - If the token matches one from the configuration, authenticate the request; otherwise, reject with 401/403.
    - Associate a simple identifier (e.g., the token itself or a configured ID) with the authenticated request context.
- **Rationale:**
    - Secures the API beyond the basic TLS layer (F-CORE-110).
    - Provides a minimal way for clients (initially, test scripts or admins) to interact securely.

#### 12. [ ] Implement Static Secrets Engine (KV v1 - Using StorageBackend)
- **Description:**
    - Define a `KVSecretEngine` interface (or similar).
    - Implement the engine to store arbitrary key-value pairs at logical paths (e.g., `kv/data/myapp/config`).
    - Use the existing `StorageBackend` (`FileSystemStorageBackend`) to persist the key-value data.
    - Encrypt the *entire map* of key-value pairs for a given path before passing it to `StorageBackend.put()`.
    - Decrypt the blob retrieved via `StorageBackend.get()` before returning the key-value map.
    - The logical path (e.g., `kv/data/myapp/config`) becomes the key for the `StorageBackend`.
- **Rationale:**
    - Provides the first usable mechanism for storing and retrieving secrets (F-STATIC-400).
    - Leverages the existing encrypted storage layer.

#### 13. [ ] Create API Endpoints for KV v1 (CRUD)
- **Description:**
    - Implement a `KVController` (e.g., under `/v1/kv/data/{path...}`).
    - **Write:** `POST` or `PUT` endpoint accepting a JSON body `{ "key1": "value1", "key2": "value2" }` to store/update secrets at the specified path. Requires authentication.
    - **Read:** `GET` endpoint to retrieve the JSON map of secrets at the specified path. Requires authentication.
    - **Delete:** `DELETE` endpoint to remove all secrets at the specified path. Requires authentication.
    - Ensure these endpoints are protected by the authentication mechanism (Task 11).
- **Rationale:**
    - Exposes the KV secrets engine functionality via the API (F-STATIC-410/420).

#### 14. [ ] Define Basic Policy/ACL Structure
- **Description:**
    - Define simple data structures (e.g., Java records or classes) for representing policies.
    - Example Policy: `{ path: "kv/data/myapp/*", capabilities: ["read", "write"] }`
    - Define how policies are associated with static tokens in the configuration (e.g., `mssm.auth.static_tokens: [{token: "...", policies: ["policy_name_1"]}]`, `mssm.policies: [{name: "policy_name_1", rules: [...]}]`).
- **Rationale:**
    - Lays the groundwork for authorization (F-CORE-120).
    - Allows defining access rules separate from authentication tokens.

#### 15. [ ] Implement Basic ACL Enforcement
- **Description:**
    - Enhance the authentication filter/interceptor (or add a dedicated authorization interceptor).
    - After successful authentication (Task 11), retrieve the policies associated with the token (Task 14).
    - For the requested API path and HTTP method, check if *any* associated policy grants the required capability (e.g., GET -> "read", POST/PUT -> "write", DELETE -> "delete").
    - Use simple path matching (exact match or basic wildcard `*` at the end).
    - If access is granted, proceed; otherwise, reject with 403 Forbidden.
- **Rationale:**
    - Enforces configured access controls on API endpoints (F-CORE-120).
    - Implements the principle of least privilege (NFR-SEC-130).

#### 16. [ ] Implement Basic Audit Logging Backend
- **Description:**
    - Define an `AuditBackend` interface (e.g., `logEvent(AuditEvent event)`).
    - Implement a simple `LogAuditBackend` that formats an `AuditEvent` object (containing timestamp, auth info, request details, response status, etc.) and writes it to SLF4j logs at INFO level.
- **Rationale:**
    - Creates the mechanism for recording security-relevant events (F-CORE-130).
    - Starts with a simple, file-based audit trail via standard logging.

#### 17. [ ] Integrate Audit Logging into API Flow
- **Description:**
    - Inject the `AuditBackend` into relevant components (e.g., auth filter, ACL interceptor, API controllers).
    - Log audit events for:
        - Authentication attempts (success/failure, token ID used).
        - Authorization decisions (granted/denied, path, required capability).
        - Secret access (read/write/delete operations on KV paths, success/failure).
    - Ensure sensitive data (like secret values themselves) is NOT included in audit logs.
- **Rationale:**
    - Provides visibility into who accessed what, when, and whether it was allowed (F-CORE-130).

#### 18. [ ] Configure Static Tokens and Policies via Properties
- **Description:**
    - Update `MssmProperties` to include structures for `mssm.auth.static_tokens` and `mssm.policies`.
    - Add validation (`@Validated`, `@NotEmpty`, `@Valid`) to ensure tokens and policies are configured correctly.
    - Update `application-dev.yml` with example static tokens and policies for testing.
- **Rationale:**
    - Makes the authentication and authorization mechanisms configurable.

#### 19. [ ] Write Unit Tests for Auth & ACLs
- **Description:**
    - Write unit tests for the authentication filter/interceptor logic using Mockito to simulate requests with/without/invalid tokens.
    - Write unit tests for the ACL enforcement logic, providing mock policies and requests to verify access grant/deny decisions.
- **Rationale:**
    - Ensures the core security mechanisms function correctly in isolation.

#### 20. [ ] Write Integration Tests for KV API
- **Description:**
    - Write Spring Boot integration tests (`@SpringBootTest`) that start the application context.
    - Use `TestRestTemplate` or `MockMvc` to send requests to the KV API endpoints (`/v1/kv/data/...`).
    - Include valid `X-Vault-Token` headers corresponding to configured static tokens/policies.
    - Verify successful CRUD operations for allowed requests.
    - Verify 401/403 responses for unauthenticated or unauthorized requests.
- **Rationale:**
    - Validates that authentication, authorization, the KV engine, and the API endpoints work together correctly end-to-end.

---

## Result After Phase 2 Completion

- API endpoints are protected by static token authentication.
- Basic, policy-based authorization controls access to secrets.
- A functional Key/Value secrets engine allows storing and retrieving static secrets via the API.
- Critical security events (auth, access) are logged to an audit trail (via SLF4j).
- Configuration allows defining users (tokens) and their permissions.
- Unit and integration tests cover the new security and secrets engine features.

---

## Suggested Improvements for Next Steps (Phase 3 / v0.3.0)

- **Dynamic Secrets Engine:** Implement the first dynamic engine (e.g., PostgreSQL).
- **Lease Management:** Track leases for dynamic secrets.
- **More Robust Auth:** Explore other auth methods (e.g., AppRole, user/pass).
- **Refined ACLs:** Improve policy language and matching capabilities.
- **Dedicated Audit Storage:** Implement an `AuditBackend` that writes to a separate, potentially immutable store.
- **API Versioning:** Formalize API versioning practices.
- **Secrets Engine Mounts:** Allow mounting engines at different paths.

---

> **Reminder:** Continue prioritizing security, modularity, and testability.

---