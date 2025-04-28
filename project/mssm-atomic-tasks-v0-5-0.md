# Minimal Secure Secrets Manager (MSSM) v0.5.0

## Atomic Tasks Roadmap: Phase 5 - Polish, Hardening & Release Prep (v1.0.0 RC)

> **Goal:** Stabilize the features developed in previous cycles, enhance testing and documentation, improve operational aspects like auditing and lease management, and prepare the system for a v1.0.0 release candidate.

---

### Phase 5 Atomic Tasks (41-50)

#### 41. [ ] Enhance Audit Logging Backend
- **Description:**
    - Implement an alternative `AuditBackend` (e.g., `FileAuditBackend`) that writes structured audit events (JSON) to a dedicated, append-only log file configured via `MssmProperties`.
    - Ensure proper log rotation configuration for the audit file (can leverage Logback/Log4j2 configuration if using SLF4j bridge).
    - Make the active `AuditBackend` configurable (e.g., default to SLF4j, allow switching to file).
- **Rationale:**
    - Moves closer to F-CORE-130's "immutable" goal by separating audit logs.
    - Provides a more parseable audit trail than general application logs.

#### 42. [ ] Implement DB Lease Revocation
- **Description:**
    - Add logic to `PostgresSecretsEngine` (or `LeaseManager`) to revoke credentials. This involves:
        - Retrieving the configured SQL *revocation* template for the role associated with a lease.
        - Executing the revocation SQL against the target DB (e.g., `DROP USER {username}`).
    - Implement a mechanism to trigger revocation (e.g., a background thread checking expired leases, an explicit API endpoint).
    - Create an API endpoint `DELETE /v1/sys/leases/{lease_id}` (or similar) for explicit revocation. Protect with Auth/ACLs.
    - Add audit logging for revocation events.
- **Rationale:**
    - Completes the lease lifecycle management for dynamic secrets (F-DB-230).
    - Enhances security by ensuring temporary credentials are removed.

#### 43. [ ] Generate OpenAPI Documentation
- **Description:**
    - Integrate a library like `springdoc-openapi` to automatically generate an OpenAPI v3 specification from existing Spring Web annotations (`@RestController`, `@GetMapping`, etc.).
    - Configure basic API info (title, version, description) via properties.
    - Ensure the generated spec accurately reflects all v1 API endpoints, request/response models, and authentication requirements (`X-Vault-Token` header).
    - Expose the spec via a standard endpoint (e.g., `/v3/api-docs`) and potentially a Swagger UI (`/swagger-ui.html`).
- **Rationale:**
    - Provides clear, machine-readable documentation for API consumers.
    - Facilitates API testing and client generation.

#### 44. [ ] Implement Comprehensive Integration Test Suite
- **Description:**
    - Review existing integration tests (KV, DB, JWT).
    - Add new integration tests covering interactions *between* components:
        - Use a token with specific ACLs to test access denial/success across different engines.
        - Test scenarios involving multiple secrets engines if applicable.
        - Test seal/unseal impact on API availability.
    - Ensure tests cover various configuration scenarios (e.g., different auth tokens, policies).
- **Rationale:**
    - Increases confidence in the overall system stability and correctness when components interact.

#### 45. [ ] Conduct Basic Performance Testing
- **Description:**
    - Identify key performance-critical API endpoints (e.g., KV read/write, DB cred generation, JWT sign).
    - Use a simple load testing tool (e.g., `k6`, `ApacheBench`, `wrk`) to run baseline tests against a locally running instance.
    - Measure basic metrics like requests per second, latency (average, p95, p99) under moderate load.
    - Document the baseline results. No optimization required yet, just measurement.
- **Rationale:**
    - Establishes initial performance benchmarks (NFR-PERF-200/210).
    - Helps identify potential bottlenecks early.

#### 46. [ ] Security Review and Hardening
- **Description:**
    - Perform a manual code review focusing on security aspects:
        - Input validation across all API endpoints (NFR-SEC-120).
        - Correct exception handling (no sensitive info leaked).
        - Secure handling of keys and credentials in memory.
        - ACL enforcement logic correctness.
    - Run static analysis security testing (SAST) tools if available.
    - Run dependency scanning tools (e.g., `mvn dependency-check:check`) to identify known vulnerabilities in libraries.
    - Address any high-priority findings.
- **Rationale:**
    - Proactively identifies and mitigates potential security weaknesses before release.

#### 47. [ ] Write User/Admin Documentation
- **Description:**
    - Update `README.md` significantly or create separate documentation files covering:
        - System architecture overview.
        - Configuration options (`MssmProperties` details).
        - Setup and running instructions (including dependencies like DB for testing).
        - API usage examples for KV, DB, JWT endpoints.
        - Authentication and authorization concepts (tokens, policies).
        - Basic operational procedures (seal/unseal, checking status).
- **Rationale:**
    - Provides essential information for users and administrators to deploy and use MSSM v1.0.0.

#### 48. [ ] Refine Build and Packaging
- **Description:**
    - Ensure `mvn clean package` produces a runnable fat JAR.
    - Create a basic `Dockerfile` that takes the JAR, sets up a non-root user, exposes the port, and allows configuration via environment variables.
    - Test building the Docker image and running a container.
- **Rationale:**
    - Provides standard ways to build and deploy the application.

#### 49. [ ] Code Cleanup and Refactoring
- **Description:**
    - Review code for TODO comments and address them.
    - Improve logging clarity and consistency across modules.
    - Refactor any overly complex methods or classes identified during development or testing.
    - Ensure consistent code style.
- **Rationale:**
    - Improves code maintainability, readability, and reduces technical debt before v1.0.0.

#### 50. [ ] Tag Release Candidate & Final Testing
- **Description:**
    - Ensure all tests (unit, integration) are passing.
    - Perform final manual testing of the core user journeys (configuring, unsealing, creating/reading KV, generating DB creds, signing JWT).
    - Tag the commit as `v1.0.0-rc1` (Release Candidate 1).
- **Rationale:**
    - Marks a feature-complete state ready for final validation before the official v1.0.0 tag.

---

## Result After Phase 5 Completion

- Audit logging is more robust and potentially separated.
- Dynamic DB credential leases can be explicitly revoked.
- Comprehensive API documentation (OpenAPI) is available.
- Integration test suite covers cross-component interactions.
- Baseline performance metrics are established.
- Security posture has been reviewed and hardened.
- User/Admin documentation is available.
- Standard packaging (JAR, Dockerfile) is ready.
- Code quality is improved.
- A `v1.0.0` Release Candidate is tagged and tested.

---

## Suggested Improvements for Next Steps (Post v1.0.0)

- **More Auth Methods:** Implement AppRole, User/Pass, OIDC, etc.
- **More Secrets Engines:** MySQL, Cloud IAM, PKI.
- **Lease Renewal:** Implement lease renewal functionality.
- **High Availability / Clustering:** Design for multi-node deployments.
- **UI:** Develop a web user interface.
- **Automated Key Rotation:** Trigger JWT rotation based on schedule.

---
