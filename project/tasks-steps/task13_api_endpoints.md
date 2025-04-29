
# Task 13: Create API Endpoints for KV v1 (CRUD)

This involves creating a Spring `@RestController` that uses the `KVSecretEngine` (implemented in Task 12) to expose Create/Read/Update (via PUT/POST) and Delete operations over HTTP. These endpoints must be protected by the static token authentication (Task 11).

---

## Step 1: Create the Controller Package and Class

- Create a package: `tech.yump.vault.api.v1`
- Create a new class: `KVController.java`

```java
package tech.yump.vault.api.v1;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.secrets.kv.KVSecretEngine;

@RestController
@RequestMapping("/v1/kv/data")
@Slf4j
@RequiredArgsConstructor
public class KVController {
    private final KVSecretEngine kvSecretEngine;
}
```

---

## Step 2: Inject Dependencies and Setup Annotations

- `@RestController` to define a REST API controller.
- `@RequestMapping("/v1/kv/data")` for the base route.
- `@Slf4j` for logging.
- `@RequiredArgsConstructor` for dependency injection.

---

## Step 3: Implement the Write Endpoint (PUT)

```java
@PutMapping("/{*path}")
public ResponseEntity<?> writeSecret(@PathVariable String path, @RequestBody Map<String, String> secrets) {
    log.info("Received request to write secrets at path: {}", path);
    kvSecretEngine.write(path, secrets);
    log.info("Successfully wrote secrets to path: {}", path);
    return ResponseEntity.noContent().build();
}
```

---

## Step 4: Implement the Read Endpoint (GET)

```java
@GetMapping("/{*path}")
public ResponseEntity<Map<String, String>> readSecret(@PathVariable String path) {
    log.info("Received request to read secrets from path: {}", path);
    Optional<Map<String, String>> secretsOptional = kvSecretEngine.read(path);
    if (secretsOptional.isPresent()) {
        return ResponseEntity.ok(secretsOptional.get());
    } else {
        return ResponseEntity.notFound().build();
    }
}
```

---

## Step 5: Implement the Delete Endpoint (DELETE)

```java
@DeleteMapping("/{*path}")
public ResponseEntity<Void> deleteSecret(@PathVariable String path) {
    log.info("Received request to delete secrets at path: {}", path);
    kvSecretEngine.delete(path);
    return ResponseEntity.noContent().build();
}
```

---

## Step 6: Implement Exception Handling

Create an `ApiError` class:

```java
package tech.yump.vault.api;

import java.time.Instant;

public record ApiError(String message, Instant timestamp) {
    public ApiError(String message) {
        this(message, Instant.now());
    }
}
```

Add exception handlers in `KVController`:

```java
@ExceptionHandler(KVEngineException.class)
public ResponseEntity<ApiError> handleKVEngineException(KVEngineException ex) { ... }

@ExceptionHandler(IllegalArgumentException.class)
public ResponseEntity<ApiError> handleIllegalArgumentException(IllegalArgumentException ex) { ... }

@ExceptionHandler(VaultSealedException.class)
public ResponseEntity<ApiError> handleVaultSealedException(VaultSealedException ex) { ... }

@ExceptionHandler(Exception.class)
public ResponseEntity<ApiError> handleGenericException(Exception ex) { ... }
```

---

## Step 7: Verify Authentication Requirement

In `SecurityConfig`, make sure `/v1/**` endpoints are protected:

```java
http.authorizeHttpRequests(authz -> authz
    .requestMatchers("/sys/seal-status", "/").permitAll()
    .requestMatchers("/v1/**").authenticated()
);
```

---

## Step 8: Update Documentation

### README.md
Add:
- **PUT /v1/kv/data/{path}**: Write secrets.
- **GET /v1/kv/data/{path}**: Read secrets.
- **DELETE /v1/kv/data/{path}**: Delete secrets.

Requires `X-Vault-Token`.

### CHANGELOG.md
Add under [Unreleased]:

- **KV v1 API Endpoints (Task 13)**:
  - Created `KVController` under `/v1/kv/data`.
  - Implemented CRUD endpoints.
  - Endpoints require authentication via `X-Vault-Token`.
  - Basic exception handling included.

---

## Step 9: Commit

Commit message:

```
feat(api): Implement CRUD endpoints for KV v1 secrets engine

Adds a REST controller (`KVController`) to expose the KV v1 secrets
engine functionality via the `/v1/kv/data/` path.

Implements:
- PUT /{*path}: Write/update secrets map (JSON body).
- GET /{*path}: Read secrets map (returns JSON or 404).
- DELETE /{*path}: Delete secrets.

Endpoints are protected by the static token authentication mechanism
(require `X-Vault-Token` header).

Includes basic exception handling to map KVEngineException,
IllegalArgumentException, and VaultSealedException to appropriate
HTTP status codes (400, 404, 500, 503).

Ref: Task 13
```

---

✅ You now have functional API endpoints for managing static secrets using the KV v1 engine, protected by your authentication layer!
