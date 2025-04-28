# Task 7: Create `/sys/seal-status` API Endpoint

## Goal
Expose the current operational state (**SEALED** or **UNSEALED**) of the vault via a simple GET request.

## Prerequisites
- Task 5 (SealManager service) is implemented and manages the seal state.
- Task 6 (HTTP Server & RootController) is implemented, providing the basic web layer.
- Spring Boot Web (`spring-boot-starter-web`) is configured.

## Step-by-Step Implementation

### Step 1: Locate the Controller
We will extend `RootController` to include the `/sys/seal-status` endpoint.

- **File:** `src/main/java/tech/yump/vault/api/RootController.java`

### Step 2: Inject SealManager
Add `SealManager` dependency using constructor injection:

```java
package tech.yump.vault.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.core.SealManager;

import java.util.Map;

/**
 * Basic controller for root path and system status checks.
 */
@RestController
public class RootController {

    private final SealManager sealManager;

    public RootController(SealManager sealManager) {
        this.sealManager = sealManager;
    }

    @GetMapping("/")
    public Map<String, String> getRoot() {
        return Map.of(
                "message", "Welcome to LiteVault API",
                "status", "OK"
        );
    }

    // New method will be added below
}
```

### Step 3: Implement `/sys/seal-status` Endpoint

```java
    /**
     * Handles GET requests to /sys/seal-status.
     * Returns the current seal status of the vault.
     *
     * @return A Map containing the seal status.
     */
    @GetMapping("/sys/seal-status")
    public Map<String, Object> getSealStatus() {
        boolean isSealed = sealManager.isSealed();
        return Map.of("sealed", isSealed);
    }
```

Optional extension could include detailed enum status:

```java
    SealStatus status = sealManager.getSealStatus();
    return Map.of(
        "sealed", status == SealStatus.SEALED,
        "status_name", status.name()
    );
```

### Step 4: Run and Verify

#### Run Sealed
- Ensure `MSSM_MASTER_KEY_B64` is **not set**.
- Start the application:
  ```bash
  mvn spring-boot:run
  ```
- Test the endpoint:
  ```bash
  curl http://localhost:8081/sys/seal-status
  ```
- Expected Output:
  ```json
  {"sealed":true}
  ```

#### Run Unsealed
- Generate a valid Base64 key:
  ```bash
  openssl rand 32 | base64
  ```
- Set the environment variable:
  ```bash
  export MSSM_MASTER_KEY_B64="your_generated_key"
  ```
- Restart the application.
- Test the endpoint again:
  ```bash
  curl http://localhost:8081/sys/seal-status
  ```
- Expected Output:
  ```json
  {"sealed":false}
  ```

## Completion of Task 7

✅ RootController now depends on SealManager.  
✅ New endpoint `GET /sys/seal-status` is implemented.  
✅ Reflects the actual state of the vault (sealed/unsealed).  

## What's Achieved
- External clients can now monitor the seal state programmatically.
- This paves the way for secure operational monitoring.

## Next Step
**Task 8: Configure Basic TLS for API Server.**  
Generate a self-signed certificate and configure Spring Boot to use HTTPS.

---
*Document generated on 2025-04-28*
