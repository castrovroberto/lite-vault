package tech.yump.vault.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map; // For returning a simple JSON object
import tech.yump.vault.core.SealManager;

/**
 * Basic controller for root path and health/status checks.
 */
@RestController // Marks this as a controller where methods return domain objects (serialized to JSON/XML)
public class RootController {

  private final SealManager sealManager;

  public RootController(SealManager sealManager) {
    this.sealManager = sealManager;
  }

  /**
   * Handles GET requests to the root path ("/").
   * Provides a simple welcome message and status indication.
   *
   * @return A Map which Jackson will serialize to a JSON object.
   */
  @GetMapping("/") // Maps HTTP GET requests for "/" to this method
  public Map<String, String> getRoot() {
    // Spring Boot + Jackson will automatically convert this Map to a JSON response:
    // { "message": "Welcome to LiteVault API", "status": "OK" }
    return Map.of(
        "message", "Welcome to LiteVault API",
        "status", "OK"
    );
  }

  /**
   * Handles GET request to /sys/seal-status.
   * Returns the current seal status of the vault.
   *
   * @return A map containing the seal status. e.g. {"sealed": true}
   */
  @GetMapping("/sys/seal-status") // <-- Map GET /sys/seal-status
  public Map<String, Object> getSealStatus() {
    boolean isSealed = sealManager.isSealed();
    // Return a map that Jackson will convert to {"sealed": true/false}
    return Map.of("sealed", isSealed);

        /* Alternative: Return more detailed status including the enum name
           SealStatus status = sealManager.getSealStatus();
           return Map.of(
               "sealed", status == SealStatus.SEALED,
               "status_name", status.name() // e.g., "SEALED" or "UNSEALED"
           );
        */
  }
}