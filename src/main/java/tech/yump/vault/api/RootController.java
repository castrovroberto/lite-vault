package tech.yump.vault.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map; // For returning a simple JSON object

/**
 * Basic controller for root path and health/status checks.
 */
@RestController // Marks this as a controller where methods return domain objects (serialized to JSON/XML)
public class RootController {

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

  // We will add the /sys/seal-status endpoint here in the next task (Task 7)
}