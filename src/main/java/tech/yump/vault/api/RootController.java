package tech.yump.vault.api;

// Import Swagger annotations
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.core.SealManager;

import java.util.Map;

@RestController
@Tag(name = "System", description = "System information and status endpoints")
public class RootController {

  private final SealManager sealManager;

  public RootController(SealManager sealManager) {
    this.sealManager = sealManager;
  }

  @GetMapping("/")
  @Operation(
          summary = "Root Endpoint",
          description = "Provides a simple welcome message and status check. Does not require authentication.",
          security = {} // Explicitly mark as not requiring authentication
  )
  @ApiResponse(responseCode = "200", description = "Welcome message and status.",
          content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                  schema = @Schema(type = "object", example = "{\"message\": \"Welcome to LiteVault API\", \"status\": \"OK\"}")))
  public Map<String, String> getRoot() {
    return Map.of("message", "Welcome to LiteVault API", "status", "OK");
  }

  @GetMapping("/sys/seal-status")
  @Operation(
          summary = "Get Seal Status",
          description = "Returns the current seal status of the vault (true if sealed, false if unsealed). Does not require authentication.",
          security = {} // Explicitly mark as not requiring authentication
  )
  @ApiResponse(responseCode = "200", description = "Seal status retrieved.",
          content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                  schema = @Schema(type = "object", example = "{\"sealed\": false}")))
  public Map<String, Object> getSealStatus() {
    boolean isSealed = sealManager.isSealed();
    return Map.of("sealed", isSealed);
  }
}
