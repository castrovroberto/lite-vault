package tech.yump.vault.api;

import io.swagger.v3.oas.annotations.media.Schema; // Import
import java.time.Instant;

@Schema(description = "Standard error response format") // Add schema description
public record ApiError(
        @Schema(description = "Detailed error message.", example = "Access denied by policy.", requiredMode = Schema.RequiredMode.REQUIRED) // Add field description and example
        String message,
        @Schema(description = "Timestamp when the error occurred.", requiredMode = Schema.RequiredMode.REQUIRED) // Add field description
        Instant timestamp
) {
    public ApiError(String message) {
        this(message, Instant.now());
    }
}
