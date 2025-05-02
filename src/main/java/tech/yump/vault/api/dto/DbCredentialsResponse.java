package tech.yump.vault.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.UUID;

@Schema(description = "Response containing dynamically generated database credentials and lease information.")
public record DbCredentialsResponse(
        @Schema(description = "Unique identifier for the lease associated with these credentials.", requiredMode = Schema.RequiredMode.REQUIRED)
        UUID leaseId,

        @Schema(description = "The dynamically generated database username.", example = "lv-readonly-app-role-a1b2c3d4", requiredMode = Schema.RequiredMode.REQUIRED)
        String username,

        @Schema(description = "The dynamically generated database password.", example = "S3cr3tP@ssw0rd!", requiredMode = Schema.RequiredMode.REQUIRED)
        String password,

        @Schema(description = "The duration for which these credentials are valid, in seconds.", example = "3600", requiredMode = Schema.RequiredMode.REQUIRED)
        long leaseDurationSeconds // Assuming the service converts TTL to seconds
) {
}
