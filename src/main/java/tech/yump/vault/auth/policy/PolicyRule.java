package tech.yump.vault.auth.policy;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.Set;

public record PolicyRule(
        @NotBlank(message = "Policy rule path cannot be blank")
        String path,
        @NotEmpty(message = "Policy rule must grant at least one capability")
        Set<PolicyCapability> capabilities
) {
}
