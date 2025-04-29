package tech.yump.vault.auth.policy;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

public record PolicyDefinition(
        @NotBlank(message = "Policy name cannot be blank")
        String name,

        @NotEmpty(message = "Policy must contain at least one rule")
        @Valid
        List<PolicyRule> rules
) {
}
