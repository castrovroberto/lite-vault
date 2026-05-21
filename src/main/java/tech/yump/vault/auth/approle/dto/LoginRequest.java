package tech.yump.vault.auth.approle.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record LoginRequest(
        @JsonProperty("role_id") String roleId,
        @JsonProperty("secret_id") String secretId
) {}
