package tech.yump.vault.auth.approle.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record SecretIdResponse(@JsonProperty("secret_id") String secretId) {}
