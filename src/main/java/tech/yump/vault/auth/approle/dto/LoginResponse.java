package tech.yump.vault.auth.approle.dto;

public record LoginResponse(String token, long ttl) {}
