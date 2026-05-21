package tech.yump.vault.auth.approle.dto;

import java.time.Duration;
import java.util.List;

public record CreateRoleRequest(
        List<String> policyNames,
        Duration tokenTtl,
        Duration secretIdTtl,
        int secretIdNumUses
) {}
