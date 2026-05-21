package tech.yump.vault.auth.approle;

import java.time.Duration;
import java.util.List;

public record AppRoleDefinition(
        String roleName,
        List<String> policyNames,
        Duration tokenTtl,
        Duration secretIdTtl,
        int secretIdNumUses
) {}
