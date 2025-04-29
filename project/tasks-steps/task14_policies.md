
# Task 14: Define Basic Policy/ACL Structure

This task focuses on defining the data structures for policies and how they link to static tokens within the configuration. Implementation will be done in future tasks.

## Step-by-Step Guide

### Step 1: Define Policy Capabilities (Enum)
Create an enum `PolicyCapability` inside `tech.yump.vault.auth.policy`.

```java
package tech.yump.vault.auth.policy;

public enum PolicyCapability {
    READ,
    WRITE,
    DELETE,
    LIST
}
```

### Step 2: Define Policy Rule Structure (Record)
Create a record `PolicyRule` inside `tech.yump.vault.auth.policy`.

```java
package tech.yump.vault.auth.policy;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.Set;

public record PolicyRule(
    @NotBlank(message = "Policy rule path cannot be blank") String path,
    @NotEmpty(message = "Policy rule must grant at least one capability") Set<PolicyCapability> capabilities
) {}
```

### Step 3: Define Policy Definition Structure (Record)
Create a record `PolicyDefinition` inside `tech.yump.vault.auth.policy`.

```java
package tech.yump.vault.auth.policy;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

public record PolicyDefinition(
    @NotBlank(message = "Policy name cannot be blank") String name,
    @NotEmpty(message = "Policy must contain at least one rule") @Valid List<PolicyRule> rules
) {}
```

### Step 4: Update Static Token Configuration Structure
Update `MssmProperties.AuthProperties.StaticTokenAuthProperties`:

```java
public record StaticTokenPolicyMapping(
    @NotBlank(message = "Static token value cannot be blank") String token,
    @NotEmpty(message = "Token must be associated with at least one policy name") List<String> policyNames
) {}

public record StaticTokenAuthProperties(
    boolean enabled,
    @NotEmpty(message = "Static token mappings cannot be empty when enabled") @Valid List<StaticTokenPolicyMapping> mappings
) {}
```

Add a `List<PolicyDefinition> policies` inside `AuthProperties`.

### Step 5: Remove Custom Validator
- Delete `StaticTokenConfigValidator.java` and `@ValidStaticTokenConfig` annotation.
- Rely on bean validation.

### Step 6: Update application-dev.yml Example

```yaml
mssm:
  policies:
    - name: "kv-reader"
      rules:
        - path: "kv/data/*"
          capabilities: [READ, LIST]
    - name: "myapp-admin"
      rules:
        - path: "kv/data/myapp/*"
          capabilities: [READ, WRITE, DELETE, LIST]
    - name: "deny-all"
      rules: []

  auth:
    static-tokens:
      enabled: true
      mappings:
        - token: "dev-root-token"
          policyNames: ["myapp-admin"]
        - token: "app-token-readonly"
          policyNames: ["kv-reader"]
        - token: "no-access-token"
          policyNames: ["deny-all"]
```

### Step 7: Update StaticTokenAuthFilter
Refactor to store `policyNames` in Spring Security `GrantedAuthority`:

```java
List<GrantedAuthority> authorities = mapping.policyNames().stream()
    .map(policyName -> new SimpleGrantedAuthority("POLICY_" + policyName))
    .toList();
```

### Step 8: Update Documentation
- Add new properties to `README.md`.
- Update `CHANGELOG.md` to reflect new policy and token mapping structure.

### Step 9: Commit Message
Example:

```
feat(auth): Define policy structure and link to static tokens

- Defines PolicyDefinition, PolicyRule, PolicyCapability, and StaticTokenPolicyMapping.
- Updates StaticTokenAuthFilter.
- Updates configuration files.
- Removes StaticTokenConfigValidator.
```

---

This completes Task 14. Policies are now structurally ready for Task 15, where enforcement will be implemented.
