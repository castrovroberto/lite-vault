
# Task 11: Basic Static Token Authentication - Manual

## Goal
Implement Basic Static Token Authentication using Spring Security.

## Tasks Breakdown
1. Add the Spring Security dependency.
2. Update `MssmProperties` to load static token configurations.
3. Create a custom authentication filter (`StaticTokenAuthFilter`) to check the `X-Vault-Token` header.
4. Configure Spring Security (`SecurityConfig`) to use the filter, define protected/public paths, and enforce stateless authentication.
5. Update `application-dev.yml` with example tokens.
6. Update project documentation.

---

## 1. Add Spring Security Dependency
Add to `pom.xml`:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

---

## 2. Update `MssmProperties`
Update `MssmProperties.java` to include:

```java
@Data
@Validated
@ConfigurationProperties(prefix = "mssm")
public class MssmProperties {
    // Existing properties
    @Valid
    @NotNull
    private AuthProperties auth = new AuthProperties();

    @Data
    public static class AuthProperties {
        @Valid
        @NotNull
        private StaticTokenAuthProperties staticTokens = new StaticTokenAuthProperties();
    }

    @Data
    public static class StaticTokenAuthProperties {
        private boolean enabled = false;
        @NotEmpty(message = "At least one static token must be configured if static token auth is enabled.")
        private Set<String> tokens = Collections.emptySet();
    }
}
```

---

## 3. Create `StaticTokenAuthFilter`
New file: `tech.yump.vault.auth.StaticTokenAuthFilter.java`

- Validates `X-Vault-Token` header.
- Sets Spring Security context on valid token.
- Skips filtering for public paths like `/sys/seal-status`.

---

## 4. Configure Spring Security (`SecurityConfig`)
New file: `tech.yump.vault.config.SecurityConfig.java`

Highlights:
- Disable CSRF, login forms.
- Add `StaticTokenAuthFilter` before default security filters.
- Allow public access to `/` and `/sys/seal-status`.
- Protect all other endpoints.

---

## 5. Update `application-dev.yml`
Example:

```yaml
mssm:
  auth:
    static-tokens:
      enabled: true
      tokens:
        - "dev-root-token"
        - "app-token-readonly"
```

---

## 6. Update Documentation
- **README.md**: Document new static token auth feature.
- **CHANGELOG.md**: Add entries under `[Unreleased]`:

```markdown
### Added
- Basic Static Token Authentication (Task 11):
  - Spring Security integration
  - StaticTokenAuthFilter
  - SecurityConfig
  - application-dev.yml updates
```

---

## Testing Instructions
1. **Without Token:** Access `/sys/seal-status` → should succeed.
2. **Without Token:** Access any protected path → should receive 401 Unauthorized.
3. **With Valid Token:** Access protected path → should succeed (404 if path missing but not 401/403).
4. **With Invalid Token:** Access protected path → should receive 401/403.

Example curl with token:

```bash
curl -k -H "X-Vault-Token: dev-root-token" https://localhost:8443/v1/protected-path
```

---

## Achievements
- Static token authentication operational.
- Spring Security integrated cleanly and modularly.
- Robust foundation for more advanced authentication later (e.g., app-roles, OIDC).

---

## Next Step
- Task 12+: Continue expanding the authentication, authorization, and secret engine functionalities.
