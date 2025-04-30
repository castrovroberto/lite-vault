
# Task 19: Write Unit Tests for Auth & ACLs

## Goal

Ensure that the LiteVault system's authentication and access control logic behaves correctly. Specifically, write unit tests that verify:

- Tokens are correctly validated
- Protected endpoints enforce the presence of a valid token
- ACLs are enforced (i.e., tokens with limited permissions receive 403)

---

## Scope

- System under test: Any controller/service that performs token validation or authorization checks.
- Mock external components (e.g., token service or permission service).
- Spring Security configuration should be part of the test context.

---

## Steps

### 1. Setup Test Configuration

- Use `@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)` or `@WebMvcTest` for controller-level tests.
- Inject or mock relevant beans (e.g., `TokenService`, `AclEvaluator`).

### 2. Test Cases

#### ✅ `GET /sys/seal-status`

- Should return 200 even with no token (public route).

```java
@Test
void sealStatus_shouldBeAccessibleWithoutAuth() throws Exception {
    mockMvc.perform(get("/sys/seal-status"))
           .andExpect(status().isOk());
}
```

#### 🚫 `GET /kv/data/test` with no token

- Should return 401 Unauthorized.

```java
@Test
void getSecret_withoutToken_shouldReturnUnauthorized() throws Exception {
    mockMvc.perform(get("/kv/data/test"))
           .andExpect(status().isUnauthorized());
}
```

#### 🚫 `GET /kv/data/test` with invalid token

- Should return 403 Forbidden (if token is present but invalid for path).

```java
@Test
void getSecret_withInvalidToken_shouldReturnForbidden() throws Exception {
    mockMvc.perform(get("/kv/data/test")
           .header("X-Vault-Token", "bad-token"))
           .andExpect(status().isForbidden());
}
```

#### ✅ `GET /kv/data/test` with read token

- Should return 200 OK and body with secret (mocked).

```java
@Test
void getSecret_withValidReadToken_shouldReturnSecret() throws Exception {
    when(tokenService.validate("read-token")).thenReturn(true);
    when(aclEvaluator.hasAccess("read-token", "kv/data/test", READ)).thenReturn(true);
    
    mockMvc.perform(get("/kv/data/test")
           .header("X-Vault-Token", "read-token"))
           .andExpect(status().isOk())
           .andExpect(content().string(containsString("key")));
}
```

#### 🚫 `PUT /kv/data/test` with read-only token

- Should return 403 Forbidden.

```java
@Test
void putSecret_withReadOnlyToken_shouldBeDenied() throws Exception {
    when(tokenService.validate("read-token")).thenReturn(true);
    when(aclEvaluator.hasAccess("read-token", "kv/data/test", WRITE)).thenReturn(false);

    mockMvc.perform(put("/kv/data/test")
           .header("X-Vault-Token", "read-token")
           .contentType(MediaType.APPLICATION_JSON)
           .content("{"key": "value"}"))
           .andExpect(status().isForbidden());
}
```

---

## Additional Notes

- Consider testing edge cases (e.g., malformed tokens, revoked tokens).
- Tests should run fast; use mocks over full Spring context if possible.
- Integration tests (TestRestTemplate) could be added separately to validate the actual HTTP layer.

---

## Completion Criteria

- [ ] Tests cover public vs protected endpoints
- [ ] Tests cover token absence, invalid token, and valid token
- [ ] Tests verify ACL enforcement
- [ ] CI pipeline runs the tests on push/PR
