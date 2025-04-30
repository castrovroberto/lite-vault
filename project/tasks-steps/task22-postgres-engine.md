# Task 22: Implement PostgreSQL Secrets Engine Core

This task involves setting up the foundational structure for the PostgreSQL secrets engine, which will later support dynamic credential generation and lease revocation. Below is a step-by-step guide to completing Task 22.

---

## Step 1: Add Dependencies to `pom.xml`

Include the PostgreSQL JDBC driver and Spring Boot’s JDBC starter:

```xml
<!-- PostgreSQL JDBC Driver (Task 22) -->
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <scope>runtime</scope>
</dependency>

<!-- Spring Boot Starter JDBC (Task 22 / Task 24) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>
```

After adding, run:

```bash
mvn clean install
```

Or:

```bash
mvn dependency:resolve
```

---

## Step 2: Create Secrets Engine Package

Create a new sub-package:

```
src/main/java/tech/yump/vault/secrets/db/
```

---

## Step 3: Create `PostgresSecretsEngine.java` Skeleton

File: `src/main/java/tech/yump/vault/secrets/db/PostgresSecretsEngine.java`

```java
package tech.yump.vault.secrets.db;

import java.util.UUID;
import javax.sql.DataSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.secrets.DynamicSecretsEngine;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.LeaseNotFoundException;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;

@Slf4j
@Service
@RequiredArgsConstructor
public class PostgresSecretsEngine implements DynamicSecretsEngine {

    private final MssmProperties properties;
    private final DataSource dataSource;

    @Override
    public Lease generateCredentials(String roleName) throws SecretsEngineException, RoleNotFoundException {
        log.warn("PostgresSecretsEngine.generateCredentials for role '{}' is not yet implemented.", roleName);
        throw new UnsupportedOperationException("generateCredentials not implemented yet");
    }

    @Override
    public void revokeLease(UUID leaseId) throws SecretsEngineException, LeaseNotFoundException {
        log.warn("PostgresSecretsEngine.revokeLease for lease ID '{}' is not yet implemented.", leaseId);
        throw new UnsupportedOperationException("revokeLease not implemented yet");
    }

    // Helper methods will go here
}
```

---

## Explanation

- **`@Service`** registers it as a Spring Bean.
- **`@RequiredArgsConstructor`** handles constructor injection.
- **`MssmProperties`** will hold configuration (loaded in Task 23).
- **`DataSource`** will be auto-configured via Spring Boot JDBC starter.
- **Method Stubs** are in place for `generateCredentials()` and `revokeLease()`.

---

## Step 4: Verify Setup

- Ensure imports are resolved.
- Run:

```bash
mvn clean compile
```

- Start the application to confirm no startup errors.

---

## ✅ Completion

Task 22 is now complete. Next up is **Task 23**, where configuration loading will be defined for this engine.
