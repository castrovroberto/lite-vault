
# Task 9: Implement Basic Configuration Loading

## Goal
Make the application's configuration handling more robust, explicit, and validated, ensuring settings like storage paths, master key sources, and TLS parameters are loaded consistently and correctly.

This task focuses on improving how the application **consumes and validates** configuration, not just how Spring Boot loads it.

---

## Prerequisites
- Tasks 1–8 completed.
- Configuration properties exist in `application.yml` or `application-dev.yml` (e.g., `mssm.storage.filesystem.path`, `mssm.master.key.b64`, `server.ssl.*`).
- Sensitive values (passwords, keys) injected via `${VAR_NAME}` placeholders.

---

## Step-by-Step Implementation

### Step 1: Identify Core Configuration Groups
Properties grouped under `mssm` prefix:
- **Storage**: `mssm.storage.filesystem.path`
- **Master Key**: `mssm.master.key.b64`

TLS (`server.ssl.*`) will stay internally managed by Spring Boot.

---

### Step 2: Create `@ConfigurationProperties` Class

#### Create `MssmProperties.java`

```java
package tech.yump.vault.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "mssm")
@Validated
public record MssmProperties(
    @Valid MasterKeyProperties master,
    @Valid StorageProperties storage
) {

    @Validated
    public record MasterKeyProperties(
        @NotBlank(message = "Master key (mssm.master.key.b64) must be provided.") String b64
    ) {}

    @Validated
    public record StorageProperties(
        @Valid FileSystemProperties filesystem
    ) {
        @Validated
        public record FileSystemProperties(
            @NotBlank(message = "Filesystem storage path (mssm.storage.filesystem.path) must be provided.") String path
        ) {}
    }
}
```

- Use Java **records** for immutability and conciseness.
- Apply **validation** with `@NotBlank` and `@Validated`.

---

### Step 3: Enable Configuration Properties

#### Modify `LiteVaultApplication.java`

```java
@SpringBootApplication
@EnableConfigurationProperties(MssmProperties.class)
public class LiteVaultApplication {
    public static void main(String[] args) {
        SpringApplication.run(LiteVaultApplication.class, args);
    }
}
```

---

### Step 4: Add Validation Dependency

#### In `pom.xml`

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

---

### Step 5: Refactor Services to Use `MssmProperties`

#### `FileSystemStorageBackend.java`

```java
@Component
public class FileSystemStorageBackend implements StorageBackend {

    private final Path basePath;

    public FileSystemStorageBackend(ObjectMapper objectMapper, MssmProperties properties) {
        this.objectMapper = objectMapper;
        this.basePath = Paths.get(properties.storage().filesystem().path()).toAbsolutePath();
    }
}
```

#### `SealManager.java`

```java
@Service
public class SealManager {

    private final MssmProperties properties;

    public SealManager(MssmProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    protected void attemptAutoUnseal() {
        String base64Key = properties.master().b64();
        if (base64Key != null && !base64Key.isBlank()) {
            unseal(base64Key);
        }
    }
}
```

---

### Step 6: Verify Configuration Loading and Validation

#### Clean and Run with Valid Properties

```bash
mvn clean spring-boot:run -Dspring-boot.run.profiles=dev
```

- Application starts if properties are valid.
- `MSSM_MASTER_KEY_B64` must be set.

#### Test Invalid Cases

- **Missing Master Key** → startup failure.
- **Empty Filesystem Path** → startup failure.

Spring Boot will throw a validation error at startup.

---

## Completion of Task 9

✅ Centralized and type-safe configuration management with `MssmProperties`  
✅ Validation of critical settings using `spring-boot-starter-validation`  
✅ Refactored services (`SealManager`, `FileSystemStorageBackend`) to consume properties bean  
✅ Application fails fast on invalid configurations

---

## What's Achieved

- Robust, scalable, and maintainable configuration architecture.
- Avoids fragile scattered `@Value` injections.
- Ensures consistent validation early in the application lifecycle.

---

## Next Step

Proceed to **Task 10: Write Unit Tests for Encryption & Storage** to verify correctness of core components.

---
