# Task 6: Set Up Minimal HTTP Server & Routing

## Goal
Initialize a basic HTTP server within our Spring Boot application that listens for requests and can route them to specific handlers. For this task, we'll create a simple root endpoint to confirm the server is running and routing works.

## Prerequisites
- Task 1 (pom.xml with `spring-boot-starter-web`) is done.
- Task 5 (SealManager, EncryptionService as `@Service` beans) is done.
- The main application class (LiteVaultApplication) is set up for Spring Boot.

## Step-by-Step Implementation

### Step 1: Verify `spring-boot-starter-web` Dependency
Ensure your `pom.xml` includes the necessary starter:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```
This brings in:
- Embedded web server (Tomcat by default)
- Spring Web MVC framework
- Jackson library for JSON processing

### Step 2: Ensure Main Application Class
Edit `/src/main/java/tech/yump/vault/LiteVaultApplication.java`:
```java
package tech.yump.vault;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@Slf4j
@SpringBootApplication
public class LiteVaultApplication {
    public static void main(String[] args) {
        SpringApplication.run(LiteVaultApplication.class, args);
        log.info(">>> LiteVault Application Started <<<");
    }
}
```

### Step 3: Create a Basic REST Controller
Create `src/main/java/tech/yump/vault/api/RootController.java`:
```java
package tech.yump.vault.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class RootController {

    @GetMapping("/")
    public Map<String, String> getRoot() {
        return Map.of(
            "message", "Welcome to LiteVault API",
            "status", "OK"
        );
    }
}
```

**Explanation:**
- `@RestController` = `@Controller` + `@ResponseBody`
- `@GetMapping("/")` routes GET requests to `/`
- Jackson automatically serializes the response to JSON

### Step 4: Configure Server Port (Optional)
Edit `src/main/resources/application.properties`:
```properties
server.port=8080
mssm.storage.filesystem.path=./lite-vault-data
# mssm.master.key.b64=YOUR_GENERATED_BASE64_KEY_HERE
```

### Step 5: Run and Verify
1. Set `MSSM_MASTER_KEY_B64` if needed.
2. Run using Maven or directly via IDE:
```bash
mvn spring-boot:run
```
3. Check logs:
    - Look for `Tomcat started on port(s): 8080 (http)` and `>>> LiteVault Application Started <<<`
4. Test endpoint:
```bash
curl http://localhost:8080/
```
**Expected Output:**
```json
{"message":"Welcome to LiteVault API","status":"OK"}
```

## Completion of Task 6
✅ Embedded web server (Tomcat) is running.  
✅ RootController routes `/` GET requests.  
✅ Returns a JSON response.  
✅ Application is ready for more API endpoints.

## What's Achieved
You have the foundation of the web layer. The application can listen for HTTP requests and route them to controller methods.

## Next Step
Proceed to **Task 7: Create `/sys/seal-status` API Endpoint**, using SealManager to report vault seal status.
