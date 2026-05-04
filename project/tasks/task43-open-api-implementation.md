Okay, let's integrate `springdoc-openapi` into the `lite-vault` project following the detailed plan, providing context and specifics for each step.

**Goal:** Automatically generate OpenAPI v3 documentation for the `lite-vault` API, configure it correctly (including the `X-Vault-Token` authentication), and expose it via standard endpoints.

**Assumptions:**
* We're working with the provided `lite-vault` codebase.
* Maven is the build tool (`pom.xml` exists).
* Spring Boot with Spring Web MVC is used (evident from dependencies and controllers).
* Controllers use standard annotations (`@RestController`, `@GetMapping`, `@PostMapping`, `@PathVariable`, `@RequestBody`, `@RequestHeader`).
* Authentication uses the `X-Vault-Token` header, handled by `StaticTokenAuthFilter`.

---

**Step 1: Add springdoc-openapi Dependency**

1.  **Action:** Open the `lite-vault/pom.xml` file.
2.  **Action:** Locate the `<dependencies>` section. Add the `springdoc-openapi-starter-webmvc-ui` dependency. This single dependency bundles the core OpenAPI generation logic (`springdoc-openapi-starter-webmvc-api`) and the Swagger UI webjar (`swagger-ui`).

    ```xml
    <dependency>
        <groupId>org.springdoc</groupId>
        <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
        <version>2.5.0</version>
    </dependency>

    ```
    * **Context:** We choose `springdoc-openapi-starter-webmvc-ui` because the project uses Spring Web MVC (Tomcat-based web server). If it were using WebFlux (Netty), we'd use `springdoc-openapi-starter-webflux-ui`. The `-ui` suffix includes the Swagger UI interface for easy Browse and testing.
    * **Version Check:** It's crucial to use a version compatible with the Spring Boot version defined in your `pom.xml` (likely in the `<parent>` tag or `<properties>`). Check the [springdoc-openapi documentation](https://springdoc.org/) or [Maven Central](https://search.maven.org/) for compatibility notes. Version `2.5.0` requires Spring Boot 3.x. If `lite-vault` uses Spring Boot 2.x, you'd need a `1.x.x` version of `springdoc-openapi`. Let's assume `lite-vault` is on Spring Boot 3.x for this example.

3.  **Action:** Reload your Maven project.
    * In IntelliJ IDEA: Right-click on `pom.xml` -> Maven -> Reload project.
    * In Eclipse: Right-click on the project -> Maven -> Update Project...
    * From command line: The dependency will be downloaded on the next build (`mvn clean install`).
4.  **Verification:** Run `mvn dependency:tree` from the command line in the `lite-vault` project root directory.
    * **Purpose:** This command displays the project's dependency tree.
    * **Check:** Look for `org.springdoc:springdoc-openapi-starter-webmvc-ui` in the output. Also, check for any potential version conflicts related to Swagger or OpenAPI dependencies (e.g., `io.swagger.core.v3`). `springdoc-openapi` should manage these transitively. Ensure there are no obvious `WARN`ings about conflicting versions being resolved.

---

**Step 2: Configure Basic API Information**

1.  **Action:** Open the main configuration file: `lite-vault/src/main/resources/application.yml`.
2.  **Action:** Add properties under a `springdoc` key to define the API metadata.

    ```yaml
    # Existing application properties (server, mssm, etc.)
    # ...

    # SpringDoc OpenAPI Configuration
    springdoc:
      api-docs:
        # Path for the raw OpenAPI JSON/YAML specification
        # Default is /v3/api-docs, usually no need to change
        path: /v3/api-docs
      swagger-ui:
        # Path for the Swagger UI interface
        # Default is /swagger-ui.html, usually no need to change
        path: /swagger-ui.html
        # Optional: Disable the default Petstore example spec url
        # urls.primaryName: "Lite Vault API"
      info:
        title: Lite Vault API (Minimal Secure Secrets Manager)
        # Fetch version dynamically from pom.xml using Maven resource filtering,
        # or hardcode the target release version.
        # Using @project.version@ requires build configuration (see below)
        version: '@project.version@' # Or e.g., 'v0.5.0'
        description: API for managing secrets (KV, Dynamic DB Credentials, JWT Signing) securely via Lite Vault.
        # Optional: Add contact and license info
        contact:
          name: Project Team Yump
          # email: your.email@example.com # Add if desired
          # url: https://github.com/your-repo # Add if desired
        license:
          name: Apache 2.0
          url: http://www.apache.org/licenses/LICENSE-2.0.html
      # Optional: Add server information (useful if deploying behind a proxy)
      # servers:
      #   - url: https://api.yourdomain.com/lite-vault
      #     description: Production Environment
      #   - url: http://localhost:8080
      #     description: Local Development

    # ... rest of application.yml
    ```
    * **Context:** These properties populate the `info` section of the OpenAPI specification. Using `@project.version@` is a good practice to keep the documentation version in sync with the build version. To make this work:
        * Ensure resource filtering is enabled in your `pom.xml` (it usually is by default with `spring-boot-starter-parent`):
            ```xml
            <build>
                <resources>
                    <resource>
                        <directory>src/main/resources</directory>
                        <filtering>true</filtering> </resource>
                </resources>
                </build>
            ```
        * When you build the project (`mvn clean install`), Maven will replace `@project.version@` in `application.yml` (within the `target/classes` directory) with the actual version from the `pom.xml`.
    * The `api-docs.path` and `swagger-ui.path` confirm the endpoints where the documentation will be available.

3.  **Verification:**
    * **Action:** Start the `lite-vault` application (`mvn spring-boot:run` or via your IDE).
    * **Action:** Open your web browser and navigate to `http://localhost:8080/swagger-ui.html` (assuming the default port 8080 and context path `/`).
    * **Check:**
        * Does the Swagger UI page load?
        * At the top of the page, do you see the correct title ("Lite Vault API...")?
        * Is the version displayed correctly (either the hardcoded value or the version from `pom.xml`)?
        * Is the description present?
        * Are the contact and license details (if added) visible?
        * Are the controllers/endpoints listed (e.g., `db-controller`, `jwt-controller`, `kv-controller`)? They will be basic at this stage.

---

**Step 3: Configure Authentication Requirement (X-Vault-Token)**

1.  **Action:** Create a new Java configuration class. A good location would be `src/main/java/tech/yump/vault/config/OpenApiConfig.java`.
2.  **Action:** Define a `@Bean` of type `OpenAPI` to configure security schemes globally.

    ```java
    package tech.yump.vault.config;

    import io.swagger.v3.oas.models.Components;
    import io.swagger.v3.oas.models.OpenAPI;
    import io.swagger.v3.oas.models.security.SecurityRequirement;
    import io.swagger.v3.oas.models.security.SecurityScheme;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;

    @Configuration
    public class OpenApiConfig {

        // Define a constant for the security scheme name used in the OpenAPI spec
        private static final String SECURITY_SCHEME_NAME = "VaultTokenAuth";
        // Define the actual header name
        private static final String API_KEY_HEADER_NAME = "X-Vault-Token";

        @Bean
        public OpenAPI customOpenAPI() {
            // Define the Security Scheme (API Key in Header)
            // This describes *how* authentication works.
            SecurityScheme apiKeyScheme = new SecurityScheme()
                    .name(API_KEY_HEADER_NAME) // Specifies the actual header name clients must use
                    .type(SecurityScheme.Type.APIKEY) // Identifies the scheme type as API Key
                    .in(SecurityScheme.In.HEADER) // Specifies the location of the API key (header)
                    .description("Static API token ('" + API_KEY_HEADER_NAME + "') for accessing Lite Vault endpoints. Obtain from configuration or administrator.");

            // Define the Security Requirement
            // This applies the defined scheme globally to all API operations.
            SecurityRequirement securityRequirement = new SecurityRequirement()
                    // The key added here ("VaultTokenAuth") MUST match the key used
                    // when adding the scheme to components.securitySchemes below.
                    .addList(SECURITY_SCHEME_NAME);

            return new OpenAPI()
                    // Add the security scheme definition to the components section of the spec.
                    // The key ("VaultTokenAuth") is the logical name used within the spec
                    // to refer to this scheme (e.g., in security requirements).
                    .components(new Components()
                            .addSecuritySchemes(SECURITY_SCHEME_NAME, apiKeyScheme))
                    // Apply the security requirement globally. All endpoints will now
                    // indicate they require this authentication method by default.
                    .addSecurityItem(securityRequirement);

            // Note: Basic API info (title, version, etc.) is configured via
            // application.yml and automatically picked up by springdoc.
            // No need to set .info() here unless overriding properties.
        }
    }
    ```
    * **Context:** We are defining an `APIKEY` security scheme located in the `HEADER`, named `X-Vault-Token`. The `SECURITY_SCHEME_NAME` ("VaultTokenAuth") is a logical name used within the OpenAPI document structure to link the requirement to the scheme definition. The `.addSecurityItem(securityRequirement)` call applies this requirement globally, meaning all endpoints will be marked as requiring this `X-Vault-Token` unless explicitly overridden. This matches the behavior of the `StaticTokenAuthFilter` which intercepts all relevant requests.

3.  **Verification:**
    * **Action:** Restart the `lite-vault` application.
    * **Action:** Access the Swagger UI again (`http://localhost:8080/swagger-ui.html`).
        * **Check:** Look for an "Authorize" button, usually near the top right.
        * **Check:** Click the "Authorize" button. A dialog should appear.
            * It should show the scheme name (`VaultTokenAuth` or similar).
            * It should clearly indicate it needs the `X-Vault-Token` (based on the `name` and `description` set in the `SecurityScheme`).
            * It should provide an input field labeled "Value" where you can paste the token.
        * **Check:** Expand any of the API operations (e.g., GET `/v1/kv/{mount}/{path}`). Look for a small padlock icon (usually closed/locked) next to the operation summary. This indicates that authentication is required for this endpoint. Hovering over it might show the required scheme (`VaultTokenAuth`).
    * **Action:** Access the raw OpenAPI specification at `http://localhost:8080/v3/api-docs`.
        * **Check:** Search for the `components` section. Inside it, there should be a `securitySchemes` object containing your `VaultTokenAuth` definition, detailing its type (`apiKey`), location (`header`), and name (`X-Vault-Token`).
        * **Check:** Search for the top-level `security` array. It should contain an item referencing your scheme, like `[{"VaultTokenAuth": []}]`. This confirms the global application of the security requirement.

---

**Step 4: Enhance Documentation with Annotations (Optional but Recommended)**

1.  **Action:** Review the existing controllers:
    * `lite-vault/src/main/java/tech/yump/vault/api/v1/KVController.java`
    * `lite-vault/src/main/java/tech/yump/vault/api/v1/JwtController.java`
    * `lite-vault/src/main/java/tech/yump/vault/api/DbController.java` (Note: This is mapped to `/db`, not `/v1/db`. Consider if it should be moved to `/v1` for consistency).
    * `lite-vault/src/main/java/tech/yump/vault/api/RootController.java` (May not need detailed docs, but could be annotated).
2.  **Action:** Add relevant annotations to controllers, methods, parameters, and DTOs for better clarity.
3.  **Example (Applying to `KVController.java`):**

    ```java
    package tech.yump.vault.api.v1;

    // Import necessary Swagger annotations
    import io.swagger.v3.oas.annotations.Operation;
    import io.swagger.v3.oas.annotations.Parameter;
    import io.swagger.v3.oas.annotations.media.Content;
    import io.swagger.v3.oas.annotations.media.ExampleObject;
    import io.swagger.v3.oas.annotations.media.Schema;
    import io.swagger.v3.oas.annotations.parameters.RequestBody; // Correct import for request body description
    import io.swagger.v3.oas.annotations.responses.ApiResponse;
    import io.swagger.v3.oas.annotations.responses.ApiResponses;
    import io.swagger.v3.oas.annotations.security.SecurityRequirement; // Needed if overriding global security
    import io.swagger.v3.oas.annotations.tags.Tag;

    import org.slf4j.Logger;
    import org.slf4j.LoggerFactory;
    import org.springframework.http.HttpStatus;
    import org.springframework.http.MediaType;
    import org.springframework.http.ResponseEntity;
    import org.springframework.web.bind.annotation.*;
    import tech.yump.vault.api.ApiError; // Assuming ApiError is used for error responses
    import tech.yump.vault.audit.AuditHelper;
    import tech.yump.vault.secrets.kv.KVEngineException;
    import tech.yump.vault.secrets.kv.KVSecretEngine;

    import java.util.Map;

    @RestController
    @RequestMapping("/v1/kv/{mount}/{path}")
    // Tag groups endpoints in the Swagger UI
    @Tag(name = "KV Secrets", description = "Operations for the Key-Value v1 Secrets Engine")
    // No need for @SecurityRequirement here if the global config in OpenApiConfig is sufficient
    public class KVController {

        private static final Logger log = LoggerFactory.getLogger(KVController.class);
        private final KVSecretEngine kvSecretEngine;
        private final AuditHelper auditHelper;

        // Constructor injection...
        public KVController(KVSecretEngine kvSecretEngine, AuditHelper auditHelper) {
            this.kvSecretEngine = kvSecretEngine;
            this.auditHelper = auditHelper;
        }

        @GetMapping
        // Describe the operation
        @Operation(
                summary = "Read secret",
                description = "Retrieves the secret data stored at the specified mount and path in the KV engine."
        )
        // Describe possible responses
        @ApiResponses(value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "Secret data retrieved successfully.",
                        content = @Content(
                                mediaType = MediaType.APPLICATION_JSON_VALUE,
                                // Define the schema of the response body
                                schema = @Schema(type = "object", example = "{\"key1\": \"value1\", \"key2\": \"value2\"}")
                                // If you had a specific DTO like SecretReadResponse.class, you'd use:
                                // schema = @Schema(implementation = SecretReadResponse.class)
                        )
                ),
                @ApiResponse(
                        responseCode = "401",
                        description = "Authentication failed (Missing or invalid X-Vault-Token).",
                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))
                ),
                @ApiResponse(
                        responseCode = "403",
                        description = "Permission denied based on token policy.",
                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))
                ),
                @ApiResponse(
                        responseCode = "404",
                        description = "Secret not found at the specified mount/path or mount/engine does not exist.",
                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))
                ),
                @ApiResponse(
                        responseCode = "500",
                        description = "Internal server error.",
                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))
                )
        })
        public ResponseEntity<Map<String, Object>> readSecret(
                // Describe path parameters
                @Parameter(description = "Mount point of the KV v1 engine.", example = "secret", required = true)
                @PathVariable String mount,
                @Parameter(description = "Path to the secret (e.g., 'myapp/config'). URL encoding might be needed for special characters.", example = "myapp/config", required = true)
                @PathVariable String path,
                // Describe headers (hide auth header if globally defined)
                @Parameter(hidden = true) // Hide X-Vault-Token from UI parameters as it's handled by the Authorize button
                @RequestHeader("X-Vault-Token") String token
        ) throws KVEngineException {
            // ... (implementation remains the same)
            log.info("Reading secret at mount='{}', path='{}'", mount, path);
            Map<String, Object> secretData = kvSecretEngine.readSecret(mount, path);
            if (secretData == null || secretData.isEmpty()) {
                log.warn("Secret not found for mount='{}', path='{}'", mount, path);
                // Consider throwing specific exception caught by handler to return 404
                // For now, returning empty body - adjust based on desired behavior for not found
                 return ResponseEntity.notFound().build(); // Or throw an exception handled by GlobalExceptionHandler
            }
            auditHelper.auditSuccess(token, "read", "kv/" + mount + "/" + path);
            return ResponseEntity.ok(secretData);
        }

        @PostMapping
        @Operation(
                summary = "Write secret",
                description = "Stores or updates secret data at the specified mount and path in the KV engine."
        )
        @ApiResponses(value = {
                @ApiResponse(responseCode = "204", description = "Secret written successfully."),
                @ApiResponse(responseCode = "400", description = "Invalid request body format.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
                @ApiResponse(responseCode = "401", description = "Authentication failed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
                @ApiResponse(responseCode = "403", description = "Permission denied.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
                 @ApiResponse(responseCode = "404", description = "Mount/engine does not exist.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
                @ApiResponse(responseCode = "500", description = "Internal server error.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class)))
        })
        public ResponseEntity<Void> writeSecret(
                @Parameter(description = "Mount point of the KV v1 engine.", example = "secret", required = true)
                @PathVariable String mount,
                @Parameter(description = "Path to store the secret (e.g., 'myapp/config').", example = "myapp/config", required = true)
                @PathVariable String path,
                // Describe the request body
                @RequestBody(
                        description = "Key-value pairs to store as the secret data.",
                        required = true,
                        content = @Content(
                                mediaType = MediaType.APPLICATION_JSON_VALUE,
                                schema = @Schema(type = "object", example = "{\"apiKey\": \"123-abc\", \"timeout\": 30}"),
                                // Example using ExampleObject for more complex examples:
                                // examples = @ExampleObject(
                                //     name = "Database Credentials Example",
                                //     summary = "Example for DB creds",
                                //     value = "{\"username\": \"dbuser\", \"password\": \"s3cr3tP@ss\"}"
                                // )
                        )
                )
                @org.springframework.web.bind.annotation.RequestBody Map<String, Object> data, // Use Spring's RequestBody annotation
                @Parameter(hidden = true) @RequestHeader("X-Vault-Token") String token
        ) throws KVEngineException {
             // ... (implementation remains the same)
            log.info("Writing secret at mount='{}', path='{}'", mount, path);
            kvSecretEngine.writeSecret(mount, path, data);
            auditHelper.auditSuccess(token, "write", "kv/" + mount + "/" + path);
            // Return 204 No Content for successful writes/updates without a body
            return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        }

        @DeleteMapping
        @Operation(
                summary = "Delete secret",
                description = "Removes the secret data stored at the specified mount and path."
        )
        @ApiResponses(value = {
                @ApiResponse(responseCode = "204", description = "Secret deleted successfully."),
                 @ApiResponse(responseCode = "401", description = "Authentication failed.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
                @ApiResponse(responseCode = "403", description = "Permission denied.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
                 @ApiResponse(responseCode = "404", description = "Secret not found or Mount/engine does not exist.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class))),
                @ApiResponse(responseCode = "500", description = "Internal server error.", content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE, schema = @Schema(implementation = ApiError.class)))
        })
        public ResponseEntity<Void> deleteSecret(
                @Parameter(description = "Mount point of the KV v1 engine.", example = "secret", required = true)
                @PathVariable String mount,
                @Parameter(description = "Path of the secret to delete.", example = "myapp/config", required = true)
                @PathVariable String path,
                @Parameter(hidden = true) @RequestHeader("X-Vault-Token") String token
        ) throws KVEngineException {
            // ... (implementation remains the same)
             log.info("Deleting secret at mount='{}', path='{}'", mount, path);
            kvSecretEngine.deleteSecret(mount, path);
            auditHelper.auditSuccess(token, "delete", "kv/" + mount + "/" + path);
             // Return 204 No Content for successful deletions
            return ResponseEntity.noContent().build();
        }
    }
    ```
    * **DTO Enhancement:** You can add `@Schema` annotations directly to your DTO classes (like `DbCredentialsResponse.java`, `ApiError.java`, and any JWT-related DTOs) and their fields to provide descriptions, examples, and mark fields as required.
        ```java
        // Example on a field in a DTO (e.g., DbCredentialsResponse.java)
        import io.swagger.v3.oas.annotations.media.Schema;

        // ... inside the class ...
        @Schema(description = "The dynamically generated database username.", example = "vault_user_1a2b3c", requiredMode = Schema.RequiredMode.REQUIRED)
        private String username;

        @Schema(description = "The dynamically generated database password.", example = "S3cr3tP@ssw0rd!", requiredMode = Schema.RequiredMode.REQUIRED)
        private String password;

        @Schema(description = "The duration for which these credentials are valid, in seconds.", example = "3600", requiredMode = Schema.RequiredMode.REQUIRED)
        private long leaseDuration;
        // ... etc ...
        ```
    * **Apply Similar Annotations:** Go through `JwtController` and `DbController` and apply similar `@Tag`, `@Operation`, `@Parameter`, `@RequestBody`, and `@ApiResponses` annotations to fully document their endpoints, parameters, request bodies, and response structures (including success and error responses). Pay attention to using the correct DTOs in `@Schema(implementation = ...)` where applicable (e.g., `DbCredentialsResponse.class`, `JwtSignResponse`, etc.). Use `@Schema` on the DTOs themselves too.

4.  **Verification:**
    * **Action:** Restart the application.
    * **Action:** Refresh the Swagger UI page (`http://localhost:8080/swagger-ui.html`).
    * **Check:**
        * Are the endpoints grouped under the Tags you defined (e.g., "KV Secrets", "JWT Secrets", "DB Credentials")?
        * Does each operation now have a clear summary and description?
        * Are path parameters, query parameters, and request bodies described accurately, including examples?
        * Are the possible HTTP response codes listed for each operation (e.g., 200, 204, 400, 401, 403, 404, 500)?
        * Do the responses define the expected content type (e.g., `application/json`) and schema (referencing your DTOs or basic types)?
        * Are DTO schemas correctly rendered, showing field names, types, descriptions, and examples added via `@Schema`?
        * Is the `X-Vault-Token` header *not* listed as an explicit parameter for operations (because it's handled by the global "Authorize" button)?
    * **Action:** Check the raw spec (`/v3/api-docs`) again. Verify that the `paths` section now contains the detailed descriptions, parameters, requestBodies, responses, and tags corresponding to your annotations.

---

**Step 5: Final Verification and Testing**

1.  **Action:** Thoroughly review the entire Swagger UI interface.
    * **Completeness:** Are all `v1` API endpoints from `KVController` and `JwtController` present? Is the `/db` endpoint from `DbController` present? Are there any missing endpoints? Are there endpoints listed that *shouldn't* be (e.g., actuator endpoints if not explicitly configured to be included/excluded)?
    * **Accuracy:**
        * Do parameter types match (path vs. query vs. header)? Are descriptions clear? Are examples helpful?
        * Do request body schemas match the expected JSON structure? Are required fields indicated?
        * Do response schemas accurately reflect the DTOs for both success and error cases (like `ApiError`)? Check data types, required fields, and examples.
    * **Authentication:** Confirm the padlock icon is present on all relevant endpoints and the "Authorize" button works as expected. Test making a request *without* providing the token via "Authorize" – it should fail with a 401 (or be blocked by the filter before hitting the controller).
    * **Response Codes:** Verify that the documented status codes align with the actual application behavior (e.g., POST returning 204, GET returning 200 or 404, errors returning 4xx/5xx with an `ApiError` body).

2.  **Action:** Validate the raw OpenAPI spec.
    * **Action:** Go to `http://localhost:8080/v3/api-docs`. Copy the entire JSON output.
    * **Action:** Go to an online validator like [editor.swagger.io](https://editor.swagger.io/). Paste the JSON into the editor.
    * **Check:** The editor should report if the specification is valid according to the OpenAPI 3.0 schema. Address any structural errors reported. Common issues might involve incorrect schema references or data types.

3.  **Action (Optional but Highly Recommended):** Use the "Try it out" feature in Swagger UI.
    * **Prerequisites:**
        * You need a valid `X-Vault-Token` (e.g., the one configured in `application-dev.yml` or `application.yml` under `mssm.auth.static-token.token`).
        * For `DbController` tests, the application needs to be configured correctly to connect to a running database instance as specified in its roles.
    * **Test Scenarios:**
        * **Authorize:** Click "Authorize" and enter your valid `X-Vault-Token`. Click "Authorize" again and close the popup.
        * **KV Write:** Try the `POST /v1/kv/{mount}/{path}` endpoint. Fill in `mount` (e.g., `secret`), `path` (e.g., `test/mykey`), and a JSON body (e.g., `{"value": "abc"}`). Execute. Expect a `204 No Content` response.
        * **KV Read:** Try the `GET /v1/kv/{mount}/{path}` endpoint with the same `mount` and `path`. Execute. Expect a `200 OK` response with the body `{"value": "abc"}`.
        * **KV Read (Not Found):** Try `GET /v1/kv/{mount}/{path}` with a non-existent path. Expect a `404 Not Found` response.
        * **JWT Sign:** Try `POST /v1/jwt/sign/{role}`. Fill in a valid role name configured in your `application.yml` (e.g., `my-app-role`) and provide a valid claims JSON body (e.g., `{"sub": "user123"}`). Execute. Expect a `200 OK` with a `signedJwt` in the response.
        * **DB Credentials:** Try `GET /db/creds/{role}`. Fill in a valid DB role name configured (e.g., `readonly-role`). Execute. Expect a `200 OK` with `username`, `password`, and `leaseDuration`.
        * **Unauthorized Test:** Click "Authorize" -> "Logout". Try any endpoint again. Expect a `401 Unauthorized` error (or potentially a block before the API is hit).

---

**Step 6: Commit and Document**

1.  **Action:** Commit the changes to your version control system (Git).
    * Stage the modified files: `pom.xml`, `src/main/resources/application.yml`, `src/main/java/tech/yump/vault/config/OpenApiConfig.java`, and any controller files (`KVController.java`, `JwtController.java`, `DbController.java`) that had annotations added. Also include any modified DTOs.
    * Commit with a clear message: `feat: Integrate springdoc-openapi for API documentation` or `chore: Add OpenAPI v3 specification and Swagger UI`.

2.  **Action:** Update project documentation, primarily `README.md`.
    * Add a new section, for example:

        ```markdown
        ## API Documentation

        This project uses `springdoc-openapi` to generate interactive API documentation using the OpenAPI v3 specification.

        Once the application is running, you can access:

        * **Swagger UI:** [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html) - A web interface to browse, understand, and test the API endpoints. Remember to use the "Authorize" button with a valid `X-Vault-Token`.
        * **OpenAPI Spec (JSON):** [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs) - The raw OpenAPI specification in JSON format.
        * **OpenAPI Spec (YAML):** [http://localhost:8080/v3/api-docs.yaml](http://localhost:8080/v3/api-docs.yaml) - The raw OpenAPI specification in YAML format.

        (Adjust URLs if you changed the default paths or run on a different port/context path).
        ```
    * Commit the documentation update: `docs: Add section on accessing API documentation`.

---

This detailed walkthrough provides the necessary steps, code examples specific to `lite-vault`, context, and verification methods to successfully integrate and configure `springdoc-openapi`, resulting in accurate and accessible API documentation.