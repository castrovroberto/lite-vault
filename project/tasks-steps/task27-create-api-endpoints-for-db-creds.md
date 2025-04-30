# Task 27: Create API Endpoints for DB Credentials

Okay, let's proceed to Task 27: Create API Endpoints for DB Credentials.This task involves creating a new Spring Boot REST controller that exposes the functionality of our PostgresSecretsEngine (specifically, the generateCredentials method we'll implement fully in Task 25, but we can use the placeholder for now). This endpoint will allow authenticated and authorized clients to request dynamic PostgreSQL credentials for a specific role.Here’s a step-by-step guide:Step 1: Create the Controller Class1.Create a new Java class named DbController in the tech.yump.vault.api package (alongside RootController and KVController).2.Annotate the class with standard Spring MVC annotations: @RestController, @RequestMapping("/v1/db"), @RequiredArgsConstructor, @Slf4j.3.Inject the PostgresSecretsEngine bean using constructor injection (handled by @RequiredArgsConstructor).

package tech.yump.vault.api;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.secrets.db.PostgresSecretsEngine; // Import the engine

@RestController
@RequestMapping("/v1/db") // Base path for database secrets endpoints
@RequiredArgsConstructor
@Slf4j
public class DbController {

    private final PostgresSecretsEngine postgresSecretsEngine;

    // Endpoint methods will go here

}

Step 2: Define the Response DTOIt's good practice to define a specific Data Transfer Object (DTO) for the API response to structure the returned credentials and lease information clearly.1.Create a new package tech.yump.vault.api.dto.2.Inside this package, create a Java record named DbCredentialsResponse.3.Define fields for the information we want to return: leaseId, username, password, and leaseDurationSeconds.

package tech.yump.vault.api.dto;

import java.util.UUID;

/**
 * DTO representing the response for a dynamic database credential request.
 *
 * @param leaseId            The unique ID associated with this credential lease.
 * @param username           The generated database username.
 * @param password           The generated database password.
 * @param leaseDurationSeconds The duration (in seconds) for which this lease is valid.
 */
public record DbCredentialsResponse(
    UUID leaseId,
    String username,
    String password,
    long leaseDurationSeconds // Represent duration as seconds for simple JSON
) {}

Step 3: Implement the generateCredentials Endpoint1.Inside DbController, create a method to handle GET requests for credentials.2.Use @GetMapping("/creds/{roleName}") to map the endpoint. The {roleName} part will be a path variable.3.Use @PathVariable to capture the roleName from the URL.4.Call the postgresSecretsEngine.generateCredentials(roleName) method.5.Map the resulting Lease object (when Task 25 is done) to the DbCredentialsResponse DTO.6.Return the DTO wrapped in a ResponseEntity.

package tech.yump.vault.api;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity; // Import ResponseEntity
import org.springframework.web.bind.annotation.GetMapping; // Import GetMapping
import org.springframework.web.bind.annotation.PathVariable; // Import PathVariable
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.dto.DbCredentialsResponse; // Import the DTO
import tech.yump.vault.secrets.Lease; // Import Lease
import tech.yump.vault.secrets.RoleNotFoundException; // Import exceptions
import tech.yump.vault.secrets.SecretsEngineException; // Import exceptions
import tech.yump.vault.secrets.db.PostgresSecretsEngine;

import java.util.Map; // Import Map

@RestController
@RequestMapping("/v1/db")
@RequiredArgsConstructor
@Slf4j
public class DbController {

    private final PostgresSecretsEngine postgresSecretsEngine;

    /**
     * Generates dynamic credentials for a specified PostgreSQL role.
     * Requires authentication and authorization (READ capability on db/creds/{roleName}).
     *
     * @param roleName The name of the configured PostgreSQL role definition.
     * @return ResponseEntity containing the generated credentials and lease info.
     */
    @GetMapping("/creds/{roleName}")
    public ResponseEntity<DbCredentialsResponse> generateDbCredentials(@PathVariable String roleName) {
        log.info("Received request to generate credentials for DB role: {}", roleName);

        try {
            // Call the engine (This will throw UnsupportedOperationException until Task 25 is done)
            Lease generatedLease = postgresSecretsEngine.generateCredentials(roleName);

            // --- Mapping Logic (will work once Task 25 is complete) ---
            Map<String, Object> secretData = generatedLease.secretData();
            String username = (String) secretData.get("username"); // Assumes Task 25 puts "username"
            String password = (String) secretData.get("password"); // Assumes Task 25 puts "password"

            if (username == null || password == null) {
                log.error("Generated lease for role '{}' is missing username or password in secretData.", roleName);
                throw new SecretsEngineException("Internal error: Generated credentials incomplete.");
            }

            DbCredentialsResponse response = new DbCredentialsResponse(
                    generatedLease.id(),
                    username,
                    password,
                    generatedLease.ttl().toSeconds() // Convert Duration to seconds
            );
            // --- End Mapping Logic ---

            log.info("Successfully generated credentials for DB role: {}", roleName);
            return ResponseEntity.ok(response);

        } catch (RoleNotFoundException e) {
            log.warn("Credential generation failed: Role '{}' not found.", roleName);
            // Let the exception handler (Step 4) handle this
            throw e;
        } catch (SecretsEngineException e) {
            log.error("Credential generation failed for role '{}': {}", roleName, e.getMessage(), e);
            // Let the exception handler (Step 4) handle this
            throw e;
        } catch (UnsupportedOperationException e) {
            // Temporary handling until Task 25 is done
            log.error("DB Credential generation for role '{}' is not yet implemented.", roleName);
            throw new SecretsEngineException("Feature not implemented yet.", e);
        } catch (ClassCastException | NullPointerException e) {
            // Catch potential errors accessing username/password from the Lease's secretData map
             log.error("Internal error processing generated lease data for role '{}': {}", roleName, e.getMessage(), e);
             throw new SecretsEngineException("Internal error: Failed to process generated credentials.", e);
        }
    }
}

Step 4: Add Exception HandlingJust like KVController, we need handlers to map exceptions from the secrets engine to appropriate HTTP status codes.1.Add @ExceptionHandler methods within DbController for the relevant exceptions.2.Map RoleNotFoundException to 404 (Not Found).3.Map VaultSealedException (if the engine throws it, though less likely here than in KV) to 503 (Service Unavailable).4.Map generic SecretsEngineException to 500 (Internal Server Error).

package tech.yump.vault.api;

// ... other imports ...
import org.springframework.http.HttpStatus; // Import HttpStatus
import org.springframework.http.ProblemDetail; // For RFC 7807 error responses
import org.springframework.web.bind.annotation.ExceptionHandler; // Import ExceptionHandler
import tech.yump.vault.core.VaultSealedException; // Import VaultSealedException

@RestController
@RequestMapping("/v1/db")
@RequiredArgsConstructor
@Slf4j
public class DbController {

    private final PostgresSecretsEngine postgresSecretsEngine;

    // --- generateDbCredentials method from Step 3 ---
    @GetMapping("/creds/{roleName}")
    public ResponseEntity<DbCredentialsResponse> generateDbCredentials(@PathVariable String roleName) {
       // ... (implementation from Step 3) ...
       log.info("Received request to generate credentials for DB role: {}", roleName);

        try {
            // Call the engine (This will throw UnsupportedOperationException until Task 25 is done)
            Lease generatedLease = postgresSecretsEngine.generateCredentials(roleName);

            // --- Mapping Logic (will work once Task 25 is complete) ---
            Map<String, Object> secretData = generatedLease.secretData();
            String username = (String) secretData.get("username"); // Assumes Task 25 puts "username"
            String password = (String) secretData.get("password"); // Assumes Task 25 puts "password"

            if (username == null || password == null) {
                log.error("Generated lease for role '{}' is missing username or password in secretData.", roleName);
                throw new SecretsEngineException("Internal error: Generated credentials incomplete.");
            }

            DbCredentialsResponse response = new DbCredentialsResponse(
                    generatedLease.id(),
                    username,
                    password,
                    generatedLease.ttl().toSeconds() // Convert Duration to seconds
            );
            // --- End Mapping Logic ---

            log.info("Successfully generated credentials for DB role: {}", roleName);
            return ResponseEntity.ok(response);

        } catch (RoleNotFoundException e) {
            log.warn("Credential generation failed: Role '{}' not found.", roleName);
            // Let the exception handler (Step 4) handle this
            throw e;
        } catch (SecretsEngineException e) {
            log.error("Credential generation failed for role '{}': {}", roleName, e.getMessage(), e);
            // Let the exception handler (Step 4) handle this
            throw e;
        } catch (UnsupportedOperationException e) {
            // Temporary handling until Task 25 is done
            log.error("DB Credential generation for role '{}' is not yet implemented.", roleName);
            throw new SecretsEngineException("Feature not implemented yet.", e);
        } catch (ClassCastException | NullPointerException e) {
            // Catch potential errors accessing username/password from the Lease's secretData map
             log.error("Internal error processing generated lease data for role '{}': {}", roleName, e.getMessage(), e);
             throw new SecretsEngineException("Internal error: Failed to process generated credentials.", e);
        }
    }


    // --- Exception Handlers ---

    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ProblemDetail> handleRoleNotFound(RoleNotFoundException ex) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        problemDetail.setTitle("Role Not Found");
        // Optionally add more details like problemDetail.setProperty("roleName", ...);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(problemDetail);
    }

    @ExceptionHandler(VaultSealedException.class)
    public ResponseEntity<ProblemDetail> handleVaultSealed(VaultSealedException ex) {
        // Less likely for DB engine unless it needs encryption service for some state, but good practice
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, ex.getMessage());
        problemDetail.setTitle("Vault Sealed");
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problemDetail);
    }

    @ExceptionHandler(SecretsEngineException.class)
    public ResponseEntity<ProblemDetail> handleSecretsEngineException(SecretsEngineException ex) {
        // Catch-all for other engine-specific errors (DB connection issues, SQL errors from Task 25, etc.)
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        problemDetail.setTitle("Secrets Engine Error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }

    // Optional: Add a handler for general exceptions if needed
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGenericException(Exception ex) {
        log.error("An unexpected error occurred processing DB credential request: {}", ex.getMessage(), ex);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected internal error occurred.");
        problemDetail.setTitle("Internal Server Error");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problemDetail);
    }
}

Step 5: Verify Security Configuration (ACLs)1.Open application-dev.yml.2.Ensure you have policies defined under mssm.policies that grant the READ capability to the path pattern matching your new endpoint. Examples:•A specific policy:

        - name: "db-app-user-policy"
          rules:
            - path: "db/creds/readonly-app-role" # Matches GET /v1/db/creds/readonly-app-role
              capabilities: [READ]
            - path: "db/creds/migrations-role"
              capabilities: [READ]
        

•A broader policy (like the example root-policy):

        - name: "root-policy"
          rules:
            # ... other rules ...
            - path: "db/creds/*" # Matches GET /v1/db/creds/*
              capabilities: [READ]
        

3.Ensure that the static tokens you intend to use for testing this endpoint are mapped to one of these policies under mssm.auth.static-tokens.mappings.No code changes are needed in the filters themselves; they should automatically protect the new endpoint based on the configuration.Step 6: Test (Manual for now)1.Run the application.2.Use curl (or a similar tool) to make a request, providing a valid X-Vault-Token that has the necessary policy assigned:

    # Replace {role_name} with a configured role like 'readonly-app-role'
    # Replace {your_token} with a token mapped to a policy granting READ on db/creds/{role_name}
    curl -k -H "X-Vault-Token: {your_token}" https://localhost:8443/v1/db/creds/{role_name}
    

3.Expected Result (Before Task 25): You should get a 500 Internal Server Error response with a message like "Feature not implemented yet." because PostgresSecretsEngine.generateCredentials throws UnsupportedOperationException.4.Test ACLs:•Try with a token that doesn't have the required policy -> Expect 403 Forbidden.•Try with an invalid token or no token -> Expect 401 Unauthorized.•Try requesting a role name that isn't configured (e.g., nonexistent-role) -> Expect 404 Not Found (once Task 25 implements role checking).With these steps, you have created the API endpoint structure for requesting dynamic DB credentials, integrated it with existing security, and added basic error handling. Task 27 is complete. The endpoint is ready to be fully activated once Task 25 (Credential Generation Logic) is implemented.