package tech.yump.vault.api;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.yump.vault.api.dto.DbCredentialsResponse;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.secrets.Lease;
import tech.yump.vault.secrets.RoleNotFoundException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.db.PostgresSecretsEngine; // Import the engine

import java.util.Map;

@RestController
@RequestMapping("/v1/db") // Base path for database secrets endpoints
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
            // Call the engine (Task 25 implementation is now present)
            Lease generatedLease = postgresSecretsEngine.generateCredentials(roleName);

            // --- Mapping Logic ---
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
            // Remove the temporary UnsupportedOperationException handling as Task 25 is done
            // } catch (UnsupportedOperationException e) {
            //     log.error("DB Credential generation for role '{}' is not yet implemented.", roleName);
            //     throw new SecretsEngineException("Feature not implemented yet.", e);
        } catch (ClassCastException | NullPointerException e) {
            // Catch potential errors accessing username/password from the Lease's secretData map
            log.error("Internal error processing generated lease data for role '{}': {}", roleName, e.getMessage(), e);
            throw new SecretsEngineException("Internal error: Failed to process generated credentials.", e);
        }
    }


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