# Task 17: Integrate Audit Logging into API & Security Filters

The following outlines the detailed implementation of audit logging integration into the core API request lifecycle and security filters of the LiteVault system.

We'll inject the LogAuditBackend (via the AuditBackend interface) into the key components involved in request processing and security checks:1.StaticTokenAuthFilter: To log authentication attempts.2.PolicyEnforcementFilter: To log authorization decisions.3.KVController: To log secret access operations (read/write/delete).Step 1: Inject AuditBackend into Filters and Controller1.Modify StaticTokenAuthFilter:•Add AuditBackend to the constructor.•Store it as a final field.

    package tech.yump.vault.auth;

    import jakarta.servlet.FilterChain;
    import jakarta.servlet.ServletException;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import lombok.extern.slf4j.Slf4j;
    import org.springframework.lang.NonNull;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.Authentication; // Added
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
    import org.springframework.util.StringUtils;
    import org.springframework.web.filter.OncePerRequestFilter;
    import tech.yump.vault.audit.AuditBackend; // Added
    import tech.yump.vault.audit.AuditEvent;   // Added
    import tech.yump.vault.config.MssmProperties;

    import java.io.IOException;
    import java.time.Instant; // Added
    import java.util.Collections;
    import java.util.List;
    import java.util.Map;     // Added
    import java.util.Optional;
    import java.util.UUID;    // Added

    @Slf4j
    public class StaticTokenAuthFilter extends OncePerRequestFilter {

        public static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
        public static final String REQUEST_ID_ATTR = "auditRequestId"; // Added

        private final boolean staticAuthEnabled;
        private final List<MssmProperties.AuthProperties.StaticTokenPolicyMapping> tokenMappings;
        private final List<String> publicPaths = List.of("/sys/seal-status", "/");
        private final AuditBackend auditBackend; // Added

        /**
         * Constructor receiving the static token properties and audit backend.
         * @param staticTokenProps The configured properties for static tokens.
         * @param auditBackend The audit backend implementation. // Added
         */
        public StaticTokenAuthFilter(
                MssmProperties.AuthProperties.StaticTokenAuthProperties staticTokenProps,
                AuditBackend auditBackend // Added
        ) {
            this.staticAuthEnabled = Optional.ofNullable(staticTokenProps)
                    .map(MssmProperties.AuthProperties.StaticTokenAuthProperties::enabled)
                    .orElse(false);

            this.tokenMappings = Optional.ofNullable(staticTokenProps)
                    .map(MssmProperties.AuthProperties.StaticTokenAuthProperties::mappings)
                    .orElse(Collections.emptyList());

            this.auditBackend = auditBackend; // Added

            log.debug("StaticTokenAuthFilter initialized. Enabled: {}, Mappings count: {}",
                    this.staticAuthEnabled, this.tokenMappings.size());
            if (this.staticAuthEnabled && this.tokenMappings.isEmpty()) {
                log.warn("Static token authentication is enabled but no token mappings are configured!");
            }
        }

        // ... (keep shouldNotFilter method) ...

        @Override
        protected void doFilterInternal(
                @NonNull HttpServletRequest request,
                @NonNull HttpServletResponse response,
                @NonNull FilterChain filterChain) throws ServletException, IOException {

            // Generate and store a unique request ID for auditing
            String requestId = UUID.randomUUID().toString();
            request.setAttribute(REQUEST_ID_ATTR, requestId); // Added

            if (!staticAuthEnabled) {
                log.trace("Static token authentication is disabled via configuration. Skipping filter.");
                filterChain.doFilter(request, response);
                return;
            }

            final String tokenHeader = request.getHeader(VAULT_TOKEN_HEADER);

            // If no token or already authenticated, proceed without logging an auth *attempt* here
            if (!StringUtils.hasText(tokenHeader) || SecurityContextHolder.getContext().getAuthentication() != null) {
                log.trace("No {} header found or authentication already present for {}. Proceeding.",
                        VAULT_TOKEN_HEADER, request.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }

            final String providedToken = tokenHeader.trim();
            Optional<MssmProperties.AuthProperties.StaticTokenPolicyMapping> mappingOptional = tokenMappings.stream()
                    .filter(mapping -> providedToken.equals(mapping.token()))
                    .findFirst();

            if (mappingOptional.isPresent()) {
                // --- Successful Authentication ---
                MssmProperties.AuthProperties.StaticTokenPolicyMapping mapping = mappingOptional.get();
                List<String> associatedPolicyNames = List.copyOf(mapping.policyNames());
                log.debug("Valid token found for request URI: {}. Associating policies: {}",
                        request.getRequestURI(), associatedPolicyNames);

                List<GrantedAuthority> authorities = associatedPolicyNames.stream()
                        .map(policyName -> (GrantedAuthority) new SimpleGrantedAuthority("POLICY_" + policyName))
                        .toList();

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        mapping.token(), // Principal is the token itself
                        null,            // No credentials needed here
                        authorities      // Authorities derived from policy names
                );
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("Successfully authenticated request using static token for URI: {}. Authorities: {}",
                        request.getRequestURI(), authorities);

                // --- Audit Log for Success ---
                logAuditEvent(
                        "auth",
                        "token_validation",
                        "success",
                        authentication, // Pass the created authentication object
                        request,
                        null, // No specific response info at this stage
                        Map.of("policies", associatedPolicyNames) // Add associated policies
                );

            } else {
                // --- Failed Authentication ---
                log.warn("Invalid or unknown static token received for URI: {}", request.getRequestURI());

                // --- Audit Log for Failure ---
                logAuditEvent(
                        "auth",
                        "token_validation",
                        "failure",
                        null, // No valid authentication object
                        request,
                        null, // No specific response info at this stage
                        Map.of("reason", "invalid_token") // Add failure reason
                );
                // Note: We still proceed down the filter chain. Spring Security's default
                // ExceptionTranslationFilter or our PolicyEnforcementFilter will likely deny access later.
            }

            filterChain.doFilter(request, response);
        }

        // --- Helper method to build and log AuditEvent ---
        private void logAuditEvent(String type, String action, String outcome, Authentication auth, HttpServletRequest request, AuditEvent.ResponseInfo responseInfo, Map<String, Object> data) {
            try {
                AuditEvent.AuthInfo.AuthInfoBuilder authInfoBuilder = AuditEvent.AuthInfo.builder()
                        .sourceAddress(request.getRemoteAddr());

                if (auth != null && auth.isAuthenticated()) {
                    authInfoBuilder.principal(auth.getName()); // Use token ID as principal
                    // Extract policy names from authorities if needed, or get from data map
                    List<String> policyNames = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .filter(a -> a.startsWith("POLICY_"))
                            .map(a -> a.substring("POLICY_".length()))
                            .toList();
                    if (!policyNames.isEmpty()) {
                         authInfoBuilder.metadata(Map.of("policies", policyNames));
                    }
                } else {
                     // Optionally add info about the failed attempt if needed, e.g., masked token prefix
                     // authInfoBuilder.principal("unknown");
                }


                AuditEvent.RequestInfo requestInfo = AuditEvent.RequestInfo.builder()
                        .requestId((String) request.getAttribute(REQUEST_ID_ATTR)) // Retrieve request ID
                        .httpMethod(request.getMethod())
                        .path(request.getRequestURI())
                        // Avoid logging sensitive headers. User-Agent might be useful.
                        .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
                        .build();

                AuditEvent event = AuditEvent.builder()
                        .timestamp(Instant.now())
                        .type(type)
                        .action(action)
                        .outcome(outcome)
                        .authInfo(authInfoBuilder.build())
                        .requestInfo(requestInfo)
                        .responseInfo(responseInfo) // Can be null
                        .data(data) // Additional context
                        .build();

                auditBackend.logEvent(event);

            } catch (Exception e) {
                log.error("Failed to log audit event in StaticTokenAuthFilter: {}", e.getMessage(), e);
            }
        }

        // --- Keep shouldNotFilter method ---
        @Override
        protected boolean shouldNotFilter(@NonNull HttpServletRequest request) throws ServletException {
            // ... (existing code) ...
             String path = request.getRequestURI();
             boolean isPublicPath = publicPaths.contains(path);

             if (!staticAuthEnabled) {
               log.trace("Skipping filter as static auth is disabled.");
               return true; // Skip if disabled
             }
             if (isPublicPath) {
               log.trace("Path {} is configured as public, skipping StaticTokenAuthFilter.", path);
               return true;
             }
             return false;
        }
    }
    

2.Modify PolicyEnforcementFilter:•Add AuditBackend to the constructor.•Store it as a final field.

    package tech.yump.vault.auth;

    import com.fasterxml.jackson.databind.ObjectMapper;
    import jakarta.servlet.FilterChain;
    import jakarta.servlet.ServletException;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import lombok.RequiredArgsConstructor;
    import lombok.extern.slf4j.Slf4j;
    import org.springframework.http.HttpStatus;
    import org.springframework.http.MediaType;
    import org.springframework.lang.NonNull;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.context.SecurityContextHolder;
    import org.springframework.web.filter.OncePerRequestFilter;
    import tech.yump.vault.api.ApiError;
    import tech.yump.vault.audit.AuditBackend; // Added
    import tech.yump.vault.audit.AuditEvent;   // Added
    import tech.yump.vault.auth.policy.PolicyCapability;
    import tech.yump.vault.auth.policy.PolicyDefinition;
    import tech.yump.vault.auth.policy.PolicyRepository;
    import tech.yump.vault.auth.policy.PolicyRule;

    import java.io.IOException;
    import java.time.Instant; // Added
    import java.util.List;
    import java.util.Map;     // Added
    import java.util.Optional;
    import java.util.Set;

    @Slf4j
    @RequiredArgsConstructor // Lombok will handle constructor injection
    public class PolicyEnforcementFilter extends OncePerRequestFilter {

        private final PolicyRepository policyRepository;
        private final AuditBackend auditBackend; // Added
        private final ObjectMapper objectMapper = new ObjectMapper();
        private static final String POLICY_AUTHORITY_PREFIX = "POLICY_";
        private static final String API_V1_PREFIX = "/v1/";

        @Override
        protected void doFilterInternal(
                @NonNull HttpServletRequest request,
                @NonNull HttpServletResponse response,
                @NonNull FilterChain filterChain) throws ServletException, IOException {

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
                log.trace("No authenticated user found for path {}. Proceeding in filter chain.", request.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }

            String requestPath = getRequestPathForPolicyCheck(request.getRequestURI());
            Optional<PolicyCapability> requiredCapabilityOpt = mapHttpMethodToCapability(request.getMethod());

            if (requestPath == null || requiredCapabilityOpt.isEmpty()) {
                log.warn("Could not determine request path relative to API root or required capability for {} {}. Denying access.",
                        request.getMethod(), request.getRequestURI());
                // Log audit denial for bad request structure
                sendForbiddenResponse(response, "Invalid request structure for policy evaluation.", request, authentication, null, null); // Pass nulls for capability/policies
                return;
            }

            PolicyCapability requiredCapability = requiredCapabilityOpt.get();
            List<String> policyNames = extractPolicyNames(authentication);

            if (policyNames.isEmpty()) {
                log.warn("Authenticated user '{}' has no associated policies. Denying access to {} {}",
                        authentication.getName(), request.getMethod(), request.getRequestURI());
                // Log audit denial for missing policies
                sendForbiddenResponse(response, "Access denied. No policies associated with token.", request, authentication, requiredCapability, policyNames);
                return;
            }

            List<PolicyDefinition> policies = policyRepository.findPoliciesByNames(policyNames);
            if (policies.isEmpty()) {
                log.error("Policy names {} associated with token '{}' not found in repository! Config mismatch. Denying access.",
                        policyNames, authentication.getName());
                // Log audit denial for config error
                sendForbiddenResponse(response, "Access denied. Policy configuration error.", request, authentication, requiredCapability, policyNames);
                return;
            }

            boolean granted = checkPolicies(policies, requestPath, requiredCapability);

            if (granted) {
                log.debug("Access GRANTED for user '{}' to {} {} (Path: {}, Capability: {}). Policies checked: {}",
                        authentication.getName(), request.getMethod(), request.getRequestURI(), requestPath, requiredCapability, policyNames);

                // --- Audit Log for Granted Access ---
                logAuditEvent(
                        "auth",
                        "policy_enforcement",
                        "granted",
                        authentication,
                        request,
                        null, // No response info yet
                        Map.of(
                                "checked_policies", policyNames,
                                "required_capability", requiredCapability.name(),
                                "request_path", requestPath
                        )
                );
                filterChain.doFilter(request, response); // Proceed

            } else {
                log.warn("Access DENIED for user '{}' to {} {} (Path: {}, Capability: {}). Policies checked: {}",
                        authentication.getName(), request.getMethod(), request.getRequestURI(), requestPath, requiredCapability, policyNames);
                // Log audit denial (handled within sendForbiddenResponse)
                sendForbiddenResponse(response, "Access denied by policy.", request, authentication, requiredCapability, policyNames);
            }
        }

        // --- Modified sendForbiddenResponse to include audit logging ---
        private void sendForbiddenResponse(
                HttpServletResponse response,
                String message,
                HttpServletRequest request, // Added
                Authentication authentication, // Added
                PolicyCapability requiredCapability, // Added (can be null)
                List<String> policyNames // Added (can be null)
        ) throws IOException {

            // --- Audit Log for Denied Access ---
            logAuditEvent(
                    "auth",
                    "policy_enforcement",
                    "denied",
                    authentication,
                    request,
                    AuditEvent.ResponseInfo.builder() // Add response info for denial
                            .statusCode(HttpStatus.FORBIDDEN.value())
                            .errorMessage(message)
                            .build(),
                    Map.of(
                            "checked_policies", Optional.ofNullable(policyNames).orElse(List.of("N/A")),
                            "required_capability", Optional.ofNullable(requiredCapability).map(Enum::name).orElse("N/A"),
                            "request_path", Optional.ofNullable(getRequestPathForPolicyCheck(request.getRequestURI())).orElse(request.getRequestURI())
                    )
            );

            // --- Original forbidden response logic ---
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            ApiError apiError = new ApiError(message);
            response.getWriter().write(objectMapper.writeValueAsString(apiError));
        }

        // --- Helper method to build and log AuditEvent (similar to StaticTokenAuthFilter) ---
        private void logAuditEvent(String type, String action, String outcome, Authentication auth, HttpServletRequest request, AuditEvent.ResponseInfo responseInfo, Map<String, Object> data) {
             try {
                 AuditEvent.AuthInfo.AuthInfoBuilder authInfoBuilder = AuditEvent.AuthInfo.builder()
                         .sourceAddress(request.getRemoteAddr());

                 if (auth != null && auth.isAuthenticated()) {
                     authInfoBuilder.principal(auth.getName());
                     List<String> policyNames = auth.getAuthorities().stream()
                             .map(GrantedAuthority::getAuthority)
                             .filter(a -> a.startsWith("POLICY_"))
                             .map(a -> a.substring("POLICY_".length()))
                             .toList();
                     if (!policyNames.isEmpty()) {
                          authInfoBuilder.metadata(Map.of("policies", policyNames));
                     }
                 } else {
                      authInfoBuilder.principal("unknown"); // Should not happen here if filter logic is correct
                 }

                 AuditEvent.RequestInfo requestInfo = AuditEvent.RequestInfo.builder()
                         .requestId((String) request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR)) // Retrieve request ID
                         .httpMethod(request.getMethod())
                         .path(request.getRequestURI())
                         .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
                         .build();

                 AuditEvent event = AuditEvent.builder()
                         .timestamp(Instant.now())
                         .type(type)
                         .action(action)
                         .outcome(outcome)
                         .authInfo(authInfoBuilder.build())
                         .requestInfo(requestInfo)
                         .responseInfo(responseInfo)
                         .data(data)
                         .build();

                 auditBackend.logEvent(event);

             } catch (Exception e) {
                 log.error("Failed to log audit event in PolicyEnforcementFilter: {}", e.getMessage(), e);
             }
         }


        // --- Keep other private methods (getRequestPathForPolicyCheck, mapHttpMethodToCapability, extractPolicyNames, checkPolicies, pathMatches, capabilitiesMatch) ---
        // --- Keep shouldNotFilter method ---
         private String getRequestPathForPolicyCheck(String uri) {
             if (uri == null || !uri.startsWith(API_V1_PREFIX)) {
                 return null;
             }
             return uri.substring(API_V1_PREFIX.length());
         }

         private Optional<PolicyCapability> mapHttpMethodToCapability(String method) {
             return switch (method.toUpperCase()) {
                 case "GET", "HEAD" -> Optional.of(PolicyCapability.READ);
                 case "PUT", "POST" -> Optional.of(PolicyCapability.WRITE);
                 case "DELETE" -> Optional.of(PolicyCapability.DELETE);
                 default -> {
                     log.trace("HTTP method {} does not map to a standard CRUD capability.", method);
                     yield Optional.empty();
                 }
             };
         }

         private List<String> extractPolicyNames(Authentication authentication) {
             return authentication.getAuthorities().stream()
                     .map(GrantedAuthority::getAuthority)
                     .filter(auth -> auth.startsWith(POLICY_AUTHORITY_PREFIX))
                     .map(auth -> auth.substring(POLICY_AUTHORITY_PREFIX.length()))
                     .toList();
         }

         private boolean checkPolicies(List<PolicyDefinition> policies, String requestPath, PolicyCapability requiredCapability) {
             for (PolicyDefinition policy : policies) {
                 for (PolicyRule rule : policy.rules()) {
                     if (pathMatches(rule.path(), requestPath) && capabilitiesMatch(rule.capabilities(), requiredCapability)) {
                         log.trace("Policy rule match found: Policy='{}', Rule Path='{}', Request Path='{}', Required Capability='{}', Rule Capabilities='{}'",
                                 policy.name(), rule.path(), requestPath, requiredCapability, rule.capabilities());
                         return true;
                     }
                 }
             }
             return false;
         }

         private boolean pathMatches(String policyPathPattern, String requestPath) {
             if (policyPathPattern.endsWith("/*")) {
                 String prefix = policyPathPattern.substring(0, policyPathPattern.length() - 1);
                 return requestPath.startsWith(prefix);
             } else {
                 return policyPathPattern.equals(requestPath);
             }
         }

         private boolean capabilitiesMatch(Set<PolicyCapability> grantedCapabilities, PolicyCapability requiredCapability) {
             return grantedCapabilities != null && grantedCapabilities.contains(requiredCapability);
         }

         @Override
         protected boolean shouldNotFilter(@NonNull HttpServletRequest request) throws ServletException {
             String path = request.getRequestURI();
             boolean isPublicPath = List.of("/sys/seal-status", "/").contains(path);
             if (isPublicPath) {
                  log.trace("Path {} is public, skipping PolicyEnforcementFilter.", path);
                  return true;
             }
             if (!path.startsWith(API_V1_PREFIX)) {
                 log.trace("Path {} is not under {}, skipping PolicyEnforcementFilter.", path, API_V1_PREFIX);
                 return true;
             }
             return false;
         }
    }
    

3.Modify KVController:•Add AuditBackend and HttpServletRequest to the constructor.•Store them as final fields.•Add audit logging calls in each endpoint method (for success) and in exception handlers (for failure).

    package tech.yump.vault.api.v1;

    import jakarta.servlet.http.HttpServletRequest; // Added
    import lombok.RequiredArgsConstructor;
    import lombok.extern.slf4j.Slf4j;
    import org.springframework.http.HttpStatus;
    import org.springframework.http.ResponseEntity;
    import org.springframework.security.core.Authentication; // Added
    import org.springframework.security.core.GrantedAuthority; // Added
    import org.springframework.security.core.context.SecurityContextHolder; // Added
    import org.springframework.web.bind.annotation.DeleteMapping;
    import org.springframework.web.bind.annotation.ExceptionHandler;
    import org.springframework.web.bind.annotation.GetMapping;
    import org.springframework.web.bind.annotation.PathVariable;
    import org.springframework.web.bind.annotation.PutMapping;
    import org.springframework.web.bind.annotation.RequestBody;
    import org.springframework.web.bind.annotation.RequestMapping;
    import org.springframework.web.bind.annotation.RestController;
    import tech.yump.vault.api.ApiError;
    import tech.yump.vault.audit.AuditBackend; // Added
    import tech.yump.vault.audit.AuditEvent;   // Added
    import tech.yump.vault.auth.StaticTokenAuthFilter; // Added for REQUEST_ID_ATTR
    import tech.yump.vault.core.VaultSealedException;
    import tech.yump.vault.secrets.kv.KVEngineException;
    import tech.yump.vault.secrets.kv.KVSecretEngine;

    import java.time.Instant; // Added
    import java.util.List;    // Added
    import java.util.Map;
    import java.util.Optional;

    @RestController
    @RequestMapping("/v1/kv/data")
    @Slf4j
    @RequiredArgsConstructor // Lombok handles constructor
    public class KVController {

        private final KVSecretEngine kvSecretEngine;
        private final AuditBackend auditBackend; // Added
        private final HttpServletRequest request; // Added (to get request-specific info like IP)

        @PutMapping("/{*path}")
        public ResponseEntity<?> writeSecret(
                @PathVariable String path,
                @RequestBody Map<String, String> secrets // DO NOT LOG THIS MAP
        ) {
            String sanitizedPath = sanitizePath(path);
            log.info("Received request to write secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
            kvSecretEngine.write(sanitizedPath, secrets);
            log.info("Successfully wrote secrets to path: {}", sanitizedPath);

            // --- Audit Log for Success ---
            logAuditEvent(
                    "kv_operation",
                    "write",
                    "success",
                    HttpStatus.NO_CONTENT.value(), // 204
                    null, // No error message
                    sanitizedPath
            );

            return ResponseEntity.noContent().build();
        }

        @GetMapping("/{*path}")
        public ResponseEntity<Map<String, String>> readSecret(
                @PathVariable String path
        ) {
            String sanitizedPath = sanitizePath(path);
            log.info("Received request to read secrets from raw path: {}, sanitized path: {}", path, sanitizedPath);
            Optional<Map<String, String>> secretsOptional = kvSecretEngine.read(sanitizedPath);

            if (secretsOptional.isPresent()) {
                log.info("Secrets found for path: {}", sanitizedPath);
                // --- Audit Log for Success ---
                logAuditEvent(
                        "kv_operation",
                        "read",
                        "success",
                        HttpStatus.OK.value(), // 200
                        null,
                        sanitizedPath
                );
                return ResponseEntity.ok(secretsOptional.get());
            } else {
                log.info("No secrets found for path: {}", sanitizedPath);
                // --- Audit Log for Not Found (still a 'successful' operation outcome in a way) ---
                 logAuditEvent(
                         "kv_operation",
                         "read",
                         "success", // Or maybe "not_found"? Let's stick with success for the operation itself.
                         HttpStatus.NOT_FOUND.value(), // 404
                         "Secret not found at path",
                         sanitizedPath
                 );
                return ResponseEntity.notFound().build();
            }
        }

        @DeleteMapping("/{*path}")
        public ResponseEntity<Void> deleteSecret(@PathVariable String path) {
            String sanitizedPath = sanitizePath(path);
            log.info("Received request to delete secrets at raw path: {}, sanitized path: {}", path, sanitizedPath);
            kvSecretEngine.delete(sanitizedPath);
            log.info("Successfully processed delete request for path: {}", sanitizedPath);

            // --- Audit Log for Success ---
            logAuditEvent(
                    "kv_operation",
                    "delete",
                    "success",
                    HttpStatus.NO_CONTENT.value(), // 204
                    null,
                    sanitizedPath
            );

            return ResponseEntity.noContent().build();
        }

        // --- Exception Handlers with Audit Logging ---

        @ExceptionHandler(KVEngineException.class)
        public ResponseEntity<ApiError> handleKVEngineException(KVEngineException ex, HttpServletRequest req) { // Added req
            String path = extractPathFromRequest(req); // Helper to get path if possible
            log.error("KV Engine error for path [{}]: {}", path, ex.getMessage(), ex);
            HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
            String message = "Internal server error processing KV request.";
            if (ex.getCause() instanceof VaultSealedException) {
                status = HttpStatus.SERVICE_UNAVAILABLE; // 503
                message = "Vault is sealed.";
            }

            // --- Audit Log for Failure ---
            logAuditEvent(
                    "kv_operation",
                    determineActionFromMethod(req.getMethod()), // Determine action from method
                    "failure",
                    status.value(),
                    message,
                    path
            );

            return ResponseEntity.status(status).body(new ApiError(message));
        }

        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<ApiError> handleIllegalArgumentException(IllegalArgumentException ex, HttpServletRequest req) { // Added req
            String path = extractPathFromRequest(req);
            log.warn("Bad request for path [{}]: {}", path, ex.getMessage());
            HttpStatus status = HttpStatus.BAD_REQUEST; // 400
            String message = "Bad request: " + ex.getMessage();

            // --- Audit Log for Failure ---
            logAuditEvent(
                    "kv_operation", // Or maybe "request_validation"?
                    determineActionFromMethod(req.getMethod()),
                    "failure",
                    status.value(),
                    message,
                    path
            );

            return ResponseEntity.status(status).body(new ApiError(message));
        }

        @ExceptionHandler(VaultSealedException.class)
        public ResponseEntity<ApiError> handleVaultSealedException(VaultSealedException ex, HttpServletRequest req) { // Added req
            String path = extractPathFromRequest(req);
            log.warn("Operation failed for path [{}]: Vault is sealed.", path);
            HttpStatus status = HttpStatus.SERVICE_UNAVAILABLE; // 503
            String message = "Vault is sealed.";

            // --- Audit Log for Failure ---
            logAuditEvent(
                    "kv_operation",
                    determineActionFromMethod(req.getMethod()),
                    "failure",
                    status.value(),
                    message,
                    path
            );

            return ResponseEntity.status(status).body(new ApiError(message));
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<ApiError> handleGenericException(Exception ex, HttpServletRequest req) { // Added req
            String path = extractPathFromRequest(req);
            log.error("An unexpected error occurred for path [{}]: {}", path, ex.getMessage(), ex);
            HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR; // 500
            String message = "An unexpected internal error occurred.";

            // --- Audit Log for Failure ---
            logAuditEvent(
                    "kv_operation", // Or "system_error"
                    determineActionFromMethod(req.getMethod()),
                    "failure",
                    status.value(),
                    message,
                    path
            );

            return ResponseEntity.status(status).body(new ApiError(message));
        }

        // --- Helper method to build and log AuditEvent ---
        private void logAuditEvent(String type, String action, String outcome, int statusCode, String errorMessage, String kvPath) {
            try {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                AuditEvent.AuthInfo.AuthInfoBuilder authInfoBuilder = AuditEvent.AuthInfo.builder()
                        .sourceAddress(request.getRemoteAddr());

                if (authentication != null && authentication.isAuthenticated()) {
                    authInfoBuilder.principal(authentication.getName());
                    List<String> policyNames = authentication.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .filter(a -> a.startsWith("POLICY_"))
                            .map(a -> a.substring("POLICY_".length()))
                            .toList();
                     if (!policyNames.isEmpty()) {
                          authInfoBuilder.metadata(Map.of("policies", policyNames));
                     }
                } else {
                    authInfoBuilder.principal("unknown"); // Should ideally not happen if security config is right
                }

                AuditEvent.RequestInfo requestInfo = AuditEvent.RequestInfo.builder()
                        .requestId((String) request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR))
                        .httpMethod(request.getMethod())
                        .path(request.getRequestURI()) // Full request URI
                        .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
                        .build();

                AuditEvent.ResponseInfo responseInfo = AuditEvent.ResponseInfo.builder()
                        .statusCode(statusCode)
                        .errorMessage(errorMessage) // Will be null for success cases
                        .build();

                // Add KV path to specific data map
                Map<String, Object> data = Map.of("kv_path", Optional.ofNullable(kvPath).orElse("N/A"));

                AuditEvent event = AuditEvent.builder()
                        .timestamp(Instant.now())
                        .type(type)
                        .action(action)
                        .outcome(outcome)
                        .authInfo(authInfoBuilder.build())
                        .requestInfo(requestInfo)
                        .responseInfo(responseInfo)
                        .data(data)
                        .build();

                auditBackend.logEvent(event);

            } catch (Exception e) {
                // Avoid letting audit failures break the main request flow
                log.error("Failed to log audit event in KVController: {}", e.getMessage(), e);
            }
        }

        // --- Helper to get path for logging in exception handlers ---
        private String extractPathFromRequest(HttpServletRequest req) {
            String uri = req.getRequestURI();
            String prefix = req.getContextPath() + "/v1/kv/data/";
            if (uri.startsWith(prefix)) {
                return sanitizePath(uri.substring(prefix.length()));
            }
            return uri; // Fallback to full URI if pattern doesn't match
        }

        // --- Helper to map HTTP method to action string ---
        private String determineActionFromMethod(String method) {
            return switch (method.toUpperCase()) {
                case "GET" -> "read";
                case "PUT", "POST" -> "write"; // Treat POST as write for KV
                case "DELETE" -> "delete";
                default -> "unknown";
            };
        }

        // --- Keep sanitizePath method ---
        private String sanitizePath(String rawPath) {
            if (rawPath != null && rawPath.startsWith("/")) {
                return rawPath.substring(1);
            }
            return rawPath;
        }
    }
    

Step 2: Update SecurityConfig to Inject AuditBackend into Filter BeansModify the bean definition methods for staticTokenAuthFilter and policyEnforcementFilter to accept and pass the AuditBackend.

package tech.yump.vault.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired; // Added
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tech.yump.vault.audit.AuditBackend; // Added
import tech.yump.vault.auth.PolicyEnforcementFilter;
import tech.yump.vault.auth.StaticTokenAuthFilter;
import tech.yump.vault.auth.policy.PolicyRepository;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor // Keeps constructor injection for final fields
@Slf4j
public class SecurityConfig {

    private final MssmProperties mssmProperties;
    private final PolicyRepository policyRepository;
    private final AuditBackend auditBackend; // Added: Inject AuditBackend

    @Bean
    public StaticTokenAuthFilter staticTokenAuthFilter() { // Removed AuditBackend from params, use injected field
        MssmProperties.AuthProperties authProps = mssmProperties.auth();
        MssmProperties.AuthProperties.StaticTokenAuthProperties staticTokenProps = (authProps != null) ? authProps.staticTokens() : null;

        MssmProperties.AuthProperties.StaticTokenAuthProperties effectiveProps;
        if (staticTokenProps != null && staticTokenProps.enabled()) {
            log.debug("Static token authentication enabled. Creating StaticTokenAuthFilter with configured properties.");
            effectiveProps = staticTokenProps;
        } else {
            log.debug("Static token authentication disabled. Creating dummy StaticTokenAuthFilter.");
            effectiveProps = new MssmProperties.AuthProperties.StaticTokenAuthProperties(false, Collections.emptyList());
        }
        // Pass the injected auditBackend to the filter constructor
        return new StaticTokenAuthFilter(effectiveProps, auditBackend); // Modified
    }

    @Bean
    public PolicyEnforcementFilter policyEnforcementFilter() { // Removed AuditBackend from params, use injected field
        log.debug("Creating PolicyEnforcementFilter.");
        // Pass the injected auditBackend to the filter constructor
        return new PolicyEnforcementFilter(policyRepository, auditBackend); // Modified
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // ... (rest of the method remains the same) ...
         http
                 .csrf(AbstractHttpConfigurer::disable)
                 .formLogin(AbstractHttpConfigurer::disable)
                 .logout(AbstractHttpConfigurer::disable)
                 .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

         MssmProperties.AuthProperties authProps = mssmProperties.auth();
         boolean staticAuthEnabled = authProps != null
                 && authProps.staticTokens() != null
                 && authProps.staticTokens().enabled();

         if (staticAuthEnabled) {
           log.info("Configuring Spring Security for Static Token Authentication and Policy Enforcement.");
           http
                   // 1. Add Static Token Authentication Filter
                   .addFilterBefore(staticTokenAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                   // 2. Add Policy Enforcement Filter *after* authentication
                   .addFilterAfter(policyEnforcementFilter(), StaticTokenAuthFilter.class)
                   .authorizeHttpRequests(authz -> authz
                           // Define public paths (these won't hit the policy filter due to shouldNotFilter)
                           .requestMatchers("/sys/seal-status", "/").permitAll()
                           // Require authentication for v1 API paths (ensures StaticTokenAuthFilter runs)
                           // The actual ALLOW/DENY decision for /v1/** is now made by PolicyEnforcementFilter
                           .requestMatchers("/v1/**").authenticated()
                           // Require authentication for any other request not explicitly permitted
                           // (e.g., future /v2/ or other management endpoints)
                           .anyRequest().authenticated()
                   );
         } else {
           log.warn("MSSM Static Token Authentication is disabled via configuration (mssm.auth.static-tokens.enabled=false). All API endpoints are accessible without authentication. THIS IS INSECURE FOR PRODUCTION.");
           http.authorizeHttpRequests(authz -> authz.anyRequest().permitAll());
         }

         return http.build();
    }
}

Step 3: Verify Logging1.Run the application.2.Use lite-vault-cli.sh or curl to perform various actions:•Access a protected endpoint (/v1/kv/data/...) with no token.•Access with an invalid token.•Access with a valid token that lacks permissions (expect 403).•Perform successful READ, WRITE, DELETE operations with a token that has permissions.•Attempt to read a non-existent secret (expect 404).3.Check the application logs. You should now see AUDIT_EVENT: {...} lines containing JSON payloads corresponding to the actions you performed, including authentication attempts, authorization decisions, and KV operations, along with relevant context like principal (token ID), source IP, request path, outcome, and status codes.Summary of Task 17:You have now successfully integrated the audit logging backend into the core API and security flow. Audit events are generated and logged (as JSON via SLF4j) for:•Static token authentication attempts (success/failure).•Policy enforcement decisions (granted/denied).•KV secret operations (read/write/delete success/failure/not found).This provides crucial visibility into security-relevant actions within the application (F-CORE-130). Remember that sensitive data (like secret values) is explicitly excluded from these logs.