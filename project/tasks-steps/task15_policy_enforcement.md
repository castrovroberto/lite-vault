# Task 15: Basic ACL Enforcement

Okay, let's implement Task 15: Basic ACL Enforcement.We'll create a new Spring Security filter (PolicyEnforcementFilter) that runs after the StaticTokenAuthFilter. This filter will:1.Check if the user is authenticated.2.Retrieve the policy names associated with the authenticated token (from the GrantedAuthority objects set by StaticTokenAuthFilter).3.Load the actual PolicyDefinitions corresponding to those names.4.Determine the required PolicyCapability based on the HTTP method.5.Extract the relevant path from the request URI.6.Check if any rule within the user's policies grants the required capability for the requested path.7.If allowed, proceed down the filter chain.8.If denied, return a 403 Forbidden response.Step 1: Create a Policy RepositoryThis component will hold the configured policies for easy lookup by name.

package tech.yump.vault.auth.policy;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tech.yump.vault.config.MssmProperties;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class PolicyRepository {

    private final MssmProperties mssmProperties;
    private Map<String, PolicyDefinition> policyMap = Collections.emptyMap();

    @PostConstruct
    void initialize() {
        List<PolicyDefinition> configuredPolicies = Optional.ofNullable(mssmProperties.policies())
                .orElse(Collections.emptyList());

        if (configuredPolicies.isEmpty()) {
            log.warn("No policies defined in configuration (mssm.policies). ACL enforcement will deny access unless policies are added.");
        } else {
            this.policyMap = configuredPolicies.stream()
                    .collect(Collectors.toMap(PolicyDefinition::name, Function.identity(), (existing, replacement) -> {
                        // Handle duplicate policy names if they somehow bypass validation
                        log.warn("Duplicate policy name found in configuration: '{}'. Using the first occurrence.", existing.name());
                        return existing;
                    }));
            log.info("Loaded {} policies from configuration.", this.policyMap.size());
            log.debug("Loaded policy names: {}", this.policyMap.keySet());
        }
    }

    public Optional<PolicyDefinition> findPolicyByName(String name) {
        return Optional.ofNullable(policyMap.get(name));
    }

    public List<PolicyDefinition> findPoliciesByNames(List<String> names) {
        if (names == null || names.isEmpty()) {
            return Collections.emptyList();
        }
        return names.stream()
                .map(this::findPolicyByName)
                .flatMap(Optional::stream) // Filter out Optional.empty() and unwrap present ones
                .toList();
    }
}

Step 2: Create the Policy Enforcement FilterThis filter performs the core authorization logic.

package tech.yump.vault.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.auth.policy.PolicyCapability;
import tech.yump.vault.auth.policy.PolicyDefinition;
import tech.yump.vault.auth.policy.PolicyRepository;
import tech.yump.vault.auth.policy.PolicyRule;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class PolicyEnforcementFilter extends OncePerRequestFilter {

    private final PolicyRepository policyRepository;
    private final ObjectMapper objectMapper = new ObjectMapper(); // For writing JSON error response
    private static final String POLICY_AUTHORITY_PREFIX = "POLICY_";
    private static final String API_V1_PREFIX = "/v1/";

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // If not authenticated (or anonymous), let Spring Security's default handling (or later filters) deny access
        // Or if the path is public (already handled by shouldNotFilter in StaticTokenAuthFilter and SecurityConfig)
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            log.trace("No authenticated user found for path {}. Proceeding in filter chain (expecting denial later or public access).", request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        String requestPath = getRequestPathForPolicyCheck(request.getRequestURI());
        Optional<PolicyCapability> requiredCapabilityOpt = mapHttpMethodToCapability(request.getMethod());

        if (requestPath == null || requiredCapabilityOpt.isEmpty()) {
            // Should not happen for standard requests handled by controllers, but good practice
            log.warn("Could not determine request path relative to API root or required capability for {} {}. Denying access.",
                    request.getMethod(), request.getRequestURI());
            sendForbiddenResponse(response, "Invalid request structure for policy evaluation.");
            return;
        }

        PolicyCapability requiredCapability = requiredCapabilityOpt.get();
        List<String> policyNames = extractPolicyNames(authentication);

        if (policyNames.isEmpty()) {
            log.warn("Authenticated user '{}' has no associated policies. Denying access to {} {}",
                    authentication.getName(), request.getMethod(), request.getRequestURI());
            sendForbiddenResponse(response, "Access denied. No policies associated with token.");
            return;
        }

        List<PolicyDefinition> policies = policyRepository.findPoliciesByNames(policyNames);
        if (policies.isEmpty()) {
            log.error("Policy names {} associated with token '{}' not found in repository! This indicates a configuration mismatch. Denying access.",
                    policyNames, authentication.getName());
            sendForbiddenResponse(response, "Access denied. Policy configuration error.");
            return;
        }

        boolean granted = checkPolicies(policies, requestPath, requiredCapability);

        if (granted) {
            log.debug("Access granted for user '{}' to {} {} (Path: {}, Capability: {}). Policies checked: {}",
                    authentication.getName(), request.getMethod(), request.getRequestURI(), requestPath, requiredCapability, policyNames);
            filterChain.doFilter(request, response);
        } else {
            log.warn("Access DENIED for user '{}' to {} {} (Path: {}, Capability: {}). Policies checked: {}",
                    authentication.getName(), request.getMethod(), request.getRequestURI(), requestPath, requiredCapability, policyNames);
            sendForbiddenResponse(response, "Access denied by policy.");
        }
    }

    private String getRequestPathForPolicyCheck(String uri) {
        if (uri == null || !uri.startsWith(API_V1_PREFIX)) {
            return null; // Not an API path we are enforcing policies on here
        }
        // Return the path *after* /v1/ e.g., "kv/data/myapp/config"
        return uri.substring(API_V1_PREFIX.length());
    }


    private Optional<PolicyCapability> mapHttpMethodToCapability(String method) {
        return switch (method.toUpperCase()) {
            case "GET", "HEAD" -> Optional.of(PolicyCapability.READ);
            // Treat POST same as PUT for KV write operations
            case "PUT", "POST" -> Optional.of(PolicyCapability.WRITE);
            case "DELETE" -> Optional.of(PolicyCapability.DELETE);
            // LIST capability might be used for future endpoints (e.g., listing keys)
            // case "OPTIONS" -> Optional.of(PolicyCapability.LIST); // Example if needed
            default -> {
                log.trace("HTTP method {} does not map to a standard CRUD capability.", method);
                yield Optional.empty(); // Or handle as needed, e.g., deny by default
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
                    return true; // Access granted by this rule
                }
            }
        }
        return false; // No matching rule found in any policy
    }

    /**
     * Basic path matching. Supports exact match or suffix wildcard ('*').
     * Example: "kv/data/app1/*" matches "kv/data/app1/db" and "kv/data/app1/"
     * Example: "kv/data/app1/config" matches only "kv/data/app1/config"
     */
    private boolean pathMatches(String policyPathPattern, String requestPath) {
        if (policyPathPattern.endsWith("/*")) {
            String prefix = policyPathPattern.substring(0, policyPathPattern.length() - 1); // Keep the trailing '/' if it was '/*'
             // Ensure requestPath starts with the prefix. Handles "kv/data/app1/" matching "kv/data/app1/db"
            return requestPath.startsWith(prefix);
        } else {
            // Exact match required
            return policyPathPattern.equals(requestPath);
        }
    }

    private boolean capabilitiesMatch(Set<PolicyCapability> grantedCapabilities, PolicyCapability requiredCapability) {
        return grantedCapabilities != null && grantedCapabilities.contains(requiredCapability);
    }

    private void sendForbiddenResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        ApiError apiError = new ApiError(message);
        response.getWriter().write(objectMapper.writeValueAsString(apiError));
    }

    /**
     * Optimization: Skip this filter for public paths already permitted in SecurityConfig.
     * Also skip if static auth itself is disabled (though SecurityConfig might permit all anyway).
     */
    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        // Match public paths defined in SecurityConfig
        boolean isPublicPath = List.of("/sys/seal-status", "/").contains(path);
        // If it's a public path, skip policy enforcement
        if (isPublicPath) {
             log.trace("Path {} is public, skipping PolicyEnforcementFilter.", path);
             return true;
        }
        // If the request is not for the v1 API, skip this filter
        if (!path.startsWith(API_V1_PREFIX)) {
            log.trace("Path {} is not under {}, skipping PolicyEnforcementFilter.", path, API_V1_PREFIX);
            return true;
        }

        // Otherwise, this filter should run for authenticated v1 requests
        return false;
    }
}

Step 3: Update Security ConfigurationInject the PolicyRepository and add the PolicyEnforcementFilter to the chain after the StaticTokenAuthFilter.

package tech.yump.vault.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tech.yump.vault.auth.PolicyEnforcementFilter; // Import the new filter
import tech.yump.vault.auth.StaticTokenAuthFilter;
import tech.yump.vault.auth.policy.PolicyRepository; // Import the repository

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final MssmProperties mssmProperties;
    private final PolicyRepository policyRepository; // Inject the repository

    @Bean
    public StaticTokenAuthFilter staticTokenAuthFilter() {
        MssmProperties.AuthProperties authProps = mssmProperties.auth();
        MssmProperties.AuthProperties.StaticTokenAuthProperties staticTokenProps = (authProps != null) ? authProps.staticTokens() : null;

        if (staticTokenProps != null && staticTokenProps.enabled()) {
            log.debug("Static token authentication enabled. Creating StaticTokenAuthFilter with configured properties.");
            return new StaticTokenAuthFilter(staticTokenProps);
        } else {
            log.debug("Static token authentication disabled. Creating dummy StaticTokenAuthFilter.");
            return new StaticTokenAuthFilter(
                    new MssmProperties.AuthProperties.StaticTokenAuthProperties(false, Collections.emptyList())
            );
        }
    }

    // Bean for the new Policy Enforcement Filter
    @Bean
    public PolicyEnforcementFilter policyEnforcementFilter() {
        log.debug("Creating PolicyEnforcementFilter.");
        return new PolicyEnforcementFilter(policyRepository);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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

Step 4: Update application-dev.yml (Example)Make sure you have policies defined and tokens mapped to them (Task 18 is closely related, but we need an example now).

# src/main/resources/application-dev.yml (or application.yml)

mssm:
  master:
    b64: "YOUR_BASE64_ENCODED_MASTER_KEY_HERE" # Replace with actual key
  storage:
    filesystem:
      path: "./mssm-data-dev"
  auth:
    static-tokens:
      enabled: true # Enable authentication
      mappings:
        - token: "dev-root-token" # A token with broad access
          policy-names: ["root-policy"]
        - token: "app1-read-token" # A token with read-only access to app1 secrets
          policy-names: ["app1-read-only"]
        - token: "app1-write-token" # A token with read/write access to app1 secrets
          policy-names: ["app1-read-only", "app1-write"] # Combine policies
        - token: "no-access-token" # A token associated with no valid policies (or policies granting nothing)
          policy-names: ["non-existent-policy"]

  # Define the actual policies
  policies:
    - name: "root-policy"
      rules:
        - path: "kv/data/*" # Access to everything under kv/data/
          capabilities: [READ, WRITE, DELETE, LIST] # Full capabilities
    - name: "app1-read-only"
      rules:
        - path: "kv/data/app1/*" # Read access only under kv/data/app1/
          capabilities: [READ]
    - name: "app1-write"
      rules:
        - path: "kv/data/app1/*" # Write access under kv/data/app1/
          capabilities: [WRITE, DELETE] # Grant write and delete

# Logging levels for debugging
logging:
  level:
    tech.yump.vault.auth: DEBUG # Enable DEBUG for auth components
    tech.yump.vault.config: DEBUG
    # org.springframework.security: TRACE # Very verbose, use if needed


Summary of Changes:1.PolicyRepository: Created to load and provide access to PolicyDefinition objects from configuration.2.PolicyEnforcementFilter: Created to perform the core authorization logic: check authentication, map HTTP method/path, consult user's policies via PolicyRepository, and allow/deny access (403).3.SecurityConfig: Updated to inject PolicyRepository, create a bean for PolicyEnforcementFilter, and add it to the filter chain after StaticTokenAuthFilter.4.application-dev.yml: Updated with example policies and token-to-policy mappings.Now, when a request hits /v1/**:1.StaticTokenAuthFilter authenticates the token and adds POLICY_xxx authorities.2.PolicyEnforcementFilter extracts these policy names, gets the rules from PolicyRepository, checks the request path/method against the rules, and either allows the request to proceed to the KVController or returns a 403 Forbidden response.