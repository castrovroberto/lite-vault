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