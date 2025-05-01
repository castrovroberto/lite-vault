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
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.auth.policy.PolicyCapability;
import tech.yump.vault.auth.policy.PolicyDefinition;
import tech.yump.vault.auth.policy.PolicyRepository;
import tech.yump.vault.auth.policy.PolicyRule;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class PolicyEnforcementFilter extends OncePerRequestFilter {

    private final PolicyRepository policyRepository;
    private final AuditBackend auditBackend;
    private final ObjectMapper objectMapper;

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
        // Handle case where token policies don't exist in the repository
        if (policies.size() != policyNames.size()) {
            List<String> foundPolicyNames = policies.stream().map(PolicyDefinition::name).toList();
            List<String> missingPolicyNames = policyNames.stream().filter(name -> !foundPolicyNames.contains(name)).toList();
            log.error("Policy names {} associated with token '{}' not found in repository! Config mismatch. Denying access.",
                    missingPolicyNames, authentication.getName());
            // Log audit denial for config error
            sendForbiddenResponse(response, "Access denied. Policy configuration error.", request, authentication, requiredCapability, policyNames);
            return;
        }
        // Original check was just isEmpty, which is wrong if *some* but not *all* policies are found.
        // If we reach here, all requested policies were found.

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


    // ... (sendForbiddenResponse remains the same, but now uses the *injected* objectMapper) ...
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
        // Assuming ApiError has a constructor ApiError(String message) and includes a timestamp field
        ApiError apiError = new ApiError(message); // You might need to adjust how ApiError is created if it needs more args
        response.getWriter().write(objectMapper.writeValueAsString(apiError)); // Uses the INJECTED objectMapper
    }


    // ... (logAuditEvent remains the same) ...
    private void logAuditEvent(String type, String action, String outcome, Authentication auth, HttpServletRequest request, AuditEvent.ResponseInfo responseInfo, Map<String, Object> data) {
        try {
            AuditEvent.AuthInfo.AuthInfoBuilder authInfoBuilder = AuditEvent.AuthInfo.builder()
                    .sourceAddress(request.getRemoteAddr());

            if (auth != null && auth.isAuthenticated()) {
                authInfoBuilder.principal(auth.getName());
                List<String> policyNamesList = auth.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .filter(a -> a.startsWith("POLICY_"))
                        .map(a -> a.substring("POLICY_".length()))
                        .toList();
                if (!policyNamesList.isEmpty()) {
                    authInfoBuilder.metadata(Map.of("policies", policyNamesList));
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


    // ... (rest of the methods remain the same) ...
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

        // Define public paths that should bypass this filter entirely
        List<String> publicPaths = List.of(
                "/sys/seal-status",
                "/"
                // Add other truly public paths if needed
        );

        // Define path prefixes that should bypass this filter
        List<String> publicPrefixes = List.of(
                "/v1/jwt/jwks/", // <-- ADD THIS LINE
                "/actuator/"     // <-- Add actuator if it should also be skipped
        );

        if (publicPaths.contains(path) || publicPrefixes.stream().anyMatch(path::startsWith)) {
            log.trace("Path {} matches a public path/prefix, skipping PolicyEnforcementFilter.", path);
            return true;
        }

        // Original check for non-v1 paths (can keep or remove if covered by prefixes)
        if (!path.startsWith(API_V1_PREFIX)) {
            log.trace("Path {} is not under {}, skipping PolicyEnforcementFilter.", path, API_V1_PREFIX);
            return true;
        }

        // Otherwise, the filter should run
        return false;
    }
}
