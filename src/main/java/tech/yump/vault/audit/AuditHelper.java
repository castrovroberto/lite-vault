package tech.yump.vault.audit;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tech.yump.vault.auth.StaticTokenAuthFilter;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuditHelper {

    private final AuditBackend auditBackend;

    /**
     * Logs an audit event related to an HTTP request outcome (success or failure).
     * Automatically gathers authentication and request context if available.
     *
     * @param type         The type of event (e.g., "kv_operation", "db_operation").
     * @param action       The specific action performed (e.g., "read", "generate_credentials").
     * @param outcome      The result ("success" or "failure").
     * @param statusCode   The HTTP status code associated with the outcome.
     * @param errorMessage Optional error message (for failures).
     * @param data         Optional map containing context-specific data.
     */
    public void logHttpEvent(
            String type,
            String action,
            String outcome,
            int statusCode,
            @Nullable String errorMessage,
            @Nullable Map<String, Object> data) {

        HttpServletRequest request = getCurrentHttpRequest();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        AuditEvent.AuthInfo authInfo = buildAuthInfo(authentication, request);
        AuditEvent.RequestInfo requestInfo = buildRequestInfo(request);
        AuditEvent.ResponseInfo responseInfo = buildResponseInfo(statusCode, errorMessage);

        logEventInternal(type, action, outcome, authInfo, requestInfo, responseInfo, data);
    }

    /**
     * Logs an audit event originating from internal processes (not directly tied to an HTTP request/response cycle).
     * Authentication context is still attempted via SecurityContextHolder if available (e.g., triggered by an authenticated request).
     *
     * @param type      The type of event (e.g., "db_operation", "system").
     * @param action    The specific action performed (e.g., "lease_creation", "revoke_lease").
     * @param outcome   The result ("success" or "failure").
     * @param principal Optional principal identifier if known (falls back to SecurityContext or "system").
     * @param data      Optional map containing context-specific data.
     */
    public void logInternalEvent(
            String type,
            String action,
            String outcome,
            @Nullable String principal,
            @Nullable Map<String, Object> data) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String effectivePrincipal = Optional.ofNullable(principal)
                .orElseGet(() -> (authentication != null && authentication.isAuthenticated()) ? authentication.getName() : "system");

        // Build AuthInfo without relying on HttpServletRequest
        AuditEvent.AuthInfo.AuthInfoBuilder authInfoBuilder = AuditEvent.AuthInfo.builder()
                .principal(effectivePrincipal);
        if (authentication != null && authentication.isAuthenticated()) {
            extractAndAddPolicies(authentication, authInfoBuilder);
        }
        AuditEvent.AuthInfo authInfo = authInfoBuilder.build();

        // RequestInfo and ResponseInfo are null for internal events
        logEventInternal(type, action, outcome, authInfo, null, null, data);
    }


    // --- Internal Helper Methods ---

    private void logEventInternal(
            String type,
            String action,
            String outcome,
            @Nullable AuditEvent.AuthInfo authInfo,
            @Nullable AuditEvent.RequestInfo requestInfo,
            @Nullable AuditEvent.ResponseInfo responseInfo,
            @Nullable Map<String, Object> data) {
        try {
            AuditEvent auditEvent = AuditEvent.builder()
                    .timestamp(Instant.now())
                    .type(type)
                    .action(action)
                    .outcome(outcome)
                    .authInfo(authInfo)
                    .requestInfo(requestInfo)
                    .responseInfo(responseInfo)
                    .data(data != null && !data.isEmpty() ? data : null) // Ensure null if empty
                    .build();

            auditBackend.logEvent(auditEvent);

        } catch (Exception e) {
            log.error("Failed to log audit event in AuditHelper: Type={}, Action={}, Outcome={}, Error={}",
                    type, action, outcome, e.getMessage(), e);
        }
    }

    @Nullable
    private HttpServletRequest getCurrentHttpRequest() {
        return Optional.ofNullable(RequestContextHolder.getRequestAttributes())
                .filter(ServletRequestAttributes.class::isInstance)
                .map(ServletRequestAttributes.class::cast)
                .map(ServletRequestAttributes::getRequest)
                .orElse(null);
    }

    private AuditEvent.AuthInfo buildAuthInfo(@Nullable Authentication authentication, @Nullable HttpServletRequest request) {
        AuditEvent.AuthInfo.AuthInfoBuilder builder = AuditEvent.AuthInfo.builder();

        // Source Address (from request if available)
        if (request != null) {
            builder.sourceAddress(request.getRemoteAddr());
        } else {
            builder.sourceAddress("unknown"); // Or null? Let's use unknown for clarity
        }

        // Principal and Policies (from Authentication if available)
        if (authentication != null && authentication.isAuthenticated() && !"anonymousUser".equals(authentication.getPrincipal())) {
            builder.principal(authentication.getName());
            extractAndAddPolicies(authentication, builder);
        } else {
            builder.principal("anonymous"); // Default if no auth or anonymous
        }

        return builder.build();
    }

    private void extractAndAddPolicies(Authentication authentication, AuditEvent.AuthInfo.AuthInfoBuilder builder) {
        List<String> policyNames = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("POLICY_"))
                .map(a -> a.substring("POLICY_".length()))
                .toList();
        if (!policyNames.isEmpty()) {
            builder.metadata(Map.of("policies", policyNames));
        }
    }

    @Nullable
    private AuditEvent.RequestInfo buildRequestInfo(@Nullable HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        return AuditEvent.RequestInfo.builder()
                .requestId((String) request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR))
                .httpMethod(request.getMethod())
                .path(request.getRequestURI())
                .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
                .build();
    }

    private AuditEvent.ResponseInfo buildResponseInfo(int statusCode, @Nullable String errorMessage) {
        return AuditEvent.ResponseInfo.builder()
                .statusCode(statusCode)
                .errorMessage(errorMessage) // Will be null if errorMessage is null
                .build();
    }
}