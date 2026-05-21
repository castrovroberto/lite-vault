package tech.yump.vault.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.auth.approle.AppRoleService;
import tech.yump.vault.core.VaultSealedException;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
public class AppRoleAuthFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final List<String> PUBLIC_PATHS = List.of("/sys/seal-status", "/", "/v1/auth/approle/login");
    private static final List<String> PUBLIC_PREFIXES = List.of("/v1/jwt/jwks/", "/actuator/");

    private final AppRoleService appRoleService;
    private final AuditBackend auditBackend;

    public AppRoleAuthFilter(AppRoleService appRoleService, AuditBackend auditBackend) {
        this.appRoleService = appRoleService;
        this.auditBackend = auditBackend;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(BEARER_PREFIX.length()).trim();

        try {
            Claims claims = appRoleService.validateToken(jwt);

            @SuppressWarnings("unchecked")
            List<String> policies = (List<String>) claims.get("policies", List.class);

            List<GrantedAuthority> authorities = policies == null ? List.of() :
                    policies.stream()
                            .map(p -> (GrantedAuthority) new SimpleGrantedAuthority("POLICY_" + p))
                            .toList();

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    claims.getSubject(), null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("AppRole JWT authenticated for subject '{}', policies: {}", claims.getSubject(), policies);
            logAuditEvent("approle_operation", "token_validation", "success", claims.getSubject(), request, null);

        } catch (VaultSealedException e) {
            log.error("AppRole JWT validation skipped — vault is sealed.");
            logAuditEvent("approle_operation", "token_validation", "failure", null, request,
                    Map.of("reason", "vault_sealed"));
        } catch (JwtException e) {
            log.warn("Invalid AppRole JWT for {}: {}", request.getRequestURI(), e.getMessage());
            logAuditEvent("approle_operation", "token_validation", "failure", null, request,
                    Map.of("reason", e.getClass().getSimpleName()));
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return PUBLIC_PATHS.contains(path) || PUBLIC_PREFIXES.stream().anyMatch(path::startsWith);
    }

    private void logAuditEvent(String type, String action, String outcome, String principal,
                                HttpServletRequest request, Map<String, Object> data) {
        try {
            AuditEvent.AuthInfo authInfo = AuditEvent.AuthInfo.builder()
                    .principal(principal)
                    .sourceAddress(request.getRemoteAddr())
                    .build();

            AuditEvent.RequestInfo requestInfo = AuditEvent.RequestInfo.builder()
                    .requestId((String) request.getAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR))
                    .httpMethod(request.getMethod())
                    .path(request.getRequestURI())
                    .headers(Map.of("User-Agent", Optional.ofNullable(request.getHeader("User-Agent")).orElse("N/A")))
                    .build();

            AuditEvent event = AuditEvent.builder()
                    .timestamp(Instant.now())
                    .type(type)
                    .action(action)
                    .outcome(outcome)
                    .authInfo(authInfo)
                    .requestInfo(requestInfo)
                    .data(data)
                    .build();

            auditBackend.logEvent(event);
        } catch (Exception e) {
            log.error("Failed to log audit event in AppRoleAuthFilter: {}", e.getMessage(), e);
        }
    }
}
