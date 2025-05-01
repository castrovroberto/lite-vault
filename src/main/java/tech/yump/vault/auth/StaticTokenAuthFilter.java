package tech.yump.vault.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.config.MssmProperties;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
public class StaticTokenAuthFilter extends OncePerRequestFilter {

  public static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
  public static final String REQUEST_ID_ATTR = "auditRequestId";
  public static final String MDC_REQUEST_ID_KEY = "requestId";


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

  public static Authentication createAuthenticationToken(String token, List<String> policyNames) {
    if (token == null || policyNames == null) {
      log.error("Cannot create authentication token with null token or policy names.");
      // Or throw IllegalArgumentException
      return null;
    }
    // Convert policy names to GrantedAuthority objects, prefixed like in the filter
    List<GrantedAuthority> authorities = policyNames.stream()
            .map(policyName -> (GrantedAuthority) new SimpleGrantedAuthority("POLICY_" + policyName))
            .collect(Collectors.toList()); // Use Collectors.toList() for compatibility

    // Create the same type of Authentication token as the filter does
    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
            token,      // Principal is the token itself
            null,       // No credentials needed/used here
            authorities // Authorities derived from policy names
    );
    // Note: We don't set details (like WebAuthenticationDetails) here,
    // as it's generally not needed for policy enforcement tests.
    log.debug("Created mock Authentication for token '{}' with authorities: {}", token, authorities);
    return authentication;
  }

  @Override
  protected void doFilterInternal(
          @NonNull HttpServletRequest request,
          @NonNull HttpServletResponse response,
          @NonNull FilterChain filterChain) throws ServletException, IOException {

    String requestId = UUID.randomUUID().toString();
    request.setAttribute(REQUEST_ID_ATTR, requestId);

     MDC.put(MDC_REQUEST_ID_KEY, requestId);

     try {
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
     } finally {
       MDC.remove(MDC_REQUEST_ID_KEY);
     }
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
