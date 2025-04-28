package tech.yump.vault.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.yump.vault.config.MssmProperties;

@RequiredArgsConstructor
@Slf4j
public class StaticTokenAuthFilter extends OncePerRequestFilter {

  public static final String VAULT_TOKEN_HEADER = "X-Vault-Token";
  private static final String TOKEN_PRINCIPAL_PREFIX = "token-";

  // Injected via constructor thanks to @RequiredArgsConstructor
  private final MssmProperties.AuthProperties.StaticTokenAuthProperties tokenProperties;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {

    // Only apply filter logic if static token auth is enabled in config
    // Use record accessor method: enabled()
    if (!tokenProperties.enabled()) {
      log.trace("Static token authentication is disabled via configuration. Skipping filter.");
      filterChain.doFilter(request, response);
      return;
    }

    final String tokenHeader = request.getHeader(VAULT_TOKEN_HEADER);

    // If no token or context already has authentication, proceed without setting auth
    if (!StringUtils.hasText(tokenHeader) || SecurityContextHolder.getContext().getAuthentication() != null) {
      log.trace("No {} header found or authentication already present. Proceeding.", VAULT_TOKEN_HEADER);
      filterChain.doFilter(request, response);
      return;
    }

    final String token = tokenHeader.trim();
    // Use record accessor method: tokens()
    final Set<String> validTokens = tokenProperties.tokens();

    // Check if the provided token is in the configured set
    if (validTokens != null && validTokens.contains(token)) {
      log.debug("Valid static token found for request URI: {}", request.getRequestURI());

      // Create Authentication object
      // Principal is a derived identifier based on the token
      // Authorities list contains a basic role indicating token authentication
      UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
          TOKEN_PRINCIPAL_PREFIX + token, // e.g., "token-dev-root-token"
          null, // Credentials are not needed after token validation
          Collections.singletonList(new SimpleGrantedAuthority("ROLE_TOKEN_AUTH")) // Basic role
      );

      // Set details (like remote address, session ID if any) from the request
      authentication.setDetails(
          new WebAuthenticationDetailsSource().buildDetails(request)
      );

      // Set the Authentication object in the SecurityContext
      SecurityContextHolder.getContext().setAuthentication(authentication);
      log.info("Successfully authenticated request using static token for URI: {}", request.getRequestURI());

    } else {
      // Token was provided but it's not in the valid set
      log.warn("Invalid or unknown static token received for URI: {}", request.getRequestURI());
      // Do NOT set authentication. Spring Security's ExceptionTranslationFilter
      // will handle the lack of authentication for protected resources later,
      // typically resulting in a 401 Unauthorized or 403 Forbidden response.
    }

    // Proceed down the filter chain regardless of authentication success/failure here
    // Authorization checks happen later in the chain based on the SecurityContext
    filterChain.doFilter(request, response);
  }

  /**
   * Optimization: Determines if the filter should be skipped for a given request.
   * This is useful for paths that are explicitly configured as public (permitAll)
   * in the SecurityConfig, avoiding unnecessary header checks.
   *
   * @param request The current request.
   * @return true if the filter should NOT be applied, false otherwise.
   * @throws ServletException If an error occurs.
   */
  @Override
  protected boolean shouldNotFilter(@NonNull HttpServletRequest request) throws ServletException {
    String path = request.getRequestURI();
    // Check against paths known to be public (configured in SecurityConfig)
    // This should align with the .permitAll() configurations.
    boolean isPublicPath = path.equals("/sys/seal-status") || path.equals("/");
    // Add other public paths like /actuator/health if applicable

    if (isPublicPath) {
      log.trace("Path {} is configured as public, skipping StaticTokenAuthFilter.", path);
    }
    return isPublicPath;
  }
}