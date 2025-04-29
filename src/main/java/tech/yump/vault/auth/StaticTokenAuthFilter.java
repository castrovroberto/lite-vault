package tech.yump.vault.auth;

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
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tech.yump.vault.config.MssmProperties;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Slf4j
public class StaticTokenAuthFilter extends OncePerRequestFilter {

  public static final String VAULT_TOKEN_HEADER = "X-Vault-Token";

  private final boolean staticAuthEnabled;
  private final List<MssmProperties.AuthProperties.StaticTokenPolicyMapping> tokenMappings;
  private final List<String> publicPaths = List.of("/sys/seal-status", "/");

  /**
   * Constructor receiving the static token properties.
   * @param staticTokenProps The configured properties for static tokens.
   */
  public StaticTokenAuthFilter(MssmProperties.AuthProperties.StaticTokenAuthProperties staticTokenProps) {
    this.staticAuthEnabled = Optional.ofNullable(staticTokenProps)
            .map(MssmProperties.AuthProperties.StaticTokenAuthProperties::enabled)
            .orElse(false);

    this.tokenMappings = Optional.ofNullable(staticTokenProps)
            .map(MssmProperties.AuthProperties.StaticTokenAuthProperties::mappings)
            .orElse(Collections.emptyList());

    log.debug("StaticTokenAuthFilter initialized. Enabled: {}, Mappings count: {}",
            this.staticAuthEnabled, this.tokenMappings.size());
    if (this.staticAuthEnabled && this.tokenMappings.isEmpty()) {
      log.warn("Static token authentication is enabled but no token mappings are configured!");
    }
  }


  @Override
  protected void doFilterInternal(
          @NonNull HttpServletRequest request,
          @NonNull HttpServletResponse response,
          @NonNull FilterChain filterChain) throws ServletException, IOException {
    if (!staticAuthEnabled) {
      log.trace("Static token authentication is disabled via configuration. Skipping filter.");
      filterChain.doFilter(request, response);
      return;
    }
    final String tokenHeader = request.getHeader(VAULT_TOKEN_HEADER);
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

    } else {
      log.warn("Invalid or unknown static token received for URI: {}", request.getRequestURI());
    }
    filterChain.doFilter(request, response);
  }

  /**
   * Optimization: Determines if the filter should be skipped for a given request.
   * Skips if static auth is disabled OR if the path is public.
   */
  @Override
  protected boolean shouldNotFilter(@NonNull HttpServletRequest request) throws ServletException {
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