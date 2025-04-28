package tech.yump.vault.config;

import java.util.Collections; // Import Collections
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger; // Import Logger
import org.slf4j.LoggerFactory; // Import LoggerFactory
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tech.yump.vault.auth.StaticTokenAuthFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  // Use SLF4j Logger
  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

  private final MssmProperties mssmProperties;

  @Bean
  public StaticTokenAuthFilter staticTokenAuthFilter() {
    MssmProperties.AuthProperties authProps = mssmProperties.auth();
    // Check if static token auth is actually enabled using record accessors
    if (authProps != null && authProps.staticTokens() != null && authProps.staticTokens().enabled()) {
      log.debug("Static token authentication enabled. Creating StaticTokenAuthFilter with configured properties.");
      // Pass the correctly populated properties record
      return new StaticTokenAuthFilter(authProps.staticTokens());
    } else {
      log.debug("Static token authentication disabled. Creating dummy StaticTokenAuthFilter.");
      // Return a non-functional filter to avoid null issues in the filter chain setup.
      // **FIX:** Call the canonical constructor with default values for the record.
      return new StaticTokenAuthFilter(
          new MssmProperties.AuthProperties.StaticTokenAuthProperties(false, Collections.emptySet())
      );
    }
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        // Disable CSRF as we are using token-based auth for a stateless API
        .csrf(AbstractHttpConfigurer::disable)

        // Disable default form login and logout pages
        .formLogin(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)

        // Ensure stateless session management
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    // Conditionally add the filter and configure authorization rules
    // **FIX:** Use record accessor methods and add null checks for safety
    MssmProperties.AuthProperties authProps = mssmProperties.auth();
    boolean staticAuthEnabled = authProps != null && authProps.staticTokens() != null && authProps.staticTokens().enabled();

    if (staticAuthEnabled) {
      log.info("Configuring Spring Security for Static Token Authentication.");
      http
          // Add our custom token filter before the standard auth filters
          // The staticTokenAuthFilter() bean method handles creating the correct instance
          .addFilterBefore(staticTokenAuthFilter(), UsernamePasswordAuthenticationFilter.class)

          // Define authorization rules
          .authorizeHttpRequests(authz -> authz
              // Allow unauthenticated access to seal status
              .requestMatchers("/sys/seal-status").permitAll()
              // Allow unauthenticated access to the root path (optional, for basic check)
              .requestMatchers("/").permitAll()
              // Require authentication for all other requests
              .anyRequest().authenticated()
          );
    } else {
      // If static token auth is disabled, allow all requests but log a warning.
      // WARNING: This is insecure if deployed without enabling auth.
      // **FIX:** Use SLF4j logger
      log.warn("MSSM Static Token Authentication is disabled via configuration (mssm.auth.static-tokens.enabled=false). All API endpoints are accessible without authentication. THIS IS INSECURE FOR PRODUCTION.");
      http.authorizeHttpRequests(authz -> authz.anyRequest().permitAll());
    }

    return http.build();
  }
}