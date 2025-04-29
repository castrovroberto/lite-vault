package tech.yump.vault.config;

import java.util.Collections; // Import Collections
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
// import org.slf4j.Logger; // Unused import
// import org.slf4j.LoggerFactory; // Unused import
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
@Slf4j
public class SecurityConfig {

  private final MssmProperties mssmProperties;

  @Bean
  public StaticTokenAuthFilter staticTokenAuthFilter() {
    MssmProperties.AuthProperties authProps = mssmProperties.auth();
    // Use null-safe accessors for robustness
    MssmProperties.AuthProperties.StaticTokenAuthProperties staticTokenProps = (authProps != null) ? authProps.staticTokens() : null;

    if (staticTokenProps != null && staticTokenProps.enabled()) {
      log.debug("Static token authentication enabled. Creating StaticTokenAuthFilter with configured properties.");
      // Pass the actual properties record
      return new StaticTokenAuthFilter(staticTokenProps);
    } else {
      log.debug("Static token authentication disabled. Creating dummy StaticTokenAuthFilter.");
      // Create a disabled properties record with an EMPTY LIST for mappings
      return new StaticTokenAuthFilter(
              new MssmProperties.AuthProperties.StaticTokenAuthProperties(false, Collections.emptyList()) // <-- FIX: Use emptyList()
      );
    }
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    // Determine if static auth is enabled based on properties
    MssmProperties.AuthProperties authProps = mssmProperties.auth();
    boolean staticAuthEnabled = authProps != null
            && authProps.staticTokens() != null
            && authProps.staticTokens().enabled();

    if (staticAuthEnabled) {
      log.info("Configuring Spring Security for Static Token Authentication.");
      http
              // Add the filter bean created above
              .addFilterBefore(staticTokenAuthFilter(), UsernamePasswordAuthenticationFilter.class)
              .authorizeHttpRequests(authz -> authz
                      // Define public paths
                      .requestMatchers("/sys/seal-status", "/").permitAll()
                      // Require authentication for v1 API paths
                      .requestMatchers("/v1/**").authenticated()
                      // Require authentication for any other request not explicitly permitted
                      .anyRequest().authenticated()
              );
    } else {
      log.warn("MSSM Static Token Authentication is disabled via configuration (mssm.auth.static-tokens.enabled=false). All API endpoints are accessible without authentication. THIS IS INSECURE FOR PRODUCTION.");
      // If auth is disabled, permit all requests
      http.authorizeHttpRequests(authz -> authz.anyRequest().permitAll());
    }

    return http.build();
  }
}