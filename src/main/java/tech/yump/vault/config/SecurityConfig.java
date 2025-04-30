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