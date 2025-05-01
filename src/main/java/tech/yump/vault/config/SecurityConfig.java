package tech.yump.vault.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired; // Added
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import tech.yump.vault.audit.AuditBackend; // Added
import tech.yump.vault.auth.PolicyEnforcementFilter;
import tech.yump.vault.auth.StaticTokenAuthFilter;
import tech.yump.vault.auth.policy.PolicyRepository;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor // Keeps constructor injection for final fields
@Slf4j
public class SecurityConfig {

  private final MssmProperties mssmProperties;
  private final PolicyRepository policyRepository;
  private final AuditBackend auditBackend;
  private final ObjectMapper objectMapper;

  @Bean
  public StaticTokenAuthFilter staticTokenAuthFilter() { // Removed AuditBackend from params, use injected field
    MssmProperties.AuthProperties authProps = mssmProperties.auth();
    MssmProperties.AuthProperties.StaticTokenAuthProperties staticTokenProps = (authProps != null) ? authProps.staticTokens() : null;

    MssmProperties.AuthProperties.StaticTokenAuthProperties effectiveProps;
    if (staticTokenProps != null && staticTokenProps.enabled()) {
      log.debug("Static token authentication enabled. Creating StaticTokenAuthFilter with configured properties.");
      effectiveProps = staticTokenProps;
    } else {
      log.debug("Static token authentication disabled. Creating dummy StaticTokenAuthFilter.");
      effectiveProps = new MssmProperties.AuthProperties.StaticTokenAuthProperties(false, Collections.emptyList());
    }
    // Pass the injected auditBackend to the filter constructor
    return new StaticTokenAuthFilter(effectiveProps, auditBackend); // Modified
  }

  @Bean
  public PolicyEnforcementFilter policyEnforcementFilter() { // Removed AuditBackend from params, use injected field
    log.debug("Creating PolicyEnforcementFilter.");
    // Pass the injected auditBackend to the filter constructor
    return new PolicyEnforcementFilter(policyRepository, auditBackend, objectMapper); // Modified
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
                      .requestMatchers("/sys/seal-status", "/").permitAll()
                      .requestMatchers("/v1/jwt/jwks/**").permitAll()
                      .requestMatchers("/actuator/**").permitAll()
                      .requestMatchers("/v1/**").authenticated()
                      .anyRequest().authenticated()
              );
    } else {
      log.warn("MSSM Static Token Authentication is disabled via configuration (mssm.auth.static-tokens.enabled=false). All API endpoints are accessible without authentication. THIS IS INSECURE FOR PRODUCTION.");
      http.authorizeHttpRequests(authz -> authz.anyRequest().permitAll());
    }

    return http.build();
  }
}