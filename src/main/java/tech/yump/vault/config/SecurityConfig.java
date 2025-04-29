package tech.yump.vault.config;

import java.util.Collections; // Import Collections
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class SecurityConfig {

  private final MssmProperties mssmProperties;

  @Bean
  public StaticTokenAuthFilter staticTokenAuthFilter() {
    MssmProperties.AuthProperties authProps = mssmProperties.auth();
    if (authProps != null && authProps.staticTokens() != null && authProps.staticTokens().enabled()) {
      log.debug("Static token authentication enabled. Creating StaticTokenAuthFilter with configured properties.");
      return new StaticTokenAuthFilter(authProps.staticTokens());
    } else {
      log.debug("Static token authentication disabled. Creating dummy StaticTokenAuthFilter.");
      return new StaticTokenAuthFilter(
          new MssmProperties.AuthProperties.StaticTokenAuthProperties(false, Collections.emptySet())
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

    MssmProperties.AuthProperties authProps = mssmProperties.auth();
    boolean staticAuthEnabled = authProps != null
            && authProps.staticTokens() != null
            && authProps.staticTokens().enabled();

    if (staticAuthEnabled) {
      log.info("Configuring Spring Security for Static Token Authentication.");
      http
          .addFilterBefore(staticTokenAuthFilter(), UsernamePasswordAuthenticationFilter.class)
          .authorizeHttpRequests(authz -> authz
              .requestMatchers("/sys/seal-status", "/").permitAll()
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