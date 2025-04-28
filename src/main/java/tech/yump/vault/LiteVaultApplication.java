package tech.yump.vault;

import lombok.extern.slf4j.Slf4j; // Add logging
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@Slf4j // Add logging annotation
@SpringBootApplication // Enable auto-configuration, component scanning, etc.
public class LiteVaultApplication {

  public static void main(String[] args) {
    // Launch the Spring Boot application
    SpringApplication.run(LiteVaultApplication.class, args);
    log.info(">>> LiteVault Application Started <<<");
    // The web server starts automatically as part of SpringApplication.run()
    // because spring-boot-starter-web is on the classpath.
  }
}