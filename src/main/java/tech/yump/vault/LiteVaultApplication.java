package tech.yump.vault;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import tech.yump.vault.config.MssmProperties;

@Slf4j
@SpringBootApplication
@EnableConfigurationProperties(MssmProperties.class)
public class LiteVaultApplication {

  public static void main(String[] args) {
    SpringApplication.run(LiteVaultApplication.class, args);
    log.info(">>> LiteVault Application Started <<<");
  }
}
