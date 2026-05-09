package tech.yump.vault;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import tech.yump.vault.config.MssmProperties;

@Slf4j
@SpringBootApplication(
        exclude = { DataSourceAutoConfiguration.class }
)
@EnableConfigurationProperties(MssmProperties.class)
@EnableScheduling
@EnableTransactionManagement
@EnableRetry
public class LiteVaultApplication {

  public static void main(String[] args) {
    SpringApplication.run(LiteVaultApplication.class, args);
    log.info(">>> LiteVault Application Started <<<");
  }
}
