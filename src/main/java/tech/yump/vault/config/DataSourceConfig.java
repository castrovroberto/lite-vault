package tech.yump.vault.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;
import java.util.Arrays;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataSourceConfig {

    private final MssmProperties mssmProperties;

    @Bean
    @Primary // Ensure this is the primary DataSource bean used by default
    public DataSource dataSource() {
        log.info("Manually configuring primary Hikari DataSource...");

        MssmProperties.PostgresProperties pgProps = mssmProperties.secrets().db().postgres();
        if (pgProps == null) {
            log.error("PostgreSQL configuration (mssm.secrets.db.postgres) is missing. Cannot configure DataSource.");
            throw new IllegalStateException("Missing PostgreSQL configuration for DataSource.");
        }

        char[] passwordChars = null;
        HikariDataSource dataSource = null;
        try {
            // Get password as char array
            passwordChars = pgProps.password();
            if (passwordChars == null || passwordChars.length == 0) {
                log.error("PostgreSQL admin password is empty or null in configuration.");
                throw new IllegalStateException("PostgreSQL admin password cannot be empty.");
            }

            HikariConfig config = new HikariConfig();
            config.setJdbcUrl(pgProps.connectionUrl());
            config.setUsername(pgProps.username());

            // Convert char[] to String ONLY for setting the password in HikariConfig
            // HikariCP doesn't offer a direct char[] setter in the config object itself.
            config.setPassword(new String(passwordChars));

            // Set driver class name (optional if HikariCP can infer from URL)
            config.setDriverClassName("org.postgresql.Driver");

            // Optional HikariCP settings (can be read from spring.datasource.hikari.* if needed)
            config.setPoolName("LiteVaultPostgresPool");
            config.setMaximumPoolSize(10); // Example: Set pool size
            config.setMinimumIdle(2);
            // Add other Hikari properties as needed

            log.info("Creating HikariDataSource for URL: {}, User: {}", config.getJdbcUrl(), config.getUsername());
            dataSource = new HikariDataSource(config);

            log.info("HikariDataSource configured successfully.");
            return dataSource;

        } catch (Exception e) {
            log.error("Failed to configure primary DataSource: {}", e.getMessage(), e);
            // Clean up password array even on failure
            throw new RuntimeException("Failed to configure primary DataSource", e);
        } finally {
            // --- CRITICAL: Clear the local password char array ---
            if (passwordChars != null) {
                Arrays.fill(passwordChars, '\0'); // Overwrite with null characters
                log.debug("Local copy of DB password char array cleared from memory.");
            }
            // Note: The original char[] within the immutable MssmProperties record instance
            // still exists in memory until the MssmProperties bean is garbage collected.
            // This step clears the copy used during DataSource configuration.
        }
    }
}