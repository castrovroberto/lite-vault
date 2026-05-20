package tech.yump.vault.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import tech.yump.vault.storage.FileSystemStorageBackend;
import tech.yump.vault.storage.JdbcStorageBackend;
import tech.yump.vault.storage.StorageBackend;
import tech.yump.vault.storage.StorageException;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class StorageConfig {

    private final MssmProperties mssmProperties;
    private final ObjectMapper objectMapper;

    @Bean
    @Primary
    public StorageBackend storageBackend(JdbcTemplate jdbcTemplate) {
        String backend = mssmProperties.storage().backend();
        log.info("Configuring storage backend: '{}'", backend);

        return switch (backend.toLowerCase()) {
            case "jdbc" -> {
                log.info("Using JdbcStorageBackend (PostgreSQL).");
                yield new JdbcStorageBackend(jdbcTemplate, objectMapper);
            }
            case "filesystem" -> {
                MssmProperties.StorageProperties.FileSystemProperties fsProps = mssmProperties.storage().filesystem();
                if (fsProps == null || fsProps.path() == null || fsProps.path().isBlank()) {
                    throw new StorageException(
                            "mssm.storage.filesystem.path must be set when using 'filesystem' backend.");
                }
                log.info("Using FileSystemStorageBackend at path: {}", fsProps.path());
                yield new FileSystemStorageBackend(objectMapper, mssmProperties);
            }
            default -> throw new StorageException(
                    "Unknown storage backend '" + backend + "'. Supported values: filesystem, jdbc.");
        };
    }
}
