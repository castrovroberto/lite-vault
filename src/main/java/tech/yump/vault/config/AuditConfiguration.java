package tech.yump.vault.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.FileAuditBackend;
import tech.yump.vault.audit.LogAuditBackend;

@Configuration
@Slf4j
public class AuditConfiguration {

    // Inject the globally configured ObjectMapper
    private final ObjectMapper objectMapper;

    // Inject MssmProperties to access audit config if needed for validation/logging
    // private final MssmProperties mssmProperties; // Optional

    public AuditConfiguration(ObjectMapper objectMapper /*, MssmProperties mssmProperties */) {
        this.objectMapper = objectMapper;
        // this.mssmProperties = mssmProperties; // Optional
    }

    @Bean
    @ConditionalOnProperty(name = "mssm.audit.backend", havingValue = "slf4j", matchIfMissing = true)
    public AuditBackend logAuditBackend() {
        log.info("Configuring SLF4j Audit Backend");
        // Ensure LogAuditBackend constructor accepts ObjectMapper
        return new LogAuditBackend(objectMapper);
    }

    @Bean
    @ConditionalOnProperty(name = "mssm.audit.backend", havingValue = "file")
    public AuditBackend fileAuditBackend() {
        log.info("Configuring File Audit Backend. Ensure Logback is configured correctly for logger '{}' and path property '{}'.",
                "tech.yump.vault.audit.FILE_AUDIT", MssmProperties.AuditProperties.FileAuditProperties.PATH_PROPERTY);
        // FileAuditBackend constructor needs ObjectMapper
        return new FileAuditBackend(objectMapper);
        // Note: We don't inject the file path here, as Logback handles it directly.
        // If validation of the path property (mssm.audit.file.path) is needed *before*
        // Logback initialization, you could inject MssmProperties and add checks here.
    }

    // Optional: Add a check for invalid values if desired, though ConditionalOnProperty handles known ones.
    // You could add a PostConstruct method to check the property value if it's neither 'slf4j' nor 'file'.
}