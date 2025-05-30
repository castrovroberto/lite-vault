package tech.yump.vault.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tech.yump.vault.auth.StaticTokenAuthFilter; // Import constant

@Configuration
public class OpenApiConfig {

    // Use the constant from the filter for consistency
    private static final String API_KEY_HEADER_NAME = StaticTokenAuthFilter.VAULT_TOKEN_HEADER; // "X-Vault-Token"
    // Logical name for the security scheme within the OpenAPI document
    private static final String SECURITY_SCHEME_NAME = "VaultTokenAuth";

    @Bean
    public OpenAPI customOpenAPI() {
        // 1. Define the Security Scheme (API Key in Header)
        SecurityScheme apiKeyScheme = new SecurityScheme()
                .name(API_KEY_HEADER_NAME) // The actual header name clients must send
                .type(SecurityScheme.Type.APIKEY) // Type is API Key
                .in(SecurityScheme.In.HEADER) // Location is Header
                .description("Static API token ('" + API_KEY_HEADER_NAME + "') required for accessing protected Lite Vault endpoints. Obtain from configuration or administrator.");

        // 2. Define the Security Requirement (Apply the scheme globally)
        SecurityRequirement securityRequirement = new SecurityRequirement()
                .addList(SECURITY_SCHEME_NAME); // Reference the scheme by its logical name

        // 3. Build the OpenAPI object with Components and global Security
        return new OpenAPI()
                // Add the scheme definition under components
                .components(new Components()
                        .addSecuritySchemes(SECURITY_SCHEME_NAME, apiKeyScheme))
                // Apply the requirement globally to all operations
                .addSecurityItem(securityRequirement);

        // Note: Basic info (title, version, etc.) is automatically picked up
        // from application.yml properties by springdoc.
    }
}