package tech.yump.vault.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.config.MssmProperties;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StaticTokenAuthFilterTest {

    @Mock
    private AuditBackend mockAuditBackend;
    @Mock
    private FilterChain mockFilterChain;

    private MockHttpServletRequest mockRequest;
    private MockHttpServletResponse mockResponse;

    private StaticTokenAuthFilter filter;

    // Define some test tokens and policies
    private static final String VALID_TOKEN_READ = "read-token-123";
    private static final String VALID_TOKEN_WRITE = "write-token-456";
    private static final String INVALID_TOKEN = "invalid-token-789";
    private static final String READ_POLICY = "kv-reader";
    private static final String WRITE_POLICY = "kv-writer";

    @Captor
    private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @BeforeEach
    void setUp() {
        // Clear security context before each test
        SecurityContextHolder.clearContext();
        mockRequest = new MockHttpServletRequest();
        mockResponse = new MockHttpServletResponse();
        // Ensure request ID attribute is handled
        mockRequest.setAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR, UUID.randomUUID().toString());
    }

    private MssmProperties.AuthProperties.StaticTokenAuthProperties createProps(boolean enabled, List<MssmProperties.AuthProperties.StaticTokenPolicyMapping> mappings) {
        return new MssmProperties.AuthProperties.StaticTokenAuthProperties(enabled, mappings);
    }

    @Test
    @DisplayName("doFilterInternal: When auth disabled, should skip filter and proceed")
    void doFilterInternal_whenAuthDisabled_shouldSkipAndProceed() throws ServletException, IOException {
        // Arrange
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(false, Collections.emptyList());
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse);
        verifyNoInteractions(mockAuditBackend);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("doFilterInternal: When auth enabled but no token header, should proceed without auth")
    void doFilterInternal_whenNoTokenHeader_shouldProceedWithoutAuth() throws ServletException, IOException {
        // Arrange
        MssmProperties.AuthProperties.StaticTokenPolicyMapping mapping = new MssmProperties.AuthProperties.StaticTokenPolicyMapping(VALID_TOKEN_READ, List.of(READ_POLICY));
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(true, List.of(mapping));
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);
        // No header set on mockRequest

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse);
        verifyNoInteractions(mockAuditBackend); // No auth attempt logged
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("doFilterInternal: When auth enabled but empty token header, should proceed without auth")
    void doFilterInternal_whenEmptyTokenHeader_shouldProceedWithoutAuth() throws ServletException, IOException {
        // Arrange
        MssmProperties.AuthProperties.StaticTokenPolicyMapping mapping = new MssmProperties.AuthProperties.StaticTokenPolicyMapping(VALID_TOKEN_READ, List.of(READ_POLICY));
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(true, List.of(mapping));
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);
        mockRequest.addHeader(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, "   "); // Empty/blank header

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse);
        verifyNoInteractions(mockAuditBackend);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("doFilterInternal: When auth enabled and invalid token, should log failure and proceed")
    void doFilterInternal_whenInvalidToken_shouldLogFailureAndProceed() throws ServletException, IOException {
        // Arrange
        MssmProperties.AuthProperties.StaticTokenPolicyMapping mapping = new MssmProperties.AuthProperties.StaticTokenPolicyMapping(VALID_TOKEN_READ, List.of(READ_POLICY));
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(true, List.of(mapping));
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);
        mockRequest.addHeader(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, INVALID_TOKEN);
        mockRequest.setMethod("GET");
        mockRequest.setRequestURI("/v1/kv/data/test");
        mockRequest.setRemoteAddr("1.2.3.4");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent capturedEvent = auditEventCaptor.getValue();
        assertThat(capturedEvent.type()).isEqualTo("auth");
        assertThat(capturedEvent.action()).isEqualTo("token_validation");
        assertThat(capturedEvent.outcome()).isEqualTo("failure");
        assertThat(capturedEvent.authInfo().principal()).isNull(); // No principal on failure
        assertThat(capturedEvent.authInfo().sourceAddress()).isEqualTo("1.2.3.4");
        assertThat(capturedEvent.requestInfo().httpMethod()).isEqualTo("GET");
        assertThat(capturedEvent.requestInfo().path()).isEqualTo("/v1/kv/data/test");
        assertThat(capturedEvent.data()).isEqualTo(Map.of("reason", "invalid_token"));
    }

    @Test
    @DisplayName("doFilterInternal: When auth enabled and valid token, should set auth context, log success, and proceed")
    void doFilterInternal_whenValidToken_shouldSetAuthLogSuccessAndProceed() throws ServletException, IOException {
        // Arrange
        List<String> policies = List.of(READ_POLICY, WRITE_POLICY);
        MssmProperties.AuthProperties.StaticTokenPolicyMapping mapping = new MssmProperties.AuthProperties.StaticTokenPolicyMapping(VALID_TOKEN_WRITE, policies);
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(true, List.of(mapping));
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);
        mockRequest.addHeader(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, VALID_TOKEN_WRITE);
        mockRequest.setMethod("PUT");
        mockRequest.setRequestURI("/v1/kv/data/app");
        mockRequest.setRemoteAddr("10.0.0.5");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse);

        // Verify Security Context
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth).isInstanceOf(UsernamePasswordAuthenticationToken.class);
        assertThat(auth.isAuthenticated()).isTrue();
        assertThat(auth.getPrincipal()).isEqualTo(VALID_TOKEN_WRITE);
        assertThat(auth.getCredentials()).isNull();
        assertThat(auth.getAuthorities())
                .extracting(GrantedAuthority::getAuthority) // Extract the String representation
                .containsExactlyInAnyOrder(                 // Assert on the Strings
                        "POLICY_" + READ_POLICY,
                        "POLICY_" + WRITE_POLICY
                );

        // Verify Audit Log
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent capturedEvent = auditEventCaptor.getValue();
        assertThat(capturedEvent.type()).isEqualTo("auth");
        assertThat(capturedEvent.action()).isEqualTo("token_validation");
        assertThat(capturedEvent.outcome()).isEqualTo("success");
        assertThat(capturedEvent.authInfo().principal()).isEqualTo(VALID_TOKEN_WRITE);
        assertThat(capturedEvent.authInfo().sourceAddress()).isEqualTo("10.0.0.5");
        assertThat(capturedEvent.authInfo().metadata()).isEqualTo(Map.of("policies", policies));
        assertThat(capturedEvent.requestInfo().httpMethod()).isEqualTo("PUT");
        assertThat(capturedEvent.requestInfo().path()).isEqualTo("/v1/kv/data/app");
        assertThat(capturedEvent.data()).isEqualTo(Map.of("policies", policies));
    }

    @Test
    @DisplayName("doFilterInternal: When already authenticated, should skip token check and proceed")
    void doFilterInternal_whenAlreadyAuthenticated_shouldSkipAndProceed() throws ServletException, IOException {
        // Arrange
        // Set up existing authentication
        Authentication existingAuth = new UsernamePasswordAuthenticationToken("pre-authenticated-user", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        SecurityContextHolder.getContext().setAuthentication(existingAuth);

        MssmProperties.AuthProperties.StaticTokenPolicyMapping mapping = new MssmProperties.AuthProperties.StaticTokenPolicyMapping(VALID_TOKEN_READ, List.of(READ_POLICY));
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(true, List.of(mapping));
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);
        mockRequest.addHeader(StaticTokenAuthFilter.VAULT_TOKEN_HEADER, VALID_TOKEN_READ); // Header is present but should be ignored

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse);
        verifyNoInteractions(mockAuditBackend); // No new auth attempt logged
        // Verify context still holds the original authentication
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existingAuth);
    }

    @Test
    @DisplayName("shouldNotFilter: Should filter non-public paths when enabled")
    void shouldNotFilter_whenEnabledAndNonPublicPath_shouldReturnFalse() throws ServletException {
        // Arrange
        MssmProperties.AuthProperties.StaticTokenPolicyMapping mapping = new MssmProperties.AuthProperties.StaticTokenPolicyMapping(VALID_TOKEN_READ, List.of(READ_POLICY));
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(true, List.of(mapping));
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);
        mockRequest.setRequestURI("/v1/kv/data/somepath");

        // Act & Assert
        assertThat(filter.shouldNotFilter(mockRequest)).isFalse();
    }

    @Test
    @DisplayName("shouldNotFilter: Should not filter public paths when enabled")
    void shouldNotFilter_whenEnabledAndPublicPath_shouldReturnTrue() throws ServletException {
        // Arrange
        MssmProperties.AuthProperties.StaticTokenPolicyMapping mapping = new MssmProperties.AuthProperties.StaticTokenPolicyMapping(VALID_TOKEN_READ, List.of(READ_POLICY));
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(true, List.of(mapping));
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);
        mockRequest.setRequestURI("/sys/seal-status");

        // Act & Assert
        assertThat(filter.shouldNotFilter(mockRequest)).isTrue();

        mockRequest.setRequestURI("/");
        assertThat(filter.shouldNotFilter(mockRequest)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter: Should not filter any path when disabled")
    void shouldNotFilter_whenDisabled_shouldReturnTrue() throws ServletException {
        // Arrange
        MssmProperties.AuthProperties.StaticTokenAuthProperties props = createProps(false, Collections.emptyList());
        filter = new StaticTokenAuthFilter(props, mockAuditBackend);
        mockRequest.setRequestURI("/v1/kv/data/somepath"); // Non-public path

        // Act & Assert
        assertThat(filter.shouldNotFilter(mockRequest)).isTrue();

        mockRequest.setRequestURI("/"); // Public path
        assertThat(filter.shouldNotFilter(mockRequest)).isTrue();
    }
}