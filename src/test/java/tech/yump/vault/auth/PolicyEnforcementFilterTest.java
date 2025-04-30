package tech.yump.vault.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
// Import lenient()
import static org.mockito.Mockito.lenient;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import tech.yump.vault.api.ApiError;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.audit.AuditEvent;
import tech.yump.vault.auth.policy.PolicyCapability;
import tech.yump.vault.auth.policy.PolicyDefinition;
import tech.yump.vault.auth.policy.PolicyRepository;
import tech.yump.vault.auth.policy.PolicyRule;

import java.io.IOException;
import java.io.PrintWriter;
// No longer need UnsupportedEncodingException if getWriter() throws IOException
// import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PolicyEnforcementFilterTest {

    @Mock
    private PolicyRepository mockPolicyRepository;
    @Mock
    private AuditBackend mockAuditBackend;
    @Mock
    private ObjectMapper mockObjectMapper;
    @Mock
    private FilterChain mockFilterChain;
    @Mock // Make mockResponse a proper Mockito mock
    private MockHttpServletResponse mockResponse;
    @Mock // Mock the PrintWriter as well
    private PrintWriter mockPrintWriter;

    @InjectMocks // Inject mocks into the filter instance
    private PolicyEnforcementFilter filter;

    private MockHttpServletRequest mockRequest;
    // No longer need StringWriter if PrintWriter is mocked

    @Captor
    private ArgumentCaptor<AuditEvent> auditEventCaptor;
    @Captor
    private ArgumentCaptor<ApiError> apiErrorCaptor; // Keep for verifying ObjectMapper interaction if needed

    private static final String TEST_USER = "test-token-principal";
    private static final String READ_POLICY_NAME = "reader";
    private static final String WRITE_POLICY_NAME = "writer";
    private static final String MISSING_POLICY_NAME = "ghost";
    private static final String REQUEST_ID = UUID.randomUUID().toString();

    @BeforeEach
        // Add throws IOException because getWriter() declares it
    void setUp() throws IOException {
        SecurityContextHolder.clearContext();
        mockRequest = new MockHttpServletRequest();
        mockRequest.setAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR, REQUEST_ID);
        mockRequest.setRemoteAddr("192.168.1.100");

        // *** FIX: Add lenient() ***
        lenient().when(mockResponse.getWriter()).thenReturn(mockPrintWriter);
        try {
            // *** FIX: Add lenient() ***
            lenient().doReturn("{\"error\":\"json\"}").when(mockObjectMapper).writeValueAsString(any(ApiError.class));
        } catch (JsonProcessingException e) {
            // This catch block is technically unreachable for doReturn setup,
            // but good practice if you were using when().thenThrow() etc.
            // You could log or rethrow as a RuntimeException if needed for debugging setup.
            System.err.println("Error setting up ObjectMapper mock: " + e.getMessage());
            throw new RuntimeException("Failed to mock ObjectMapper during test setup", e);
        }
    }

    // Helper to set up authentication context
    private void setupAuthentication(String principal, List<String> policyNames) {
        List<SimpleGrantedAuthority> authorities = policyNames.stream()
                .map(name -> new SimpleGrantedAuthority("POLICY_" + name))
                .toList();
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    @Test
    @DisplayName("doFilterInternal: When no authentication, should proceed")
    void doFilterInternal_whenNoAuthentication_shouldProceed() throws ServletException, IOException {
        // Arrange (no auth setup)

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse);
        verifyNoInteractions(mockPolicyRepository, mockAuditBackend, mockObjectMapper);
        verify(mockResponse, never()).setStatus(anyInt()); // Ensure no response modification happened
    }

    @Test
    @DisplayName("doFilterInternal: When anonymous authentication, should proceed")
    void doFilterInternal_whenAnonymousAuthentication_shouldProceed() throws ServletException, IOException {
        // Arrange
        Authentication anonAuth = new UsernamePasswordAuthenticationToken("anonymousUser", null, List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
        SecurityContextHolder.getContext().setAuthentication(anonAuth);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse);
        verifyNoInteractions(mockPolicyRepository, mockAuditBackend, mockObjectMapper);
        verify(mockResponse, never()).setStatus(anyInt());
    }

    @Test
    @DisplayName("doFilterInternal: When authenticated but no policies, should deny 403 and log")
    void doFilterInternal_whenAuthenticatedNoPolicies_shouldDeny403AndLog() throws ServletException, IOException {
        // Arrange
        setupAuthentication(TEST_USER, Collections.emptyList());
        mockRequest.setMethod("GET");
        mockRequest.setRequestURI("/v1/kv/data/test");
        // No need to stub getWriter here, it's done leniently in setUp

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockResponse).setStatus(HttpStatus.FORBIDDEN.value()); // Verify status set on mock
        verify(mockResponse).setContentType(MediaType.APPLICATION_JSON_VALUE); // Verify content type set on mock
        verify(mockPrintWriter).write("{\"error\":\"json\"}"); // Verify write called on mocked writer

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();
        assertThat(event.outcome()).isEqualTo("denied");
        assertThat(event.authInfo().principal()).isEqualTo(TEST_USER);
        assertThat(event.responseInfo().statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(event.responseInfo().errorMessage()).isEqualTo("Access denied. No policies associated with token.");
        // *** FIX: Assert against emptyList() directly ***
        assertThat(event.data().get("checked_policies")).isEqualTo(Collections.emptyList());
    }

    @Test
    @DisplayName("doFilterInternal: When policy name not found in repo, should deny 403 and log")
    void doFilterInternal_whenPolicyNotFound_shouldDeny403AndLog() throws ServletException, IOException {
        // Arrange
        setupAuthentication(TEST_USER, List.of(MISSING_POLICY_NAME));
        mockRequest.setMethod("GET");
        mockRequest.setRequestURI("/v1/kv/data/test");
        when(mockPolicyRepository.findPoliciesByNames(List.of(MISSING_POLICY_NAME))).thenReturn(Collections.emptyList());
        // No need to stub getWriter here, it's done leniently in setUp

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockResponse).setStatus(HttpStatus.FORBIDDEN.value());
        verify(mockResponse).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(mockPrintWriter).write("{\"error\":\"json\"}");

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();
        assertThat(event.outcome()).isEqualTo("denied");
        assertThat(event.authInfo().principal()).isEqualTo(TEST_USER);
        assertThat(event.responseInfo().statusCode()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(event.responseInfo().errorMessage()).isEqualTo("Access denied. Policy configuration error.");
        assertThat(event.data().get("checked_policies")).isEqualTo(List.of(MISSING_POLICY_NAME));
    }

    @Test
    @DisplayName("doFilterInternal: When some policies found but not all, should deny 403 and log")
    void doFilterInternal_whenSomePoliciesNotFound_shouldDeny403AndLog() throws ServletException, IOException {
        // Arrange
        setupAuthentication(TEST_USER, List.of(READ_POLICY_NAME, MISSING_POLICY_NAME));
        mockRequest.setMethod("GET");
        mockRequest.setRequestURI("/v1/kv/data/test");

        PolicyRule readRule = new PolicyRule("kv/data/*", Set.of(PolicyCapability.READ));
        PolicyDefinition readPolicyDef = new PolicyDefinition(READ_POLICY_NAME, List.of(readRule));

        when(mockPolicyRepository.findPoliciesByNames(List.of(READ_POLICY_NAME, MISSING_POLICY_NAME)))
                .thenReturn(List.of(readPolicyDef)); // Only return the one found
        // No need to stub getWriter here, it's done leniently in setUp

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockResponse).setStatus(HttpStatus.FORBIDDEN.value());
        verify(mockResponse).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(mockPrintWriter).write("{\"error\":\"json\"}");

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();
        assertThat(event.outcome()).isEqualTo("denied");
        assertThat(event.responseInfo().errorMessage()).isEqualTo("Access denied. Policy configuration error.");
        assertThat(event.data().get("checked_policies")).isEqualTo(List.of(READ_POLICY_NAME, MISSING_POLICY_NAME));
    }

    @Test
    @DisplayName("doFilterInternal: When access granted by policy, should proceed and log")
    void doFilterInternal_whenAccessGranted_shouldProceedAndLog() throws ServletException, IOException {
        // Arrange
        setupAuthentication(TEST_USER, List.of(READ_POLICY_NAME));
        mockRequest.setMethod("GET");
        mockRequest.setRequestURI("/v1/kv/data/myapp/config");

        PolicyRule rule = new PolicyRule("kv/data/myapp/*", Set.of(PolicyCapability.READ, PolicyCapability.LIST));
        PolicyDefinition policyDef = new PolicyDefinition(READ_POLICY_NAME, List.of(rule));
        when(mockPolicyRepository.findPoliciesByNames(List.of(READ_POLICY_NAME))).thenReturn(List.of(policyDef));

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(mockRequest, mockResponse); // Proceeded
        verify(mockResponse, never()).setStatus(anyInt()); // No error response status set
        verify(mockPrintWriter, never()).write(anyString()); // No error response body written

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();
        assertThat(event.outcome()).isEqualTo("granted");
        assertThat(event.authInfo().principal()).isEqualTo(TEST_USER);
        assertThat(event.requestInfo().path()).isEqualTo("/v1/kv/data/myapp/config");
        assertThat(event.data().get("checked_policies")).isEqualTo(List.of(READ_POLICY_NAME));
        assertThat(event.data().get("required_capability")).isEqualTo(PolicyCapability.READ.name());
        assertThat(event.data().get("request_path")).isEqualTo("kv/data/myapp/config");
    }

    @Test
    @DisplayName("doFilterInternal: When capability denied by policy, should deny 403 and log")
    void doFilterInternal_whenCapabilityDenied_shouldDeny403AndLog() throws ServletException, IOException {
        // Arrange
        setupAuthentication(TEST_USER, List.of(READ_POLICY_NAME));
        mockRequest.setMethod("PUT"); // Requires WRITE
        mockRequest.setRequestURI("/v1/kv/data/myapp/config");

        PolicyRule rule = new PolicyRule("kv/data/myapp/*", Set.of(PolicyCapability.READ)); // Only grants READ
        PolicyDefinition policyDef = new PolicyDefinition(READ_POLICY_NAME, List.of(rule));
        when(mockPolicyRepository.findPoliciesByNames(List.of(READ_POLICY_NAME))).thenReturn(List.of(policyDef));
        // No need to stub getWriter here, it's done leniently in setUp

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockResponse).setStatus(HttpStatus.FORBIDDEN.value());
        verify(mockResponse).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(mockPrintWriter).write("{\"error\":\"json\"}");

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();
        assertThat(event.outcome()).isEqualTo("denied");
        assertThat(event.responseInfo().errorMessage()).isEqualTo("Access denied by policy.");
        assertThat(event.data().get("required_capability")).isEqualTo(PolicyCapability.WRITE.name());
    }

    @Test
    @DisplayName("doFilterInternal: When path denied by policy (wildcard), should deny 403 and log")
    void doFilterInternal_whenPathDeniedWildcard_shouldDeny403AndLog() throws ServletException, IOException {
        // Arrange
        setupAuthentication(TEST_USER, List.of(WRITE_POLICY_NAME));
        mockRequest.setMethod("PUT");
        mockRequest.setRequestURI("/v1/kv/data/other/secret"); // Path doesn't match rule

        PolicyRule rule = new PolicyRule("kv/data/myapp/*", Set.of(PolicyCapability.WRITE)); // Rule for myapp/*
        PolicyDefinition policyDef = new PolicyDefinition(WRITE_POLICY_NAME, List.of(rule));
        when(mockPolicyRepository.findPoliciesByNames(List.of(WRITE_POLICY_NAME))).thenReturn(List.of(policyDef));
        // No need to stub getWriter here, it's done leniently in setUp

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockResponse).setStatus(HttpStatus.FORBIDDEN.value());
        verify(mockResponse).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(mockPrintWriter).write("{\"error\":\"json\"}");

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();
        assertThat(event.outcome()).isEqualTo("denied");
        assertThat(event.responseInfo().errorMessage()).isEqualTo("Access denied by policy.");
        assertThat(event.data().get("request_path")).isEqualTo("kv/data/other/secret");
    }

    @Test
    @DisplayName("doFilterInternal: When path denied by policy (exact), should deny 403 and log")
    void doFilterInternal_whenPathDeniedExact_shouldDeny403AndLog() throws ServletException, IOException {
        // Arrange
        setupAuthentication(TEST_USER, List.of(READ_POLICY_NAME));
        mockRequest.setMethod("GET");
        mockRequest.setRequestURI("/v1/kv/data/config"); // Path doesn't match rule

        PolicyRule rule = new PolicyRule("kv/data/config/specific", Set.of(PolicyCapability.READ)); // Exact path rule
        PolicyDefinition policyDef = new PolicyDefinition(READ_POLICY_NAME, List.of(rule));
        when(mockPolicyRepository.findPoliciesByNames(List.of(READ_POLICY_NAME))).thenReturn(List.of(policyDef));
        // No need to stub getWriter here, it's done leniently in setUp

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockResponse).setStatus(HttpStatus.FORBIDDEN.value());
        verify(mockResponse).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(mockPrintWriter).write("{\"error\":\"json\"}");

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();
        assertThat(event.outcome()).isEqualTo("denied");
        assertThat(event.responseInfo().errorMessage()).isEqualTo("Access denied by policy.");
        assertThat(event.data().get("request_path")).isEqualTo("kv/data/config");
    }

    @Test
    @DisplayName("doFilterInternal: When request URI not under /v1/, should deny 403 and log")
    void doFilterInternal_whenInvalidRequestPathPrefix_shouldDeny403AndLog() throws ServletException, IOException {
        // Arrange
        setupAuthentication(TEST_USER, List.of(READ_POLICY_NAME)); // Has policies, but path is wrong
        mockRequest.setMethod("GET");
        mockRequest.setRequestURI("/api/v2/kv/data/test"); // Invalid prefix for policy check
        // No need to stub getWriter here, it's done leniently in setUp

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain, never()).doFilter(any(), any());
        verify(mockResponse).setStatus(HttpStatus.FORBIDDEN.value());
        verify(mockResponse).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(mockPrintWriter).write("{\"error\":\"json\"}");

        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();
        assertThat(event.outcome()).isEqualTo("denied");
        assertThat(event.responseInfo().errorMessage()).isEqualTo("Invalid request structure for policy evaluation.");
        assertThat(event.data().get("request_path")).isEqualTo("/api/v2/kv/data/test"); // Logs original path
        assertThat(event.data().get("required_capability")).isEqualTo("N/A");
    }

    @Test
    @DisplayName("shouldNotFilter: Should filter paths under /v1/")
    void shouldNotFilter_whenV1Path_shouldReturnFalse() throws ServletException {
        // Arrange
        mockRequest.setRequestURI("/v1/kv/data/test");
        // Act & Assert
        assertThat(filter.shouldNotFilter(mockRequest)).isFalse();
    }

    @Test
    @DisplayName("shouldNotFilter: Should not filter public paths")
    void shouldNotFilter_whenPublicPath_shouldReturnTrue() throws ServletException {
        // Arrange
        mockRequest.setRequestURI("/");
        // Act & Assert
        assertThat(filter.shouldNotFilter(mockRequest)).isTrue();

        mockRequest.setRequestURI("/sys/seal-status");
        assertThat(filter.shouldNotFilter(mockRequest)).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter: Should not filter non-v1 paths")
    void shouldNotFilter_whenNonV1Path_shouldReturnTrue() throws ServletException {
        // Arrange
        mockRequest.setRequestURI("/actuator/health");
        // Act & Assert
        assertThat(filter.shouldNotFilter(mockRequest)).isTrue();

        mockRequest.setRequestURI("/some/other/path");
        assertThat(filter.shouldNotFilter(mockRequest)).isTrue();
    }
}