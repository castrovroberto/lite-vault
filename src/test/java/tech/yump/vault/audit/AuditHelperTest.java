package tech.yump.vault.audit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tech.yump.vault.auth.StaticTokenAuthFilter;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuditHelperTest {

    @Mock
    private AuditBackend mockAuditBackend;
    @Mock
    private SecurityContext mockSecurityContext;

    @InjectMocks
    private AuditHelper auditHelper;

    @Captor
    private ArgumentCaptor<AuditEvent> auditEventCaptor;

    private MockHttpServletRequest mockRequest;
    private MockedStatic<RequestContextHolder> mockedRequestContextHolder;
    private MockedStatic<SecurityContextHolder> mockedSecurityContextHolder;

    private final String TEST_REQUEST_ID = UUID.randomUUID().toString();
    private final String TEST_PRINCIPAL = "test-token";
    private final String TEST_POLICY = "test-policy";
    private final String TEST_IP = "192.168.0.100";

    @BeforeEach
    void setUp() {
        // Mock RequestContextHolder to return our mock request attributes
        mockRequest = new MockHttpServletRequest();
        mockRequest.setRemoteAddr(TEST_IP);
        mockRequest.setRequestURI("/v1/test/path");
        mockRequest.setMethod("GET");
        mockRequest.setAttribute(StaticTokenAuthFilter.REQUEST_ID_ATTR, TEST_REQUEST_ID);
        mockRequest.addHeader("User-Agent", "TestAgent/1.0");

        ServletRequestAttributes attrs = new ServletRequestAttributes(mockRequest);
        mockedRequestContextHolder = mockStatic(RequestContextHolder.class);
        mockedRequestContextHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(attrs);

        // Mock SecurityContextHolder
        mockedSecurityContextHolder = mockStatic(SecurityContextHolder.class);
        mockedSecurityContextHolder.when(SecurityContextHolder::getContext).thenReturn(mockSecurityContext);
    }

    @AfterEach
    void tearDown() {
        // Close static mocks
        mockedRequestContextHolder.close();
        mockedSecurityContextHolder.close();
    }

    private Authentication createMockAuthentication(boolean authenticated) {
        if (!authenticated) {
            return null; // Or an unauthenticated token if needed
        }
        return new UsernamePasswordAuthenticationToken(
                TEST_PRINCIPAL,
                null,
                List.of(new SimpleGrantedAuthority("POLICY_" + TEST_POLICY))
        );
    }

    // --- Tests for logHttpEvent ---

    @Test
    @DisplayName("logHttpEvent: Should log success event with full context")
    void logHttpEvent_Success_FullContext() {
        // Arrange
        Authentication auth = createMockAuthentication(true);
        when(mockSecurityContext.getAuthentication()).thenReturn(auth);
        String type = "test_op";
        String action = "do_thing";
        int status = HttpStatus.OK.value();
        Map<String, Object> data = Map.of("key", "value");

        // Act
        auditHelper.logHttpEvent(type, action, "success", status, null, data);

        // Assert
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();

        assertThat(event.type()).isEqualTo(type);
        assertThat(event.action()).isEqualTo(action);
        assertThat(event.outcome()).isEqualTo("success");
        assertThat(event.timestamp()).isNotNull();

        assertThat(event.authInfo()).isNotNull();
        assertThat(event.authInfo().principal()).isEqualTo(TEST_PRINCIPAL);
        assertThat(event.authInfo().sourceAddress()).isEqualTo(TEST_IP);
        assertThat(event.authInfo().metadata()).isEqualTo(Map.of("policies", List.of(TEST_POLICY)));

        assertThat(event.requestInfo()).isNotNull();
        assertThat(event.requestInfo().requestId()).isEqualTo(TEST_REQUEST_ID);
        assertThat(event.requestInfo().httpMethod()).isEqualTo("GET");
        assertThat(event.requestInfo().path()).isEqualTo("/v1/test/path");
        assertThat(event.requestInfo().headers()).isEqualTo(Map.of("User-Agent", "TestAgent/1.0"));

        assertThat(event.responseInfo()).isNotNull();
        assertThat(event.responseInfo().statusCode()).isEqualTo(status);
        assertThat(event.responseInfo().errorMessage()).isNull();

        assertThat(event.data()).isEqualTo(data);
    }

    @Test
    @DisplayName("logHttpEvent: Should log failure event with error message")
    void logHttpEvent_Failure_WithError() {
        // Arrange
        Authentication auth = createMockAuthentication(true);
        when(mockSecurityContext.getAuthentication()).thenReturn(auth);
        String type = "test_op";
        String action = "fail_thing";
        int status = HttpStatus.INTERNAL_SERVER_ERROR.value();
        String errorMsg = "Something went wrong";
        Map<String, Object> data = Map.of("reason", "db_error");

        // Act
        auditHelper.logHttpEvent(type, action, "failure", status, errorMsg, data);

        // Assert
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();

        assertThat(event.outcome()).isEqualTo("failure");
        assertThat(event.responseInfo()).isNotNull();
        assertThat(event.responseInfo().statusCode()).isEqualTo(status);
        assertThat(event.responseInfo().errorMessage()).isEqualTo(errorMsg);
        assertThat(event.data()).isEqualTo(data);
        // Verify other fields are populated as in success test
        assertThat(event.authInfo().principal()).isEqualTo(TEST_PRINCIPAL);
        assertThat(event.requestInfo().requestId()).isEqualTo(TEST_REQUEST_ID);
    }

    @Test
    @DisplayName("logHttpEvent: Should handle anonymous user correctly")
    void logHttpEvent_AnonymousUser() {
        // Arrange
        Authentication anonAuth = new UsernamePasswordAuthenticationToken("anonymousUser", null, List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")));
        when(mockSecurityContext.getAuthentication()).thenReturn(anonAuth);
        int status = HttpStatus.NOT_FOUND.value();

        // Act
        auditHelper.logHttpEvent("test_op", "read", "failure", status, "Not found", null);

        // Assert
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();

        assertThat(event.authInfo().principal()).isEqualTo("anonymous");
        assertThat(event.authInfo().metadata()).isNull(); // No policies for anonymous
        assertThat(event.requestInfo()).isNotNull(); // Request info should still be present
    }

    @Test
    @DisplayName("logHttpEvent: Should handle missing request context gracefully")
    void logHttpEvent_MissingRequestContext() {
        // Arrange
        mockedRequestContextHolder.when(RequestContextHolder::getRequestAttributes).thenReturn(null); // Simulate no request context
        Authentication auth = createMockAuthentication(true);
        when(mockSecurityContext.getAuthentication()).thenReturn(auth);
        int status = HttpStatus.OK.value();

        // Act
        auditHelper.logHttpEvent("test_op", "do_thing", "success", status, null, null);

        // Assert
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();

        assertThat(event.authInfo().principal()).isEqualTo(TEST_PRINCIPAL);
        assertThat(event.authInfo().sourceAddress()).isEqualTo("unknown"); // Fallback
        assertThat(event.requestInfo()).isNull(); // No request info
        assertThat(event.responseInfo()).isNotNull(); // Response info still built
    }

    // --- Tests for logInternalEvent ---

    @Test
    @DisplayName("logInternalEvent: Should log event with provided principal and data")
    void logInternalEvent_ProvidedPrincipal() {
        // Arrange
        String type = "internal_op";
        String action = "cleanup";
        String outcome = "success";
        String principal = "scheduler_job";
        Map<String, Object> data = Map.of("items_cleaned", 10);
        // No SecurityContext auth needed for this case

        // Act
        auditHelper.logInternalEvent(type, action, outcome, principal, data);

        // Assert
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();

        assertThat(event.type()).isEqualTo(type);
        assertThat(event.action()).isEqualTo(action);
        assertThat(event.outcome()).isEqualTo(outcome);
        assertThat(event.authInfo().principal()).isEqualTo(principal);
        assertThat(event.authInfo().sourceAddress()).isNull(); // No request context
        assertThat(event.authInfo().metadata()).isNull();
        assertThat(event.requestInfo()).isNull();
        assertThat(event.responseInfo()).isNull();
        assertThat(event.data()).isEqualTo(data);
    }

    @Test
    @DisplayName("logInternalEvent: Should use principal from SecurityContext if available and principal is null")
    void logInternalEvent_PrincipalFromContext() {
        // Arrange
        Authentication auth = createMockAuthentication(true);
        when(mockSecurityContext.getAuthentication()).thenReturn(auth);
        String type = "db_op";
        String action = "lease_creation";

        // Act
        auditHelper.logInternalEvent(type, action, "success", null, Map.of("lease_id", "123"));

        // Assert
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();

        assertThat(event.authInfo().principal()).isEqualTo(TEST_PRINCIPAL);
        assertThat(event.authInfo().metadata()).isEqualTo(Map.of("policies", List.of(TEST_POLICY)));
        assertThat(event.requestInfo()).isNull();
        assertThat(event.responseInfo()).isNull();
        assertThat(event.data()).isEqualTo(Map.of("lease_id", "123"));
    }

    @Test
    @DisplayName("logInternalEvent: Should default principal to 'system' if context unavailable and principal is null")
    void logInternalEvent_DefaultSystemPrincipal() {
        // Arrange
        when(mockSecurityContext.getAuthentication()).thenReturn(null); // No auth in context
        String type = "system_event";
        String action = "startup";

        // Act
        auditHelper.logInternalEvent(type, action, "success", null, null);

        // Assert
        verify(mockAuditBackend).logEvent(auditEventCaptor.capture());
        AuditEvent event = auditEventCaptor.getValue();

        assertThat(event.authInfo().principal()).isEqualTo("system");
        assertThat(event.requestInfo()).isNull();
        assertThat(event.responseInfo()).isNull();
        assertThat(event.data()).isNull();
    }

    @Test
    @DisplayName("logInternalEvent: Should not fail if AuditBackend throws exception")
    void logInternalEvent_AuditBackendThrowsException() {
        // Arrange
        doThrow(new RuntimeException("Logging failed!")).when(mockAuditBackend).logEvent(any(AuditEvent.class));

        // Act & Assert
        // Verify that the helper method itself doesn't throw the exception
        assertThatCode(() -> auditHelper.logInternalEvent("type", "action", "outcome", "principal", null))
                .doesNotThrowAnyException();

        // Verify that logEvent was called
        verify(mockAuditBackend).logEvent(any(AuditEvent.class));
        // Error logging within the helper would also happen (requires log capture to verify)
    }
}