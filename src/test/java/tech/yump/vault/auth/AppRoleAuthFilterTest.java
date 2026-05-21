package tech.yump.vault.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import tech.yump.vault.audit.AuditBackend;
import tech.yump.vault.auth.approle.AppRoleService;
import tech.yump.vault.core.VaultSealedException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AppRoleAuthFilterTest {

    @Mock
    private AppRoleService appRoleService;

    @Mock
    private AuditBackend auditBackend;

    private AppRoleAuthFilter filter;

    @BeforeEach
    void setUp() {
        filter = new AppRoleAuthFilter(appRoleService, auditBackend);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("No Authorization header — skip filter, chain proceeds, SecurityContext empty")
    void noAuthHeader_shouldSkipAndProceed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/kv/data/test");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(appRoleService, never()).validateToken(anyString());
    }

    @Test
    @DisplayName("Authorization: Basic ... header — not Bearer, skip filter")
    void basicAuthHeader_shouldSkipAndProceed() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/kv/data/test");
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(appRoleService, never()).validateToken(anyString());
    }

    @Test
    @DisplayName("Valid JWT — SecurityContext set with POLICY_* authorities")
    void validJwt_shouldSetSecurityContext() throws Exception {
        Claims claims = mock(Claims.class);
        when(claims.getSubject()).thenReturn("my-svc");
        when(claims.get("policies", List.class)).thenReturn(List.of("my-policy", "other-policy"));
        when(appRoleService.validateToken("valid.jwt.token")).thenReturn(claims);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/kv/data/test");
        request.addHeader("Authorization", "Bearer valid.jwt.token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getName()).isEqualTo("my-svc");
        assertThat(auth.getAuthorities()).extracting("authority")
                .containsExactlyInAnyOrder("POLICY_my-policy", "POLICY_other-policy");
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Expired JWT — SecurityContext empty, chain proceeds")
    void expiredJwt_shouldNotSetSecurityContextAndProceed() throws Exception {
        when(appRoleService.validateToken(anyString())).thenThrow(mock(ExpiredJwtException.class));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/kv/data/test");
        request.addHeader("Authorization", "Bearer expired.jwt.token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Tampered signature — SecurityContext empty, chain proceeds")
    void tamperedSignature_shouldNotSetSecurityContext() throws Exception {
        when(appRoleService.validateToken(anyString())).thenThrow(mock(SignatureException.class));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/kv/data/test");
        request.addHeader("Authorization", "Bearer tampered.jwt.token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Malformed JWT — SecurityContext empty, chain proceeds")
    void malformedJwt_shouldNotSetSecurityContext() throws Exception {
        when(appRoleService.validateToken(anyString())).thenThrow(mock(MalformedJwtException.class));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/kv/data/test");
        request.addHeader("Authorization", "Bearer not-a-jwt");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Vault sealed — SecurityContext empty, chain proceeds")
    void sealedVault_shouldNotSetSecurityContext() throws Exception {
        when(appRoleService.validateToken(anyString())).thenThrow(new VaultSealedException("Vault is sealed"));

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/kv/data/test");
        request.addHeader("Authorization", "Bearer some.jwt.token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilterInternal(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    @DisplayName("Login path — shouldNotFilter returns true")
    void loginPath_shouldBeExcludedFromFilter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/v1/auth/approle/login");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }
}
