package tech.yump.vault.auth.approle;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.core.SealManager;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.crypto.EncryptionService;
import tech.yump.vault.storage.EncryptedData;
import tech.yump.vault.storage.StorageBackend;
import tech.yump.vault.storage.StorageException;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
public class AppRoleService {

    private static final String HMAC_KEY_PATH = "auth/approle/hmac-key";
    private static final String ROLE_PATH_FMT = "auth/approle/roles/%s";
    private static final Duration DEFAULT_TOKEN_TTL = Duration.ofHours(1);
    private static final Duration DEFAULT_SECRET_ID_TTL = Duration.ofHours(24);

    private final StorageBackend storageBackend;
    private final EncryptionService encryptionService;
    private final SealManager sealManager;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final AuditHelper auditHelper;
    private final Clock clock;

    private volatile byte[] hmacKeyBytes;

    public AppRoleService(StorageBackend storageBackend,
                          EncryptionService encryptionService,
                          SealManager sealManager,
                          JdbcTemplate jdbcTemplate,
                          ObjectMapper objectMapper,
                          AuditHelper auditHelper,
                          Clock clock) {
        this.storageBackend = storageBackend;
        this.encryptionService = encryptionService;
        this.sealManager = sealManager;
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.auditHelper = auditHelper;
        this.clock = clock;
    }

    @PostConstruct
    public void initialize() {
        if (sealManager.isSealed()) {
            log.warn("Vault is sealed at startup — AppRole HMAC key not loaded. AppRole auth will be unavailable until unseal.");
            return;
        }
        loadOrGenerateHmacKey();
    }

    private void loadOrGenerateHmacKey() {
        try {
            Optional<EncryptedData> existing = storageBackend.get(HMAC_KEY_PATH);
            if (existing.isPresent()) {
                EncryptedData data = existing.get();
                byte[] nonceAndCt = toNonceAndCiphertext(data);
                hmacKeyBytes = encryptionService.decrypt(nonceAndCt);
                log.info("AppRole HMAC key loaded from storage.");
            } else {
                byte[] rawKey = new byte[32];
                new SecureRandom().nextBytes(rawKey);
                byte[] nonceAndCt = encryptionService.encrypt(rawKey);
                storageBackend.put(HMAC_KEY_PATH, toEncryptedData(nonceAndCt));
                hmacKeyBytes = rawKey;
                log.info("AppRole HMAC key generated and stored.");
            }
        } catch (StorageException | EncryptionService.EncryptionException e) {
            throw new AppRoleException("Failed to initialize AppRole HMAC key", e);
        }
    }

    // --- Role CRUD ---

    public void createOrUpdateRole(AppRoleDefinition role) {
        if (role.roleName() == null || role.roleName().isBlank()) {
            throw new IllegalArgumentException("Role name cannot be blank.");
        }
        if (role.policyNames() == null || role.policyNames().isEmpty()) {
            throw new IllegalArgumentException("Role must have at least one policy name.");
        }
        try {
            byte[] json = objectMapper.writeValueAsBytes(role);
            byte[] nonceAndCt = encryptionService.encrypt(json);
            storageBackend.put(roleStoragePath(role.roleName()), toEncryptedData(nonceAndCt));
            log.debug("AppRole '{}' stored.", role.roleName());
            auditHelper.logInternalEvent("approle_operation", "role_create_or_update", "success",
                    null, Map.of("role_name", role.roleName()));
        } catch (JsonProcessingException e) {
            throw new AppRoleException("Failed to serialize role: " + role.roleName(), e);
        }
    }

    public AppRoleDefinition getRole(String roleName) {
        try {
            return storageBackend.get(roleStoragePath(roleName))
                    .map(data -> {
                        try {
                            byte[] plaintext = encryptionService.decrypt(toNonceAndCiphertext(data));
                            return objectMapper.readValue(plaintext, AppRoleDefinition.class);
                        } catch (Exception e) {
                            throw new AppRoleException("Failed to deserialize role: " + roleName, e);
                        }
                    })
                    .orElseThrow(() -> new AppRoleException.RoleNotFoundException(roleName));
        } catch (StorageException e) {
            throw new AppRoleException("Storage error reading role: " + roleName, e);
        }
    }

    public void deleteRole(String roleName) {
        try {
            storageBackend.delete(roleStoragePath(roleName));
            jdbcTemplate.update("DELETE FROM approle_credentials WHERE role_name = ?", roleName);
            log.debug("AppRole '{}' and its credentials deleted.", roleName);
            auditHelper.logInternalEvent("approle_operation", "role_delete", "success",
                    null, Map.of("role_name", roleName));
        } catch (StorageException e) {
            throw new AppRoleException("Storage error deleting role: " + roleName, e);
        }
    }

    // --- Secret ID lifecycle ---

    public String generateSecretId(String roleName) {
        AppRoleDefinition role = getRole(roleName);
        String secretId = UUID.randomUUID().toString();
        Instant expiresAt = Instant.now(clock).plus(
                role.secretIdTtl() != null ? role.secretIdTtl() : DEFAULT_SECRET_ID_TTL);
        jdbcTemplate.update(
                "INSERT INTO approle_credentials (secret_id, role_name, expires_at, used, created_at) VALUES (?, ?, ?, FALSE, now())",
                secretId, roleName, Timestamp.from(expiresAt));
        log.debug("Generated secret_id for role '{}'.", roleName);
        auditHelper.logInternalEvent("approle_operation", "secret_id_generate", "success",
                null, Map.of("role_name", roleName));
        return secretId;
    }

    // --- Login ---

    public LoginResult login(String roleId, String secretId) {
        // 1. Look up credential row
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT role_name, expires_at, used FROM approle_credentials WHERE secret_id = ?",
                secretId);

        if (rows.isEmpty()) {
            auditHelper.logInternalEvent("approle_operation", "login", "failure",
                    null, Map.of("reason", "unknown_secret_id"));
            throw new AppRoleException.InvalidCredentialsException("unknown secret_id");
        }

        Map<String, Object> row = rows.get(0);
        Instant expiresAt = ((Timestamp) row.get("expires_at")).toInstant();
        boolean used = (Boolean) row.get("used");
        String storedRoleName = (String) row.get("role_name");

        if (Instant.now(clock).isAfter(expiresAt)) {
            auditHelper.logInternalEvent("approle_operation", "login", "failure",
                    null, Map.of("reason", "expired_secret_id"));
            throw new AppRoleException.InvalidCredentialsException("secret_id expired");
        }

        if (used) {
            auditHelper.logInternalEvent("approle_operation", "login", "failure",
                    null, Map.of("reason", "secret_id_exhausted"));
            throw new AppRoleException.SecretIdExhaustedException();
        }

        // 2. Verify role_id matches
        if (!storedRoleName.equals(roleId)) {
            auditHelper.logInternalEvent("approle_operation", "login", "failure",
                    null, Map.of("reason", "role_id_mismatch"));
            throw new AppRoleException.InvalidCredentialsException("role_id mismatch");
        }

        // 3. Load role definition
        AppRoleDefinition role = getRole(roleId);

        // 4. Mark used if single-use
        if (role.secretIdNumUses() != 0) {
            jdbcTemplate.update("UPDATE approle_credentials SET used = TRUE WHERE secret_id = ?", secretId);
        }

        // 5. Issue JWT
        LoginResult result = buildAppRoleJwt(role);
        auditHelper.logInternalEvent("approle_operation", "login", "success",
                roleId, Map.of("role_name", roleId, "ttl_seconds", result.ttlSeconds()));
        return result;
    }

    private LoginResult buildAppRoleJwt(AppRoleDefinition role) {
        if (hmacKeyBytes == null) {
            throw new VaultSealedException("AppRole HMAC key not available — vault may be sealed.");
        }
        SecretKey key = Keys.hmacShaKeyFor(hmacKeyBytes);
        Instant now = Instant.now(clock);
        Duration ttl = role.tokenTtl() != null ? role.tokenTtl() : DEFAULT_TOKEN_TTL;
        Instant exp = now.plus(ttl);

        String token = Jwts.builder()
                .subject(role.roleName())
                .claim("policies", role.policyNames())
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

        return new LoginResult(token, ttl.getSeconds());
    }

    // --- JWT validation (called by AppRoleAuthFilter) ---

    public Claims validateToken(String jwtString) {
        if (hmacKeyBytes == null) {
            throw new VaultSealedException("AppRole HMAC key not available — vault may be sealed.");
        }
        SecretKey key = Keys.hmacShaKeyFor(hmacKeyBytes);
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwtString)
                .getPayload();
    }

    // --- Scheduled cleanup ---

    @Scheduled(fixedDelayString = "${mssm.auth.approle.secret-id-cleanup-interval:PT5M}")
    public void cleanupExpiredSecretIds() {
        if (sealManager.isSealed()) return;
        int deleted = jdbcTemplate.update(
                "DELETE FROM approle_credentials WHERE expires_at < ?",
                Timestamp.from(Instant.now(clock)));
        if (deleted > 0) {
            log.debug("Cleaned up {} expired AppRole secret_id(s).", deleted);
        }
    }

    // --- Helpers ---

    private String roleStoragePath(String roleName) {
        return String.format(ROLE_PATH_FMT, roleName);
    }

    private EncryptedData toEncryptedData(byte[] nonceAndCiphertext) {
        byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE];
        byte[] ct = new byte[nonceAndCiphertext.length - EncryptionService.NONCE_LENGTH_BYTE];
        ByteBuffer.wrap(nonceAndCiphertext).get(nonce).get(ct);
        return new EncryptedData(nonce, ct);
    }

    private byte[] toNonceAndCiphertext(EncryptedData data) {
        byte[] nonce = data.getNonceBytes();
        byte[] ct = data.getCiphertextBytes();
        return ByteBuffer.allocate(nonce.length + ct.length).put(nonce).put(ct).array();
    }

    public record LoginResult(String token, long ttlSeconds) {}
}
