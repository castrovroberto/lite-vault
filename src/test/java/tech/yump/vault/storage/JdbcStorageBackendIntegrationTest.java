package tech.yump.vault.storage;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers
class JdbcStorageBackendIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("testdb")
            .withUsername("testuser")
            .withPassword("testpassword");

    private JdbcStorageBackend backend;

    @BeforeEach
    void setUp() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setUrl(postgres.getJdbcUrl());
        ds.setUsername(postgres.getUsername());
        ds.setPassword(postgres.getPassword());

        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        backend = new JdbcStorageBackend(jdbcTemplate, new ObjectMapper());
        backend.initSchema();

        // Clean slate for each test
        jdbcTemplate.update("DELETE FROM vault_storage");
    }

    private EncryptedData makeData(String nonce, String cipher) {
        EncryptedData d = new EncryptedData();
        d.setVersion(1);
        d.setNonceBase64(nonce);
        d.setCiphertextBase64(cipher);
        d.setTimestamp(Instant.now());
        return d;
    }

    @Test
    @DisplayName("put and get roundtrip returns stored data")
    void putAndGet_roundtrip() {
        EncryptedData data = makeData("nonce1", "cipher1");
        backend.put("kv/data/myapp/secret", data);

        Optional<EncryptedData> result = backend.get("kv/data/myapp/secret");
        assertThat(result).isPresent();
        assertThat(result.get().getNonceBase64()).isEqualTo("nonce1");
        assertThat(result.get().getCiphertextBase64()).isEqualTo("cipher1");
    }

    @Test
    @DisplayName("put overwrites existing data for same key")
    void put_overwrite() {
        backend.put("kv/data/foo", makeData("n1", "c1"));
        backend.put("kv/data/foo", makeData("n2", "c2"));

        Optional<EncryptedData> result = backend.get("kv/data/foo");
        assertThat(result).isPresent();
        assertThat(result.get().getNonceBase64()).isEqualTo("n2");
    }

    @Test
    @DisplayName("get returns empty for non-existent key")
    void get_notFound_returnsEmpty() {
        assertThat(backend.get("does/not/exist")).isEmpty();
    }

    @Test
    @DisplayName("delete removes the key")
    void delete_removesKey() {
        backend.put("kv/data/temp", makeData("n", "c"));
        backend.delete("kv/data/temp");
        assertThat(backend.get("kv/data/temp")).isEmpty();
    }

    @Test
    @DisplayName("delete on non-existent key does not throw")
    void delete_nonExistent_noOp() {
        backend.delete("does/not/exist");
    }

    @Test
    @DisplayName("isDirectory returns true when children exist under prefix")
    void isDirectory_withChildren_returnsTrue() {
        backend.put("jwt/keys/my-key/config", makeData("n", "c"));
        assertThat(backend.isDirectory("jwt/keys/my-key")).isTrue();
    }

    @Test
    @DisplayName("isDirectory returns false when no children exist")
    void isDirectory_noChildren_returnsFalse() {
        assertThat(backend.isDirectory("jwt/keys/nonexistent")).isFalse();
    }

    @Test
    @DisplayName("listDirectory returns only immediate children, stripping prefix")
    void listDirectory_returnsImmediateChildren() {
        backend.put("jwt/keys/rsa/versions/1", makeData("n1", "c1"));
        backend.put("jwt/keys/rsa/versions/2", makeData("n2", "c2"));
        backend.put("jwt/keys/rsa/config", makeData("nc", "cc"));

        List<String> entries = backend.listDirectory("jwt/keys/rsa");
        assertThat(entries).containsExactlyInAnyOrder("versions", "config");
    }

    @Test
    @DisplayName("listDirectory returns empty list for non-existent prefix")
    void listDirectory_nonExistent_returnsEmpty() {
        assertThat(backend.listDirectory("nothing/here")).isEmpty();
    }

    @Test
    @DisplayName("listDirectory does not return keys from sibling prefixes")
    void listDirectory_doesNotLeakSiblings() {
        backend.put("a/b/secret", makeData("n", "c"));
        backend.put("a/c/secret", makeData("n", "c"));

        List<String> entries = backend.listDirectory("a/b");
        assertThat(entries).containsExactly("secret");
    }

    @Test
    @DisplayName("path traversal in key throws StorageException")
    void put_pathTraversal_throws() {
        assertThatThrownBy(() -> backend.put("kv/../etc/passwd", makeData("n", "c")))
                .isInstanceOf(StorageException.class)
                .hasMessageContaining("path traversal");
    }

    @Test
    @DisplayName("blank key throws IllegalArgumentException")
    void put_blankKey_throws() {
        assertThatThrownBy(() -> backend.put("  ", makeData("n", "c")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
