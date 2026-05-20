package tech.yump.vault.storage;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

@Slf4j
public class JdbcStorageBackend implements StorageBackend {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public JdbcStorageBackend(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    void initSchema() {
        log.info("Initializing JDBC storage backend schema...");
        try {
            ClassPathResource schemaResource = new ClassPathResource("db/storage-schema.sql");
            try (Reader reader = new InputStreamReader(schemaResource.getInputStream(), StandardCharsets.UTF_8)) {
                String sql = FileCopyUtils.copyToString(reader);
                jdbcTemplate.execute(sql);
            }
            log.info("JDBC storage schema initialized successfully.");
        } catch (IOException e) {
            throw new StorageException("Failed to load storage schema SQL from classpath.", e);
        }
    }

    @Override
    public void put(String key, EncryptedData data) throws StorageException {
        validateKey(key);
        if (data == null) throw new IllegalArgumentException("Data cannot be null for put operation.");

        String json = serialize(data, key);
        jdbcTemplate.update(
                """
                INSERT INTO vault_storage (key_path, encrypted_data, updated_at)
                VALUES (?, ?::jsonb, now())
                ON CONFLICT (key_path) DO UPDATE
                  SET encrypted_data = EXCLUDED.encrypted_data,
                      updated_at = now()
                """,
                key, json
        );
        log.debug("Stored data for key '{}'", key);
    }

    @Override
    public Optional<EncryptedData> get(String key) throws StorageException {
        validateKey(key);
        List<EncryptedData> results = jdbcTemplate.query(
                "SELECT encrypted_data::text FROM vault_storage WHERE key_path = ?",
                (rs, rowNum) -> deserialize(rs.getString(1), key),
                key
        );
        if (results.isEmpty()) {
            log.debug("No data found for key '{}'", key);
            return Optional.empty();
        }
        log.debug("Retrieved data for key '{}'", key);
        return Optional.of(results.get(0));
    }

    @Override
    public void delete(String key) throws StorageException {
        validateKey(key);
        int rows = jdbcTemplate.update("DELETE FROM vault_storage WHERE key_path = ?", key);
        log.debug("Deleted {} row(s) for key '{}'", rows, key);
    }

    @Override
    public boolean isDirectory(String relativePath) throws StorageException {
        validateKey(relativePath);
        String prefix = ensureTrailingSlash(relativePath);
        // A "directory" exists if any key starts with this prefix
        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(1) FROM vault_storage WHERE key_path LIKE ? ESCAPE '\\'",
                Integer.class,
                escapeLike(prefix) + "%"
        );
        boolean result = count != null && count > 0;
        log.debug("isDirectory('{}') = {}", relativePath, result);
        return result;
    }

    @Override
    public List<String> listDirectory(String relativeDirPath) throws StorageException {
        validateKey(relativeDirPath);
        String prefix = ensureTrailingSlash(relativeDirPath);
        String escapedPrefix = escapeLike(prefix);

        // Return only immediate children: keys that start with prefix but have no further '/' after it
        List<String> results = jdbcTemplate.queryForList(
                """
                SELECT DISTINCT
                  CASE
                    WHEN position('/' IN substring(key_path FROM ?)) > 0
                      THEN substring(key_path FROM 1 FOR ? + position('/' IN substring(key_path FROM ?)) - 1)
                    ELSE key_path
                  END AS entry
                FROM vault_storage
                WHERE key_path LIKE ? ESCAPE '\\'
                ORDER BY entry
                """,
                String.class,
                prefix.length() + 1,   // start of the suffix (1-based)
                prefix.length(),        // characters before the slash
                prefix.length() + 1,   // start of suffix again for nested slash check
                escapedPrefix + "%"
        );

        // Strip the leading prefix to return only the entry name
        List<String> names = results.stream()
                .map(full -> full.substring(prefix.length()))
                .filter(name -> !name.isEmpty())
                .toList();

        log.debug("listDirectory('{}') returned {} entries", relativeDirPath, names.size());
        return names;
    }

    // --- helpers ---

    private void validateKey(String key) {
        if (!StringUtils.hasText(key)) {
            throw new IllegalArgumentException("Key/path cannot be null or blank.");
        }
        if (key.contains("..")) {
            throw new StorageException("Invalid key: path traversal detected in '" + key + "'");
        }
    }

    private String ensureTrailingSlash(String path) {
        return path.endsWith("/") ? path : path + "/";
    }

    // Escape LIKE special characters so key prefixes are treated literally
    private String escapeLike(String value) {
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    private String serialize(EncryptedData data, String key) {
        try {
            return objectMapper.writeValueAsString(data);
        } catch (JsonProcessingException e) {
            throw new StorageException("Failed to serialize EncryptedData for key '" + key + "'", e);
        }
    }

    private EncryptedData deserialize(String json, String key) {
        try {
            return objectMapper.readValue(json, EncryptedData.class);
        } catch (JsonProcessingException e) {
            throw new StorageException("Failed to deserialize EncryptedData for key '" + key + "'", e);
        }
    }
}
