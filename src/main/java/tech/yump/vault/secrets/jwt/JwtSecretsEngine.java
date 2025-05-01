// src/main/java/tech/yump/vault/secrets/jwt/JwtSecretsEngine.java
package tech.yump.vault.secrets.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.core.SealManager;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.crypto.EncryptionService;
import tech.yump.vault.secrets.SecretsEngine;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.storage.EncryptedData;
import tech.yump.vault.storage.StorageBackend;
import tech.yump.vault.storage.StorageException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec; // Needed for JWKS
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap; // Needed for JWKS
import java.util.List; // Needed for JWKS
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors; // Needed for JWKS

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtSecretsEngine implements SecretsEngine {

    private final MssmProperties properties;
    private final EncryptionService encryptionService;
    private final StorageBackend storageBackend;
    private final SealManager sealManager;
    private final AuditHelper auditHelper;
    private final ObjectMapper objectMapper;

    // --- DTOs ---
    private record StoredJwtKeyMaterial(String publicKeyB64, String encryptedPrivateKeyB64) {}
    private record JwtKeyConfig(int currentVersion, Duration rotationPeriod, Instant lastRotationTime) {}
    // Removed PublicKeyInfo DTO as JWKS generation needs more context

    // --- Exceptions ---
    public static class JwtKeyNotFoundException extends SecretsEngineException {
        public JwtKeyNotFoundException(String keyName) {
            super("JWT key configuration not found for name: " + keyName);
        }
        public JwtKeyNotFoundException(String keyName, int version) {
            super(String.format("JWT key material not found for key '%s', version %d", keyName, version));
        }
    }
    // ------------

    private static final String KEY_MATERIAL_PATH_FORMAT = "jwt/keys/%s/versions/%d";
    private static final String KEY_CONFIG_PATH_FORMAT = "jwt/keys/%s/config";
    private static final TypeReference<StoredJwtKeyMaterial> KEY_MATERIAL_TYPE_REF = new TypeReference<>() {}; // For deserialization

    // --- Task 33 Method (generateAndStoreKeyPair) ---
    public void generateAndStoreKeyPair(String keyName, int version) throws SecretsEngineException, VaultSealedException {
        if (sealManager.isSealed()) {
            log.warn("Cannot generate JWT key pair for '{}': Vault is sealed.", keyName);
            throw new VaultSealedException("Vault is sealed");
        }
        log.info("Generating and storing JWT key pair for key '{}', version {}", keyName, version);

        MssmProperties.JwtKeyDefinition keyDefinition = getKeyDefinition(keyName);
        KeyPair keyPair = generateKeyPair(keyDefinition);
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        try {
            byte[] encryptedPrivateKeyNonceAndCiphertext = encryptionService.encrypt(privateKeyBytes);
            log.debug("Successfully encrypted private key for '{}' version {}", keyName, version);

            String publicKeyB64 = Base64.getEncoder().encodeToString(publicKeyBytes);
            String encryptedPrivateKeyB64 = Base64.getEncoder().encodeToString(encryptedPrivateKeyNonceAndCiphertext);
            StoredJwtKeyMaterial keyMaterial = new StoredJwtKeyMaterial(publicKeyB64, encryptedPrivateKeyB64);

            byte[] keyMaterialJsonBytes = objectMapper.writeValueAsBytes(keyMaterial);
            byte[] finalNonceAndCiphertext = encryptionService.encrypt(keyMaterialJsonBytes);
            log.debug("Successfully encrypted key material bundle for '{}' version {}", keyName, version);

            EncryptedData dataToStore = splitAndCreateEncryptedData(finalNonceAndCiphertext, "key material bundle");

            String storagePath = String.format(KEY_MATERIAL_PATH_FORMAT, keyName, version);
            storageBackend.put(storagePath, dataToStore);
            log.info("Successfully stored JWT key material for key '{}', version {} at path '{}'", keyName, version, storagePath);

            // Audit Log for key generation
            auditHelper.logInternalEvent(
                    "jwt_operation", "key_generation", "success", null,
                    Map.of("key_name", keyName, "version", version, "type", keyDefinition.type().name(), "storage_path", storagePath)
            );

        } catch (EncryptionService.EncryptionException e) {
            log.error("Encryption failed during JWT key generation for '{}' version {}: {}", keyName, version, e.getMessage(), e);
            // Audit failure? Maybe not needed here as exception propagates
            throw new SecretsEngineException("Failed to encrypt JWT key material for key: " + keyName, e);
        } catch (JsonProcessingException e) {
            log.error("JSON serialization failed during JWT key generation for '{}' version {}: {}", keyName, version, e.getMessage(), e);
            throw new SecretsEngineException("Failed to serialize JWT key material for key: " + keyName, e);
        } catch (StorageException e) {
            log.error("Storage failed during JWT key generation for '{}' version {}: {}", keyName, version, e.getMessage(), e);
            throw new SecretsEngineException("Failed to store JWT key material for key: " + keyName, e);
        } finally {
            // Ensure private key bytes are cleared from memory
            if (privateKeyBytes != null) {
                java.util.Arrays.fill(privateKeyBytes, (byte) 0);
            }
        }
    }


    // --- Task 34 Methods (Metadata Handling) ---
    private String getKeyConfigPath(String keyName) {
        return String.format(KEY_CONFIG_PATH_FORMAT, keyName);
    }

    private Optional<JwtKeyConfig> readKeyConfig(String keyName) throws SecretsEngineException, VaultSealedException {
        String configPath = getKeyConfigPath(keyName);
        log.debug("Attempting to read JWT key config from path: {}", configPath);

        try {
            Optional<EncryptedData> encryptedDataOptional = storageBackend.get(configPath);

            if (encryptedDataOptional.isEmpty()) {
                log.debug("No JWT key config found at path: {}", configPath);
                return Optional.empty();
            }

            EncryptedData storedData = encryptedDataOptional.get();
            byte[] decryptedBytes = decryptEncryptedData(storedData, "key config");

            JwtKeyConfig keyConfig = objectMapper.readValue(decryptedBytes, JwtKeyConfig.class);
            log.info("Successfully read and decrypted JWT key config for key '{}'", keyName);
            return Optional.of(keyConfig);

        } catch (StorageException e) {
            log.error("Storage error reading JWT key config from path {}: {}", configPath, e.getMessage(), e);
            throw new SecretsEngineException("Failed to read key config from storage for key: " + keyName, e);
        } catch (VaultSealedException e) {
            log.warn("Cannot read JWT key config from path {}: Vault is sealed.", configPath);
            throw e;
        } catch (EncryptionService.EncryptionException e) {
            log.error("Decryption error reading JWT key config from path {}: {}", configPath, e.getMessage(), e);
            throw new SecretsEngineException("Failed to decrypt key config for key: " + keyName, e);
        } catch (IOException e) {
            log.error("Deserialization error reading JWT key config from path {}: {}", configPath, e.getMessage(), e);
            throw new SecretsEngineException("Failed to parse key config data for key: " + keyName, e);
        } catch (IllegalStateException | IllegalArgumentException e) {
            log.error("Error processing stored encrypted data structure for key config path {}: {}", configPath, e.getMessage(), e);
            throw new SecretsEngineException("Failed to process stored key config structure for key: " + keyName, e);
        }
    }

    private void writeKeyConfig(String keyName, JwtKeyConfig config) throws SecretsEngineException, VaultSealedException {
        String configPath = getKeyConfigPath(keyName);
        log.info("Attempting to write JWT key config for key '{}' to path: {}", keyName, configPath);
        Objects.requireNonNull(config, "JwtKeyConfig cannot be null for writing.");

        try {
            byte[] configJsonBytes = objectMapper.writeValueAsBytes(config);
            byte[] finalNonceAndCiphertext = encryptionService.encrypt(configJsonBytes);
            log.debug("Successfully encrypted JWT key config bundle for '{}'", keyName);

            EncryptedData dataToStore = splitAndCreateEncryptedData(finalNonceAndCiphertext, "key config bundle");
            storageBackend.put(configPath, dataToStore);
            log.info("Successfully stored JWT key config for key '{}' at path '{}'", keyName, configPath);

            // Audit Log for config update
            auditHelper.logInternalEvent(
                    "jwt_operation", "key_config_update", "success", null,
                    Map.of("key_name", keyName, "new_current_version", config.currentVersion(), "storage_path", configPath)
            );

        } catch (JsonProcessingException e) {
            log.error("JSON serialization failed during JWT key config write for '{}': {}", keyName, e.getMessage(), e);
            throw new SecretsEngineException("Failed to serialize JWT key config for key: " + keyName, e);
        } catch (VaultSealedException e) {
            log.warn("Cannot write JWT key config for key '{}': Vault is sealed.", keyName);
            throw e;
        } catch (EncryptionService.EncryptionException e) {
            log.error("Encryption failed during JWT key config write for '{}': {}", keyName, e.getMessage(), e);
            throw new SecretsEngineException("Failed to encrypt JWT key config for key: " + keyName, e);
        } catch (StorageException e) {
            log.error("Storage failed during JWT key config write for '{}': {}", keyName, e.getMessage(), e);
            throw new SecretsEngineException("Failed to store JWT key config for key: " + keyName, e);
        }
    }

    // --- Task 35 Methods (Signing) ---

    private StoredJwtKeyMaterial getStoredKeyMaterial(String keyName, int version)
            throws JwtKeyNotFoundException, SecretsEngineException, VaultSealedException {

        String storagePath = String.format(KEY_MATERIAL_PATH_FORMAT, keyName, version);
        log.debug("Attempting to retrieve JWT key material from path: {}", storagePath);

        try {
            Optional<EncryptedData> encryptedBundleOpt = storageBackend.get(storagePath);

            if (encryptedBundleOpt.isEmpty()) {
                log.warn("JWT key material not found at path: {}", storagePath);
                throw new JwtKeyNotFoundException(keyName, version);
            }

            byte[] decryptedJsonBytes = decryptEncryptedData(encryptedBundleOpt.get(), "key material bundle");
            StoredJwtKeyMaterial keyMaterial = objectMapper.readValue(decryptedJsonBytes, KEY_MATERIAL_TYPE_REF);
            log.info("Successfully retrieved and decrypted JWT key material bundle for key '{}', version {}", keyName, version);
            return keyMaterial;

        } catch (StorageException e) {
            log.error("Storage error reading JWT key material from path {}: {}", storagePath, e.getMessage(), e);
            throw new SecretsEngineException("Failed to read key material from storage for key: " + keyName + ", version: " + version, e);
        } catch (VaultSealedException e) {
            log.warn("Cannot read JWT key material from path {}: Vault is sealed.", storagePath);
            throw e;
        } catch (EncryptionService.EncryptionException e) {
            log.error("Decryption error reading JWT key material bundle from path {}: {}", storagePath, e.getMessage(), e);
            throw new SecretsEngineException("Failed to decrypt key material bundle for key: " + keyName + ", version: " + version, e);
        } catch (IOException e) {
            log.error("Deserialization error reading JWT key material bundle from path {}: {}", storagePath, e.getMessage(), e);
            throw new SecretsEngineException("Failed to parse key material data for key: " + keyName + ", version: " + version, e);
        } catch (IllegalStateException | IllegalArgumentException e) {
            log.error("Error processing stored encrypted data structure for key material path {}: {}", storagePath, e.getMessage(), e);
            throw new SecretsEngineException("Failed to process stored key material structure for key: " + keyName + ", version: " + version, e);
        }
    }

    public String signJwt(String keyName, Map<String, Object> claims)
            throws JwtKeyNotFoundException, SecretsEngineException, VaultSealedException {

        if (sealManager.isSealed()) {
            log.warn("Cannot sign JWT for key '{}': Vault is sealed.", keyName);
            throw new VaultSealedException("Vault is sealed");
        }
        log.info("Attempting to sign JWT using key '{}'", keyName);

        JwtKeyConfig keyConfig = readKeyConfig(keyName)
                .orElseThrow(() -> new JwtKeyNotFoundException(keyName));
        int currentVersion = keyConfig.currentVersion();
        log.debug("Current signing version for key '{}' is {}", keyName, currentVersion);

        MssmProperties.JwtKeyDefinition keyDefinition = getKeyDefinition(keyName);
        StoredJwtKeyMaterial keyMaterial = getStoredKeyMaterial(keyName, currentVersion);

        byte[] encryptedPrivateKeyBytes;
        try {
            encryptedPrivateKeyBytes = Base64.getDecoder().decode(keyMaterial.encryptedPrivateKeyB64());
        } catch (IllegalArgumentException e) {
            log.error("Failed to Base64 decode encrypted private key for key '{}', version {}", keyName, currentVersion, e);
            throw new SecretsEngineException("Invalid Base64 format for stored encrypted private key.", e);
        }

        byte[] decryptedPrivateKeyBytes = null;
        PrivateKey privateKey;
        try {
            decryptedPrivateKeyBytes = encryptionService.decrypt(encryptedPrivateKeyBytes);
            log.debug("Successfully decrypted private key for key '{}', version {}", keyName, currentVersion);
            privateKey = reconstructPrivateKey(decryptedPrivateKeyBytes, keyDefinition.type());
        } catch (EncryptionService.EncryptionException e) {
            log.error("Failed to decrypt private key for key '{}', version {}: {}", keyName, currentVersion, e.getMessage(), e);
            throw new SecretsEngineException("Failed to decrypt private key for signing.", e);
        } finally {
            if (decryptedPrivateKeyBytes != null) {
                java.util.Arrays.fill(decryptedPrivateKeyBytes, (byte) 0);
            }
        }

        try {
            Instant now = Instant.now();
            String issuer = "lite-vault"; // Configurable later
            Duration validityDuration = Duration.ofHours(1); // Configurable later
            Instant expiration = now.plus(validityDuration);

            JwtBuilder builder = Jwts.builder()
                    .header()
                    .keyId(keyName + "-" + currentVersion) // kid header
                    .and()
                    .issuer(issuer)
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(expiration))
                    .claims(claims)
                    .signWith(privateKey); // jjwt infers algorithm

            String jwtString = builder.compact();
            log.info("Successfully signed JWT using key '{}', version {}", keyName, currentVersion);
            return jwtString;

        } catch (Exception e) {
            log.error("Failed to build or sign JWT for key '{}', version {}: {}", keyName, currentVersion, e.getMessage(), e);
            throw new SecretsEngineException("Failed to sign JWT.", e);
        }
    }

    // --- Task 37 Method (Rotation) ---

    /**
     * Rotates the specified JWT key by generating a new key pair and updating the configuration.
     *
     * @param keyName The name of the key to rotate.
     * @throws JwtKeyNotFoundException If the key configuration is not found.
     * @throws VaultSealedException    If the vault is sealed.
     * @throws SecretsEngineException  If key generation, storage, or config update fails.
     */
    public void rotateKey(String keyName) throws JwtKeyNotFoundException, VaultSealedException, SecretsEngineException {
        if (sealManager.isSealed()) {
            log.warn("Cannot rotate JWT key '{}': Vault is sealed.", keyName);
            throw new VaultSealedException("Vault is sealed");
        }
        log.info("Attempting to rotate JWT key '{}'", keyName);

        // 1. Read current config
        JwtKeyConfig currentConfig = readKeyConfig(keyName)
                .orElseThrow(() -> {
                    log.warn("Cannot rotate key '{}': Configuration not found.", keyName);
                    return new JwtKeyNotFoundException(keyName);
                });
        int currentVersion = currentConfig.currentVersion();
        int newVersion = currentVersion + 1;
        log.debug("Current version for key '{}' is {}. New version will be {}.", keyName, currentVersion, newVersion);

        try {
            // 2. Generate and store the new key pair (this also audits key generation)
            generateAndStoreKeyPair(keyName, newVersion);
            log.info("Successfully generated and stored new key material for key '{}', version {}", keyName, newVersion);

            // 3. Create and write the updated configuration (this also audits config update)
            JwtKeyConfig newConfig = new JwtKeyConfig(
                    newVersion,
                    currentConfig.rotationPeriod(), // Keep existing rotation period
                    Instant.now() // Update last rotation time
            );
            writeKeyConfig(keyName, newConfig);
            log.info("Successfully updated key configuration for key '{}' to version {}", keyName, newVersion);

            // 4. Audit the successful rotation operation itself
            auditHelper.logInternalEvent(
                    "jwt_operation",
                    "key_rotation",
                    "success",
                    null, // Principal from context or "system"
                    Map.of(
                            "key_name", keyName,
                            "old_version", currentVersion,
                            "new_version", newVersion
                    )
            );
            log.info("Successfully completed rotation for JWT key '{}' to version {}", keyName, newVersion);

        } catch (VaultSealedException | SecretsEngineException e) {
            // Audit failure specifically for rotation attempt
            log.error("Rotation failed for JWT key '{}': {}", keyName, e.getMessage(), e);
            auditHelper.logInternalEvent(
                    "jwt_operation",
                    "key_rotation",
                    "failure",
                    null, // Principal from context or "system"
                    Map.of(
                            "key_name", keyName,
                            "attempted_new_version", newVersion,
                            "error", e.getMessage()
                    )
            );
            // Re-throw the original exception
            throw e;
        }
        // No need for a general catch(Exception) here, let specific exceptions propagate
    }


    // --- Helper Methods ---

    private byte[] decryptEncryptedData(EncryptedData storedData, String dataType) throws EncryptionService.EncryptionException {
        byte[] nonce = storedData.getNonceBytes();
        byte[] ciphertext = storedData.getCiphertextBytes();
        ByteBuffer byteBuffer = ByteBuffer.allocate(nonce.length + ciphertext.length);
        byteBuffer.put(nonce);
        byteBuffer.put(ciphertext);

        byte[] nonceAndCiphertext = byteBuffer.array();
        log.trace("Attempting decryption of {} bytes for {}", nonceAndCiphertext.length, dataType);
        return encryptionService.decrypt(nonceAndCiphertext);
    }

    private EncryptedData splitAndCreateEncryptedData(byte[] nonceAndCiphertext, String dataType) throws SecretsEngineException {
        final int nonceLength = EncryptionService.NONCE_LENGTH_BYTE;
        if (nonceAndCiphertext.length < nonceLength) {
            throw new SecretsEngineException("Encrypted " + dataType + " is too short, indicates an encryption error.");
        }
        ByteBuffer bb = ByteBuffer.wrap(nonceAndCiphertext);
        byte[] nonce = new byte[nonceLength];
        bb.get(nonce);
        byte[] ciphertext = new byte[bb.remaining()];
        bb.get(ciphertext);
        return new EncryptedData(nonce, ciphertext);
    }

    private MssmProperties.JwtKeyDefinition getKeyDefinition(String keyName) throws JwtKeyNotFoundException {
        MssmProperties.JwtProperties jwtProps = properties.jwt();
        if (jwtProps == null || jwtProps.keys() == null) {
            throw new JwtKeyNotFoundException("JWT configuration (mssm.jwt.keys) is missing or empty.");
        }
        MssmProperties.JwtKeyDefinition keyDefinition = jwtProps.keys().get(keyName);
        if (keyDefinition == null) {
            throw new JwtKeyNotFoundException(keyName);
        }
        return keyDefinition;
    }

    private KeyPair generateKeyPair(MssmProperties.JwtKeyDefinition keyDefinition) throws SecretsEngineException {
        try {
            KeyPairGenerator keyPairGenerator;
            String algorithm;

            switch (keyDefinition.type()) {
                case RSA:
                    algorithm = "RSA";
                    keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
                    keyPairGenerator.initialize(keyDefinition.size());
                    log.debug("Generating RSA key pair with size {}", keyDefinition.size());
                    break;
                case EC:
                    algorithm = "EC";
                    keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
                    ECGenParameterSpec ecSpec = new ECGenParameterSpec(keyDefinition.curve());
                    keyPairGenerator.initialize(ecSpec, new SecureRandom());
                    log.debug("Generating EC key pair with curve {}", keyDefinition.curve());
                    break;
                default:
                    throw new SecretsEngineException("Unsupported JWT key type: " + keyDefinition.type());
            }
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            log.error("Failed to generate {} key pair: {}", keyDefinition.type(), e.getMessage(), e);
            throw new SecretsEngineException("Failed to initialize key pair generator for type " + keyDefinition.type(), e);
        }
    }

    private PrivateKey reconstructPrivateKey(byte[] pkcs8Bytes, MssmProperties.JwtKeyType keyType) throws SecretsEngineException {
        try {
            String algorithm = switch (keyType) {
                case RSA -> "RSA";
                case EC -> "EC";
            };
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Failed to reconstruct {} private key from stored bytes: {}", keyType, e.getMessage(), e);
            throw new SecretsEngineException("Failed to reconstruct private key for signing.", e);
        }
    }

    // --- Task 36 Method (JWKS - Placeholder, needs full implementation) ---
    // public Map<String, Object> getJsonWebKeySet(String keyName) throws SecretsEngineException, VaultSealedException {
    //     log.info("Retrieving JWKS for key '{}'", keyName);
    //     // 1. Read config to find current version (and potentially previous versions)
    //     // 2. Loop through relevant versions:
    //     //    a. Get StoredJwtKeyMaterial for the version
    //     //    b. Decode public key bytes
    //     //    c. Reconstruct PublicKey object
    //     //    d. Convert PublicKey to JWK format (RFC 7517) - requires careful mapping based on key type (RSA/EC)
    //     //    e. Add 'kid' (key ID, e.g., keyName + "-" + version) and 'alg'
    //     // 3. Assemble JWKs into a JWK Set JSON structure: {"keys": [jwk1, jwk2, ...]}
    //     // This requires a library or manual implementation of JWK formatting.
    //     throw new UnsupportedOperationException("JWKS endpoint not fully implemented yet.");
    // }
}