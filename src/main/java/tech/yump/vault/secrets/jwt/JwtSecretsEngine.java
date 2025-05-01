package tech.yump.vault.secrets.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
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
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    private static final String VERSIONS_DIR_FORMAT = "jwt/keys/%s/versions";
    private static final Pattern VERSION_FILE_PATTERN = Pattern.compile("^(\\d+)\\.json$");

    // --- DTOs ---
    record StoredJwtKeyMaterial(String publicKeyB64, String encryptedPrivateKeyB64) {}
    record JwtKeyConfig(int currentVersion, Duration rotationPeriod, Instant lastRotationTime) {}
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
    static final TypeReference<StoredJwtKeyMaterial> KEY_MATERIAL_TYPE_REF = new TypeReference<>() {}; // For deserialization

    // --- generateAndStoreKeyPair ---
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
            String keyId = keyName + "-" + currentVersion; // kid header

            JwtBuilder builder = Jwts.builder()
                    .header()
                    .keyId(keyId) // kid header
                    .and()
                    .issuer(issuer)
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(expiration))
                    .claims(claims)
                    .signWith(privateKey); // jjwt infers algorithm

            String jwtString = builder.compact();
            log.info("Successfully signed JWT using key '{}', version {}", keyName, currentVersion);

            // --- Audit Log for successful signing (Task 38) ---
            auditHelper.logInternalEvent(
                    "jwt_operation",
                    "sign_jwt",
                    "success",
                    null, // Principal from context or "system"
                    Map.of(
                            "key_name", keyName,
                            "key_version", currentVersion,
                            "key_id", keyId,
                            "issuer", issuer
                    )
            );
            // --- End Audit Log ---

            return jwtString;

        } catch (Exception e) {
            log.error("Failed to build or sign JWT for key '{}', version {}: {}", keyName, currentVersion, e.getMessage(), e);

            // --- Audit Log for signing failure (Task 38) ---
            auditHelper.logInternalEvent(
                    "jwt_operation",
                    "sign_jwt",
                    "failure",
                    null, // Principal from context or "system"
                    Map.of(
                            "key_name", keyName,
                            "key_version", currentVersion,
                            "error", e.getMessage()
                    )
            );
            // --- End Audit Log ---

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

        int currentVersion;
        int newVersion;
        Duration rotationPeriod;

        MssmProperties.JwtKeyDefinition keyDefinition = getKeyDefinition(keyName);
        rotationPeriod = keyDefinition.rotationPeriod() != null ? keyDefinition.rotationPeriod() : Duration.ZERO;

        // 1. Read current config
        Optional<JwtKeyConfig> currentConfigOpt = readKeyConfig(keyName);

        if (currentConfigOpt.isPresent()) {
            currentVersion = currentConfigOpt.get().currentVersion();
            newVersion = currentVersion + 1;
            log.debug("Existing config found for key '{}'. Current version is {}. New version will be {}.", keyName, currentVersion, newVersion);
        } else {
            currentVersion = 0;
            newVersion = 1;
            log.debug("No existing config found for key '{}'. Performing initial generation for version {}.", keyName, newVersion);
        }

        try {
            // 2. Generate and store the new key pair (this also audits key generation)
            generateAndStoreKeyPair(keyName, newVersion);
            log.info("Successfully generated and stored new key material for key '{}', version {}", keyName, newVersion);

            // 3. Create and write the updated configuration (this also audits config update)
            JwtKeyConfig newConfig = new JwtKeyConfig(
                    newVersion,
                    rotationPeriod,
                    Instant.now()
            );
            writeKeyConfig(keyName, newConfig);
            log.info("Successfully {} key configuration for key '{}' to version {}",
                    (currentVersion == 0 ? "created initial" : "updated"), keyName, newVersion);

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
        MssmProperties.SecretsProperties secretsProps = properties.secrets();
        if (secretsProps == null) {
            throw new JwtKeyNotFoundException("Secrets configuration (mssm.secrets) is missing.");
        }
        MssmProperties.JwtProperties jwtProps = secretsProps.jwt();
        if (jwtProps == null || jwtProps.keys() == null) {
            throw new JwtKeyNotFoundException("JWT configuration (mssm.secrets.jwt.keys) is missing or empty.");
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
                    String curveNameFromConfig = keyDefinition.curve();
                    String javaCurveName = switch (curveNameFromConfig) {
                        case "P-256" -> "secp256r1";
                        case "P-384" -> "secp384r1"; // Add if you support P-384
                        case "P-521" -> "secp521r1"; // Add if you support P-521
                        default -> throw new InvalidAlgorithmParameterException("Unsupported or unknown curve name configured: " + curveNameFromConfig);
                    };
                    ECGenParameterSpec ecSpec = new ECGenParameterSpec(javaCurveName);
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

    /**
     * Reconstructs a PublicKey object from its X.509 encoded byte representation.
     *
     * @param x509Bytes The X.509 encoded public key bytes.
     * @param keyType   The type of the key (RSA or EC).
     * @return The reconstructed PublicKey object.
     * @throws SecretsEngineException If the key reconstruction fails due to invalid encoding or unsupported algorithm.
     */
    private PublicKey reconstructPublicKey(byte[] x509Bytes, MssmProperties.JwtKeyType keyType) throws SecretsEngineException {
        log.debug("Attempting to reconstruct {} public key from X.509 bytes", keyType);
        try {
            String algorithm = switch (keyType) {
                case RSA -> "RSA";
                case EC -> "EC";
                // No default needed as JwtKeyType enum is exhaustive for supported types
            };
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509Bytes);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            log.debug("Successfully reconstructed {} public key", keyType);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("Failed to reconstruct {} public key from stored bytes: {}", keyType, e.getMessage(), e);
            throw new SecretsEngineException("Failed to reconstruct public key.", e);
        }
    }

    /**
     * Retrieves the JSON Web Key Set (JWKS) containing the public keys for *all*
     * valid, stored versions of the specified key name.
     *
     * @param keyName The name of the JWT key.
     * @return A Map representing the JWK Set JSON structure.
     * @throws JwtKeyNotFoundException If the key configuration is not found (needed for type info) or no valid versions exist.
     * @throws VaultSealedException    If the vault is sealed.
     * @throws SecretsEngineException  If there's an error during key retrieval, reconstruction, or JWK generation.
     */
    public Map<String, Object> getJwks(String keyName) throws SecretsEngineException, VaultSealedException {
        if (sealManager.isSealed()) {
            log.warn("Cannot retrieve JWKS for key '{}': Vault is sealed.", keyName);
            throw new VaultSealedException("Vault is sealed");
        }
        log.info("Retrieving JWKS for all versions of key '{}'", keyName);
        String operation = "get_jwks"; // For audit context

        List<JWK> jwkList = new ArrayList<>();
        List<Integer> includedVersions = new ArrayList<>(); // For audit log

        try {
            // 1. Get Key Definition (needed for type, algorithm) - Throws if keyName invalid
            MssmProperties.JwtKeyDefinition keyDefinition = getKeyDefinition(keyName);
            JWSAlgorithm commonAlgorithm = determineJwsAlgorithm(keyDefinition); // Determine algorithm once

            // 2. Determine Storage Path for Versions
            // Need the base storage path to resolve relative paths correctly
            String storageBasePath = properties.storage().filesystem().path(); // Get base path from properties
            if (storageBasePath == null || storageBasePath.isBlank()) {
                throw new SecretsEngineException("Filesystem storage path is not configured.");
            }
            Path versionsDirectoryPath = Paths.get(storageBasePath, String.format(VERSIONS_DIR_FORMAT, keyName));
            log.debug("Looking for key versions in directory: {}", versionsDirectoryPath);

            if (!Files.isDirectory(versionsDirectoryPath)) {
                log.warn("Versions directory not found for key '{}' at path: {}. Returning empty JWKSet.", keyName, versionsDirectoryPath);
                // Depending on requirements, you might throw JwtKeyNotFoundException here
                // Or return an empty set if a key *could* exist but has no versions yet.
                // Let's throw for consistency with finding *no* versions.
                throw new JwtKeyNotFoundException("No key versions found for key: " + keyName);
            }

            // 3. Iterate through version files in the storage directory
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(versionsDirectoryPath, "*.json")) {
                for (Path versionFilePath : stream) {
                    String filename = versionFilePath.getFileName().toString();
                    Matcher matcher = VERSION_FILE_PATTERN.matcher(filename);

                    if (matcher.matches()) {
                        int version = Integer.parseInt(matcher.group(1));
                        log.debug("Found potential version file: {}, extracted version: {}", filename, version);
                        String keyId = keyName + "-" + version;

                        try {
                            // 4. Get Key Material for this Version
                            StoredJwtKeyMaterial keyMaterial = getStoredKeyMaterial(keyName, version); // Throws if specific version missing/error

                            // 5. Decode Public Key Bytes
                            byte[] publicKeyBytes = Base64.getDecoder().decode(keyMaterial.publicKeyB64());

                            // 6. Reconstruct PublicKey
                            PublicKey publicKey = reconstructPublicKey(publicKeyBytes, keyDefinition.type());

                            // 7. Convert PublicKey to JWK
                            JWK jwk = convertPublicKeyToJwk(publicKey, keyDefinition.type(), keyId, commonAlgorithm);

                            // 8. Add to list
                            jwkList.add(jwk);
                            includedVersions.add(version);
                            log.debug("Successfully processed and added JWK for key '{}', version {}", keyName, version);

                        } catch (JwtKeyNotFoundException e) {
                            log.warn("Key material not found for key '{}', version {}. Skipping this version for JWKS.", keyName, version, e);
                            // Continue to next version
                        } catch (IllegalArgumentException e) {
                            log.warn("Failed to Base64 decode public key for key '{}', version {}. Skipping this version for JWKS.", keyName, version, e);
                            // Continue to next version
                        } catch (SecretsEngineException e) {
                            log.warn("Failed to reconstruct or convert public key for key '{}', version {}. Skipping this version for JWKS.", keyName, version, e);
                            // Continue to next version
                        }
                        // Let VaultSealedException propagate upwards immediately if it occurs during getStoredKeyMaterial
                    } else {
                        log.warn("Skipping file '{}' in versions directory for key '{}' as it does not match expected pattern.", filename, keyName);
                    }
                }
            } catch (IOException e) {
                log.error("Error listing version files in directory {}: {}", versionsDirectoryPath, e.getMessage(), e);
                throw new SecretsEngineException("Failed to list key versions from storage for key: " + keyName, e);
            }

            // 9. Check if any keys were found
            if (jwkList.isEmpty()) {
                log.warn("No valid key versions found or processed for key '{}'. Returning empty JWKSet.", keyName);
                // Throw exception as per earlier decision
                throw new JwtKeyNotFoundException("No valid key versions found for key: " + keyName);
            }

            // 10. Assemble JWK Set
            // Optional: Sort JWKs by version number (descending is common)
            jwkList.sort(Comparator.comparing(jwk -> {
                Matcher m = Pattern.compile(".*-(\\d+)$").matcher(jwk.getKeyID());
                return m.matches() ? -Integer.parseInt(m.group(1)) : 0; // Negative for descending
            }));
            JWKSet jwkSet = new JWKSet(jwkList);

            // 11. Convert to Map and Audit
            Map<String, Object> jwksMap = jwkSet.toJSONObject();
            log.info("Successfully generated JWKS for key '{}', including versions: {}", keyName, includedVersions);
            auditHelper.logInternalEvent(
                    "jwt_operation", operation, "success", null,
                    Map.of("key_name", keyName, "versions_included", includedVersions) // Log included versions
            );
            return jwksMap;

        } catch (JwtKeyNotFoundException | VaultSealedException e) {
            // Log and rethrow specific exceptions (already logged where they occur)
            auditHelper.logInternalEvent(
                    "jwt_operation", operation, "failure", null,
                    Map.of("key_name", keyName, "error", e.getMessage())
            );
            throw e;
        } catch (SecretsEngineException e) {
            // Log and rethrow internal engine errors (already logged where they occur)
            auditHelper.logInternalEvent(
                    "jwt_operation", operation, "failure", null,
                    Map.of("key_name", keyName, "error", e.getMessage())
            );
            throw e;
        } catch (Exception e) {
            // Catch unexpected errors
            log.error("Unexpected error retrieving JWKS for key '{}': {}", keyName, e.getMessage(), e);
            auditHelper.logInternalEvent(
                    "jwt_operation", operation, "failure", null,
                    Map.of("key_name", keyName, "error", "Unexpected: " + e.getMessage())
            );
            throw new SecretsEngineException("An unexpected error occurred while generating JWKS for key: " + keyName, e);
        }
    }


    // --- Helper Methods (Add these if they don't exist) ---

    /**
     * Determines the appropriate JWS algorithm based on the key definition.
     *
     * @param keyDefinition The definition of the key.
     * @return The corresponding JWSAlgorithm.
     * @throws SecretsEngineException if the key type/parameters are unsupported for JWS.
     */
    private JWSAlgorithm determineJwsAlgorithm(MssmProperties.JwtKeyDefinition keyDefinition) throws SecretsEngineException {
        return switch (keyDefinition.type()) {
            case RSA -> {
                // We assume RS256 for RSA >= 2048 as a common default.
                // Could be refined based on size if needed (RS384, RS512)
                if (keyDefinition.size() >= 2048) {
                    yield JWSAlgorithm.RS256;
                } else {
                    throw new SecretsEngineException("Unsupported RSA key size for JWS: " + keyDefinition.size());
                }
            }
            case EC -> switch (keyDefinition.curve()) {
                // Map NIST curve names to JWA algorithm names
                case "P-256" -> JWSAlgorithm.ES256;
                case "P-384" -> JWSAlgorithm.ES384;
                case "P-521" -> JWSAlgorithm.ES512;
                default -> throw new SecretsEngineException("Unsupported EC curve for JWS: " + keyDefinition.curve());
            };
            // Default case should not be reachable if config validation is correct
            // default -> throw new SecretsEngineException("Unsupported key type for JWS: " + keyDefinition.type());
        };
    }

    /**
     * Converts a java.security.PublicKey into a com.nimbusds.jose.jwk.JWK object.
     *
     * @param publicKey The public key to convert.
     * @param keyType   The type of the key (RSA or EC).
     * @param keyId     The desired Key ID (kid) for the JWK.
     * @param algorithm The JWS algorithm associated with this key.
     * @return The generated JWK object.
     * @throws SecretsEngineException If the key type is unsupported or conversion fails.
     */
    private JWK convertPublicKeyToJwk(PublicKey publicKey, MssmProperties.JwtKeyType keyType, String keyId, Algorithm algorithm) throws SecretsEngineException {
        try {
            switch (keyType) {
                case RSA:
                    if (!(publicKey instanceof RSAPublicKey rsaPublicKey)) {
                        throw new SecretsEngineException("Expected RSAPublicKey but got " + publicKey.getClass().getName());
                    }
                    return new RSAKey.Builder(rsaPublicKey)
                            .keyUse(KeyUse.SIGNATURE) // 'use' parameter: sig (signing/verification)
                            .algorithm(algorithm)     // 'alg' parameter (e.g., RS256)
                            .keyID(keyId)             // 'kid' parameter
                            .build();
                case EC:
                    if (!(publicKey instanceof ECPublicKey ecPublicKey)) {
                        throw new SecretsEngineException("Expected ECPublicKey but got " + publicKey.getClass().getName());
                    }
                    // Nimbus requires the Curve object, derive it from the key params
                    Curve curve = Curve.forECParameterSpec(ecPublicKey.getParams());
                    if (curve == null) {
                        throw new SecretsEngineException("Could not determine Nimbus Curve for EC key parameters.");
                    }
                    return new ECKey.Builder(curve, ecPublicKey)
                            .keyUse(KeyUse.SIGNATURE)
                            .algorithm(algorithm)     // 'alg' parameter (e.g., ES256)
                            .keyID(keyId)
                            .build();
                default:
                    // Should not happen due to enum constraints
                    throw new SecretsEngineException("Unsupported key type for JWK conversion: " + keyType);
            }
        } catch (Exception e) { // Catch potential Nimbus library exceptions too
            log.error("Failed to convert {} public key (kid: {}) to JWK: {}", keyType, keyId, e.getMessage(), e);
            throw new SecretsEngineException("Failed to convert public key to JWK format.", e);
        }
    }

}