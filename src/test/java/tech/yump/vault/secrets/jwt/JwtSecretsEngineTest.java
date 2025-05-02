package tech.yump.vault.secrets.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tech.yump.vault.audit.AuditHelper;
import tech.yump.vault.config.MssmProperties;
import tech.yump.vault.config.MssmProperties.JwtKeyDefinition;
import tech.yump.vault.config.MssmProperties.JwtKeyType;
import tech.yump.vault.config.MssmProperties.JwtProperties;
import tech.yump.vault.core.SealManager;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.crypto.EncryptionService;
import tech.yump.vault.crypto.EncryptionService.EncryptionException;
import tech.yump.vault.secrets.SecretsEngineException;
import tech.yump.vault.secrets.jwt.JwtSecretsEngine.JwtKeyConfig;
import tech.yump.vault.secrets.jwt.JwtSecretsEngine.JwtKeyNotFoundException;
import tech.yump.vault.secrets.jwt.JwtSecretsEngine.StoredJwtKeyMaterial;
import tech.yump.vault.storage.EncryptedData;
import tech.yump.vault.storage.StorageBackend;
import tech.yump.vault.storage.StorageException;
import org.assertj.core.api.InstanceOfAssertFactories;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List; // <-- Added import
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.startsWith; // <-- Added import


@ExtendWith(MockitoExtension.class)
class JwtSecretsEngineTest {

    @Mock
    private MssmProperties properties;
    @Mock
    private EncryptionService encryptionService;
    @Mock
    private StorageBackend storageBackend;
    @Mock
    private SealManager sealManager;
    @Mock
    private AuditHelper auditHelper;
    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private JwtSecretsEngine jwtSecretsEngine;

    @BeforeEach
    void setUp() {
        // Default behavior: Vault is unsealed for most tests
        lenient().when(sealManager.isSealed()).thenReturn(false);

        // You can add other common mock setups here if needed later
    }

    // Inside JwtSecretsEngineTest class...

    // --- Task 3.2: generateAndStoreKeyPair Tests ---

    @Test
    @DisplayName("generateAndStoreKeyPair: Success RSA")
    void generateAndStoreKeyPair_rsaSuccess() throws Exception { // Allow checked exceptions from mocks/objectMapper
        // Arrange
        String keyName = "test-rsa-key";
        int version = 1;
        String expectedStoragePath = String.format("jwt/keys/%s/versions/%d", keyName, version);

        // Mock Key Definition (RSA)
        JwtKeyDefinition rsaDefinition = new JwtKeyDefinition(JwtKeyType.RSA, 2048, null, null);
        Map<String, JwtKeyDefinition> keysMap = new HashMap<>();
        keysMap.put(keyName, rsaDefinition);

        MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);
        JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
        when(properties.secrets()).thenReturn(secretsPropertiesMock);
        when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);
        when(jwtPropertiesMock.keys()).thenReturn(keysMap);

        // Mock EncryptionService
        byte[] dummyEncryptedPrivateKey = "encryptedPrivateKey".getBytes();
        byte[] dummyEncryptedBundle = "encryptedBundle".getBytes();
        // Need to combine nonce + ciphertext for mock return
        byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE]; // Use actual nonce length
        byte[] ciphertextPriv = "privCipher".getBytes();
        byte[] ciphertextBundle = "bundleCipher".getBytes();
        ByteBuffer bbPriv = ByteBuffer.allocate(nonce.length + ciphertextPriv.length).put(nonce).put(ciphertextPriv);
        ByteBuffer bbBundle = ByteBuffer.allocate(nonce.length + ciphertextBundle.length).put(nonce).put(ciphertextBundle);
        byte[] encryptedPrivateKeyNonceAndCiphertext = bbPriv.array();
        byte[] finalNonceAndCiphertext = bbBundle.array();

        when(encryptionService.encrypt(any(byte[].class)))
                .thenReturn(encryptedPrivateKeyNonceAndCiphertext) // First call (private key)
                .thenReturn(finalNonceAndCiphertext);             // Second call (bundle)

        // Mock ObjectMapper
        byte[] dummyJsonBytes = "{\"publicKeyB64\":\"...\",\"encryptedPrivateKeyB64\":\"...\"}".getBytes();
        when(objectMapper.writeValueAsBytes(any(JwtSecretsEngine.StoredJwtKeyMaterial.class))).thenReturn(dummyJsonBytes);

        // Mock StorageBackend (put returns void)
        // No explicit mock needed unless verifying interactions

        // Act
        assertDoesNotThrow(() -> jwtSecretsEngine.generateAndStoreKeyPair(keyName, version));

        // Assert
        // 1. Verify encryption calls
        ArgumentCaptor<byte[]> encryptCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(encryptionService, times(2)).encrypt(encryptCaptor.capture());
        List<byte[]> encryptedArgs = encryptCaptor.getAllValues();
        // First call should be the raw private key (hard to verify exact bytes without real generation)
        // Second call should be the JSON bytes
        assertArrayEquals(dummyJsonBytes, encryptedArgs.get(1), "Second encrypt call should use JSON bytes");

        // 2. Verify ObjectMapper call
        ArgumentCaptor<JwtSecretsEngine.StoredJwtKeyMaterial> materialCaptor = ArgumentCaptor.forClass(JwtSecretsEngine.StoredJwtKeyMaterial.class);
        verify(objectMapper, times(1)).writeValueAsBytes(materialCaptor.capture());
        JwtSecretsEngine.StoredJwtKeyMaterial capturedMaterial = materialCaptor.getValue();
        assertThat(capturedMaterial.publicKeyB64()).isNotBlank(); // Public key should be generated and encoded
        assertThat(capturedMaterial.encryptedPrivateKeyB64())
                .isEqualTo(Base64.getEncoder().encodeToString(encryptedPrivateKeyNonceAndCiphertext)); // Should match first encryption result

        // 3. Verify StorageBackend call
        ArgumentCaptor<EncryptedData> storageCaptor = ArgumentCaptor.forClass(EncryptedData.class);
        verify(storageBackend, times(1)).put(eq(expectedStoragePath), storageCaptor.capture());
        EncryptedData storedData = storageCaptor.getValue();
        // Verify the stored data corresponds to the *second* encryption result (the bundle)
        ByteBuffer expectedBundleBuffer = ByteBuffer.wrap(finalNonceAndCiphertext);
        byte[] expectedNonce = new byte[EncryptionService.NONCE_LENGTH_BYTE];
        expectedBundleBuffer.get(expectedNonce);
        byte[] expectedCiphertext = new byte[expectedBundleBuffer.remaining()];
        expectedBundleBuffer.get(expectedCiphertext);
        assertArrayEquals(expectedNonce, storedData.getNonceBytes(), "Stored nonce should match bundle encryption");
        assertArrayEquals(expectedCiphertext, storedData.getCiphertextBytes(), "Stored ciphertext should match bundle encryption");


        // 4. Verify Audit Log call
        ArgumentCaptor<Map<String, Object>> auditDataCaptor = ArgumentCaptor.forClass(Map.class);
        verify(auditHelper, times(1)).logInternalEvent(
                eq("jwt_operation"),
                eq("key_generation"),
                eq("success"),
                isNull(), // Principal is null for internal events
                auditDataCaptor.capture()
        );
        Map<String, Object> auditData = auditDataCaptor.getValue();
        assertThat(auditData)
                .containsEntry("key_name", keyName)
                .containsEntry("version", version)
                .containsEntry("type", JwtKeyType.RSA.name())
                .containsEntry("storage_path", expectedStoragePath);
    }

    @Test
    @DisplayName("generateAndStoreKeyPair: Success EC")
    void generateAndStoreKeyPair_ecSuccess() throws Exception {
        // Arrange
        String keyName = "test-ec-key";
        int version = 1;
        String expectedStoragePath = String.format("jwt/keys/%s/versions/%d", keyName, version);

        // Mock Key Definition (EC)
        JwtKeyDefinition ecDefinition = new JwtKeyDefinition(JwtKeyType.EC, null, "P-256", null);
        Map<String, JwtKeyDefinition> keysMap = new HashMap<>();
        keysMap.put(keyName, ecDefinition);

        MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);
        JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
        when(properties.secrets()).thenReturn(secretsPropertiesMock);
        when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);
        when(jwtPropertiesMock.keys()).thenReturn(keysMap);

        // Mock EncryptionService (same logic as RSA test)
        byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE];
        byte[] ciphertextPriv = "ecPrivCipher".getBytes();
        byte[] ciphertextBundle = "ecBundleCipher".getBytes();
        ByteBuffer bbPriv = ByteBuffer.allocate(nonce.length + ciphertextPriv.length).put(nonce).put(ciphertextPriv);
        ByteBuffer bbBundle = ByteBuffer.allocate(nonce.length + ciphertextBundle.length).put(nonce).put(ciphertextBundle);
        byte[] encryptedPrivateKeyNonceAndCiphertext = bbPriv.array();
        byte[] finalNonceAndCiphertext = bbBundle.array();

        when(encryptionService.encrypt(any(byte[].class)))
                .thenReturn(encryptedPrivateKeyNonceAndCiphertext)
                .thenReturn(finalNonceAndCiphertext);

        // Mock ObjectMapper (same logic as RSA test)
        byte[] dummyJsonBytes = "{\"publicKeyB64\":\"ec...\",\"encryptedPrivateKeyB64\":\"ec...\"}".getBytes();
        when(objectMapper.writeValueAsBytes(any(JwtSecretsEngine.StoredJwtKeyMaterial.class))).thenReturn(dummyJsonBytes);

        // Act
        assertDoesNotThrow(() -> jwtSecretsEngine.generateAndStoreKeyPair(keyName, version));

        // Assert
        // (Verifications are largely the same as the RSA test, just check the audit log type)
        verify(encryptionService, times(2)).encrypt(any(byte[].class));
        verify(objectMapper, times(1)).writeValueAsBytes(any(JwtSecretsEngine.StoredJwtKeyMaterial.class));
        verify(storageBackend, times(1)).put(eq(expectedStoragePath), any(EncryptedData.class));

        // Verify Audit Log call (check type is EC)
        ArgumentCaptor<Map<String, Object>> auditDataCaptor = ArgumentCaptor.forClass(Map.class);
        verify(auditHelper, times(1)).logInternalEvent(
                eq("jwt_operation"),
                eq("key_generation"),
                eq("success"),
                isNull(),
                auditDataCaptor.capture()
        );
        Map<String, Object> auditData = auditDataCaptor.getValue();
        assertThat(auditData)
                .containsEntry("key_name", keyName)
                .containsEntry("version", version)
                .containsEntry("type", JwtKeyType.EC.name()) // Check for EC type
                .containsEntry("storage_path", expectedStoragePath);
    }

    @Test
    @DisplayName("generateAndStoreKeyPair: Vault Sealed")
    void generateAndStoreKeyPair_vaultSealed() throws JsonProcessingException {
        // Arrange
        String keyName = "test-key";
        int version = 1;
        when(sealManager.isSealed()).thenReturn(true); // Override @BeforeEach

        // Act & Assert
        VaultSealedException exception = assertThrows(VaultSealedException.class, () -> {
            jwtSecretsEngine.generateAndStoreKeyPair(keyName, version);
        });
        assertEquals("Vault is sealed", exception.getMessage());

        // Verify no interactions with other services occurred
        verify(encryptionService, never()).encrypt(any());
        verify(objectMapper, never()).writeValueAsBytes(any());
        verify(storageBackend, never()).put(anyString(), any());
        verify(auditHelper, never()).logInternalEvent(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("generateAndStoreKeyPair: Encryption Exception")
    void generateAndStoreKeyPair_encryptionException() throws Exception {
        // Arrange
        String keyName = "test-key";
        int version = 1;

        // Mock Key Definition (need this before encryption happens)
        JwtKeyDefinition rsaDefinition = new JwtKeyDefinition(JwtKeyType.RSA, 2048, null, null);
        Map<String, JwtKeyDefinition> keysMap = new HashMap<>();
        keysMap.put(keyName, rsaDefinition);

        MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);
        JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
        when(properties.secrets()).thenReturn(secretsPropertiesMock);
        when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);
        when(jwtPropertiesMock.keys()).thenReturn(keysMap);

        // Mock EncryptionService to throw
        EncryptionException thrownException = new EncryptionException("Encryption failed test");
        when(encryptionService.encrypt(any(byte[].class))).thenThrow(thrownException);

        // Act & Assert
        SecretsEngineException exception = assertThrows(SecretsEngineException.class, () -> {
            jwtSecretsEngine.generateAndStoreKeyPair(keyName, version);
        });
        assertEquals("Failed to encrypt JWT key material for key: " + keyName, exception.getMessage());
        assertEquals(thrownException, exception.getCause());

        // Verify audit log was NOT called for success
        verify(auditHelper, never()).logInternalEvent(any(), any(), eq("success"), any(), any());
        // Verify storage was NOT called
        verify(storageBackend, never()).put(anyString(), any());
    }

    @Test
    @DisplayName("generateAndStoreKeyPair: Storage Exception")
    void generateAndStoreKeyPair_storageException() throws Exception {
        // Arrange
        String keyName = "test-key";
        int version = 1;
        String expectedStoragePath = String.format("jwt/keys/%s/versions/%d", keyName, version);

        // Mock Key Definition
        JwtKeyDefinition rsaDefinition = new JwtKeyDefinition(JwtKeyType.RSA, 2048, null, null);
        Map<String, JwtKeyDefinition> keysMap = new HashMap<>();
        keysMap.put(keyName, rsaDefinition);

        MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);
        JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
        when(properties.secrets()).thenReturn(secretsPropertiesMock);
        when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);
        when(jwtPropertiesMock.keys()).thenReturn(keysMap);

        // Mock EncryptionService (successful calls)
        byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE];
        byte[] ciphertextPriv = "privCipher".getBytes();
        byte[] ciphertextBundle = "bundleCipher".getBytes();
        ByteBuffer bbPriv = ByteBuffer.allocate(nonce.length + ciphertextPriv.length).put(nonce).put(ciphertextPriv);
        ByteBuffer bbBundle = ByteBuffer.allocate(nonce.length + ciphertextBundle.length).put(nonce).put(ciphertextBundle);
        byte[] encryptedPrivateKeyNonceAndCiphertext = bbPriv.array();
        byte[] finalNonceAndCiphertext = bbBundle.array();
        when(encryptionService.encrypt(any(byte[].class)))
                .thenReturn(encryptedPrivateKeyNonceAndCiphertext)
                .thenReturn(finalNonceAndCiphertext);

        // Mock ObjectMapper (successful call)
        byte[] dummyJsonBytes = "{}".getBytes();
        when(objectMapper.writeValueAsBytes(any(JwtSecretsEngine.StoredJwtKeyMaterial.class))).thenReturn(dummyJsonBytes);

        // Mock StorageBackend to throw
        StorageException thrownException = new StorageException("Storage failed test");
        doThrow(thrownException).when(storageBackend).put(eq(expectedStoragePath), any(EncryptedData.class));

        // Act & Assert
        SecretsEngineException exception = assertThrows(SecretsEngineException.class, () -> {
            jwtSecretsEngine.generateAndStoreKeyPair(keyName, version);
        });
        assertEquals("Failed to store JWT key material for key: " + keyName, exception.getMessage());
        assertEquals(thrownException, exception.getCause());

        // Verify audit log was NOT called for success
        verify(auditHelper, never()).logInternalEvent(any(), any(), eq("success"), any(), any());
    }

    @Test
    @DisplayName("generateAndStoreKeyPair: JSON Processing Exception")
    void generateAndStoreKeyPair_jsonProcessingException() throws Exception {
        // Arrange
        String keyName = "test-key";
        int version = 1;

        // Mock Key Definition
        JwtKeyDefinition rsaDefinition = new JwtKeyDefinition(JwtKeyType.RSA, 2048, null, null);
        Map<String, JwtKeyDefinition> keysMap = new HashMap<>();
        keysMap.put(keyName, rsaDefinition);

        MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);
        JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
        when(properties.secrets()).thenReturn(secretsPropertiesMock);
        when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);
        when(jwtPropertiesMock.keys()).thenReturn(keysMap);

        // Mock EncryptionService (successful first call)
        byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE];
        byte[] ciphertextPriv = "privCipher".getBytes();
        ByteBuffer bbPriv = ByteBuffer.allocate(nonce.length + ciphertextPriv.length).put(nonce).put(ciphertextPriv);
        byte[] encryptedPrivateKeyNonceAndCiphertext = bbPriv.array();
        when(encryptionService.encrypt(any(byte[].class))).thenReturn(encryptedPrivateKeyNonceAndCiphertext);

        // Mock ObjectMapper to throw
        JsonProcessingException thrownException = new JsonProcessingException("JSON failed test") {
        }; // Anonymous class needed
        when(objectMapper.writeValueAsBytes(any(JwtSecretsEngine.StoredJwtKeyMaterial.class))).thenThrow(thrownException);

        // Act & Assert
        SecretsEngineException exception = assertThrows(SecretsEngineException.class, () -> {
            jwtSecretsEngine.generateAndStoreKeyPair(keyName, version);
        });
        assertEquals("Failed to serialize JWT key material for key: " + keyName, exception.getMessage());
        assertEquals(thrownException, exception.getCause());

        // Verify audit log was NOT called for success
        verify(auditHelper, never()).logInternalEvent(any(), any(), eq("success"), any(), any());
        // Verify storage was NOT called
        verify(storageBackend, never()).put(anyString(), any());
        // Verify second encryption call was NOT made
        verify(encryptionService, times(1)).encrypt(any(byte[].class));
    }

    // --- End Task 3.2 ---

    // Inside JwtSecretsEngineTest class...

    // --- Task 3.6: signJwt Tests ---

    @Nested
    @DisplayName("signJwt Tests")
    class SignJwtTests {

        private final String keyName = "test-sign-key-rsa";
        private final int currentVersion = 1;
        private final String keyId = keyName + "-" + currentVersion;
        private final String configPath = String.format("jwt/keys/%s/config", keyName);
        private final String materialPath = String.format("jwt/keys/%s/versions/%d", keyName, currentVersion);
        private final Map<String, Object> claims = Map.of("sub", "test-user", "scope", "read write");

        private KeyPair testKeyPair;
        private PrivateKey testPrivateKey;
        private PublicKey testPublicKey;
        private byte[] testPrivateKeyBytesPkcs8;
        private byte[] encryptedPrivateKeyBytes;
        private byte[] encryptedConfigBytes;
        private byte[] encryptedMaterialBytes;
        private byte[] configJsonBytes;
        private byte[] materialJsonBytes;
        private JwtKeyConfig testKeyConfig;
        private StoredJwtKeyMaterial testKeyMaterial;
        private JwtKeyDefinition testKeyDefinition;

        @BeforeEach
        void signJwtSetup() throws Exception {
            // Generate real keys for verification later (optional but useful)
            testKeyPair = generateTestRsaKeyPair(); // Using RSA for these examples
            testPrivateKey = testKeyPair.getPrivate();
            testPublicKey = testKeyPair.getPublic();
            testPrivateKeyBytesPkcs8 = testPrivateKey.getEncoded();

            // --- Mock Data ---
            byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE]; // Dummy nonce

            // Encrypted Private Key (as stored in StoredJwtKeyMaterial)
            byte[] cipherPriv = "encryptedPrivKeyBytes".getBytes();
            ByteBuffer bbPriv = ByteBuffer.allocate(nonce.length + cipherPriv.length).put(nonce).put(cipherPriv);
            encryptedPrivateKeyBytes = bbPriv.array();

            // Key Config
            testKeyConfig = new JwtKeyConfig(currentVersion, Duration.ofDays(1), Instant.now().minusSeconds(3600));
            configJsonBytes = objectMapper.writeValueAsBytes(testKeyConfig); // Use real ObjectMapper for setup
            byte[] cipherConfig = "encryptedConfigBytes".getBytes();
            ByteBuffer bbConfig = ByteBuffer.allocate(nonce.length + cipherConfig.length).put(nonce).put(cipherConfig);
            encryptedConfigBytes = bbConfig.array();

            // Key Material (Bundle)
            testKeyMaterial = new StoredJwtKeyMaterial(
                    Base64.getEncoder().encodeToString(testPublicKey.getEncoded()), // Real public key B64
                    Base64.getEncoder().encodeToString(encryptedPrivateKeyBytes) // Encrypted private key B64
            );
            materialJsonBytes = objectMapper.writeValueAsBytes(testKeyMaterial); // Use real ObjectMapper for setup
            byte[] cipherMaterial = "encryptedMaterialBytes".getBytes();
            ByteBuffer bbMaterial = ByteBuffer.allocate(nonce.length + cipherMaterial.length).put(nonce).put(cipherMaterial);
            encryptedMaterialBytes = bbMaterial.array();

            // Key Definition
            testKeyDefinition = new JwtKeyDefinition(JwtKeyType.RSA, 2048, null, null);

            // --- Default Mock Behaviors for Success Path ---
            // Mock properties
            // --- Default Mock Behaviors for Success Path ---
            // Mock properties chain: properties -> secrets -> jwt -> keys

            // 1. Mock the intermediate SecretsProperties object
            MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);

            // 2. Mock the final JwtProperties object in the chain before keys()
            JwtProperties jwtPropertiesMock = mock(JwtProperties.class);

            // 3. Mock properties.secrets() to return the secrets mock
            lenient().when(properties.secrets()).thenReturn(secretsPropertiesMock);

            // 4. Mock secretsPropertiesMock.jwt() to return the jwt mock
            lenient().when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);

            // 5. Mock jwtPropertiesMock.keys() to return the actual map
            lenient().when(jwtPropertiesMock.keys()).thenReturn(Map.of(keyName, testKeyDefinition));

            // Mock readKeyConfig success
            EncryptedData encryptedConfigData = new EncryptedData(nonce, cipherConfig);
            lenient().when(storageBackend.get(eq(configPath))).thenReturn(Optional.of(encryptedConfigData));
            lenient().when(encryptionService.decrypt(eq(encryptedConfigBytes))).thenReturn(configJsonBytes);
            // objectMapper.readValue for config is implicitly mocked by injecting the mock

            // Mock getStoredKeyMaterial success
            EncryptedData encryptedMaterialData = new EncryptedData(nonce, cipherMaterial);
            lenient().when(storageBackend.get(eq(materialPath))).thenReturn(Optional.of(encryptedMaterialData));
            lenient().when(encryptionService.decrypt(eq(encryptedMaterialBytes))).thenReturn(materialJsonBytes);
            // objectMapper.readValue for material is implicitly mocked

            // Mock private key decryption success
            lenient().when(encryptionService.decrypt(eq(encryptedPrivateKeyBytes))).thenReturn(testPrivateKeyBytesPkcs8);

            // Mock ObjectMapper for the specific types used in the methods
            lenient().when(objectMapper.readValue(eq(configJsonBytes), eq(JwtKeyConfig.class))).thenReturn(testKeyConfig);
            lenient().when(objectMapper.readValue(eq(materialJsonBytes), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF))).thenReturn(testKeyMaterial);

        }

        @Test
        @DisplayName("Success: Should sign JWT correctly with RSA key")
        void signJwt_successRsa() throws Exception {
            // Arrange (Defaults set up in @BeforeEach)

            // Act
            String jwtString = jwtSecretsEngine.signJwt(keyName, claims);

            // Assert
            assertThat(jwtString).isNotBlank();

            // Verify interactions
            verify(storageBackend).get(configPath);
            verify(encryptionService).decrypt(encryptedConfigBytes);
            verify(objectMapper).readValue(configJsonBytes, JwtKeyConfig.class);

            verify(storageBackend).get(materialPath);
            verify(encryptionService).decrypt(encryptedMaterialBytes);
            verify(objectMapper).readValue(materialJsonBytes, JwtSecretsEngine.KEY_MATERIAL_TYPE_REF);

            verify(encryptionService).decrypt(encryptedPrivateKeyBytes); // Private key decryption

            // Verify Audit Log (Success)
            ArgumentCaptor<Map<String, Object>> auditDataCaptor = ArgumentCaptor.forClass(Map.class);
            verify(auditHelper).logInternalEvent(
                    eq("jwt_operation"),
                    eq("sign_jwt"),
                    eq("success"),
                    isNull(),
                    auditDataCaptor.capture()
            );
            assertThat(auditDataCaptor.getValue())
                    .containsEntry("key_name", keyName)
                    .containsEntry("key_version", currentVersion)
                    .containsEntry("key_id", keyId);

            // Optional: Verify JWT content and signature using the *real* public key
            JwtParser parser = Jwts.parser().verifyWith(testPublicKey).build();
            Claims parsedClaims = parser.parseSignedClaims(jwtString).getPayload();
            JwsHeader parsedHeader = parser.parseSignedClaims(jwtString).getHeader();

            assertThat(parsedHeader.getKeyId()).isEqualTo(keyId);
            assertThat(parsedClaims.getIssuer()).isEqualTo("lite-vault");
            assertThat(parsedClaims.getSubject()).isEqualTo("test-user");
            assertThat(parsedClaims.get("scope")).isEqualTo("read write");
            assertThat(parsedClaims.getIssuedAt()).isNotNull();
            assertThat(parsedClaims.getExpiration()).isAfter(Date.from(Instant.now()));
        }

        @Test
        @DisplayName("Fail: Vault Sealed")
        void signJwt_vaultSealed_shouldThrowVaultSealedException() {
            // Arrange
            when(sealManager.isSealed()).thenReturn(true); // Override default

            // Act & Assert
            VaultSealedException ex = assertThrows(VaultSealedException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            assertThat(ex.getMessage()).isEqualTo("Vault is sealed");

            // Verify minimal interactions
            verify(sealManager).isSealed();
            verify(storageBackend, never()).get(anyString());
            verify(encryptionService, never()).decrypt(any());
            verify(auditHelper, never()).logInternalEvent(any(), any(), any(), any(), any());
        }

        @Test
        @DisplayName("Fail: Config Not Found")
        void signJwt_configNotFound_shouldThrowJwtKeyNotFoundException() throws Exception {
            // Arrange
            when(storageBackend.get(eq(configPath))).thenReturn(Optional.empty()); // Config doesn't exist

            // Act & Assert
            JwtKeyNotFoundException ex = assertThrows(JwtKeyNotFoundException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            // This exception comes from readKeyConfig -> storageBackend.get returning empty
            assertThat(ex.getMessage()).isEqualTo("JWT key configuration not found for name: " + keyName);

            // Verify audit log was NOT called for signing success/failure
            verify(auditHelper, never()).logInternalEvent(any(), eq("sign_jwt"), any(), any(), any());
        }

        @Test
        @DisplayName("Fail: Key Material Not Found")
        void signJwt_keyMaterialNotFound_shouldThrowJwtKeyNotFoundException() throws Exception {
            // Arrange
            // Config read is successful (mocked in @BeforeEach)
            when(storageBackend.get(eq(materialPath))).thenReturn(Optional.empty()); // Material doesn't exist

            // Act & Assert
            JwtKeyNotFoundException ex = assertThrows(JwtKeyNotFoundException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            // This exception comes from getStoredKeyMaterial -> storageBackend.get returning empty
            assertThat(ex.getMessage()).isEqualTo(String.format("JWT key material not found for key '%s', version %d", keyName, currentVersion));

            // Verify audit log was NOT called for signing success/failure
            verify(auditHelper, never()).logInternalEvent(any(), eq("sign_jwt"), any(), any(), any());
        }

        @Test
        @DisplayName("Fail: Private Key Decryption Failure")
        void signJwt_privateKeyDecryptionFails_shouldThrowSecretsEngineException() throws Exception {
            // Arrange
            // Config and Material read are successful (mocked in @BeforeEach)
            EncryptionException decryptException = new EncryptionException("Decrypt fail");
            when(encryptionService.decrypt(eq(encryptedPrivateKeyBytes))).thenThrow(decryptException);

            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            assertThat(ex.getMessage()).isEqualTo("Failed to decrypt private key for signing.");
            assertThat(ex.getCause()).isEqualTo(decryptException);
        }

        @Test
        @DisplayName("Fail: Private Key Reconstruction Failure (Invalid Bytes)")
        void signJwt_privateKeyReconstructionFails_shouldThrowSecretsEngineException() throws Exception {
            // Arrange
            // Config and Material read are successful
            byte[] invalidPkcs8Bytes = new byte[]{1, 2, 3, 4}; // Invalid format
            when(encryptionService.decrypt(eq(encryptedPrivateKeyBytes))).thenReturn(invalidPkcs8Bytes);

            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            // Exception comes from reconstructPrivateKey
            assertThat(ex.getMessage()).isEqualTo("Failed to reconstruct private key for signing.");
            assertThat(ex.getCause()).isInstanceOf(InvalidKeySpecException.class);
        }

        @Test
        @DisplayName("Fail: Base64 Decode Failure for Encrypted Private Key")
        void signJwt_base64DecodeFails_shouldThrowSecretsEngineException() throws Exception {
            // Arrange
            // Config read is successful
            // Modify the stored material mock to have invalid Base64
            StoredJwtKeyMaterial invalidMaterial = new StoredJwtKeyMaterial(
                    testKeyMaterial.publicKeyB64(),
                    "---Invalid Base64---"
            );
            byte[] invalidMaterialJsonBytes = objectMapper.writeValueAsBytes(invalidMaterial);
            when(encryptionService.decrypt(eq(encryptedMaterialBytes))).thenReturn(invalidMaterialJsonBytes);
            when(objectMapper.readValue(eq(invalidMaterialJsonBytes), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF))).thenReturn(invalidMaterial);


            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            assertThat(ex.getMessage()).isEqualTo("Invalid Base64 format for stored encrypted private key.");
            assertThat(ex.getCause()).isInstanceOf(IllegalArgumentException.class);

            // Verify audit log was NOT called for signing success/failure (fails before signing attempt)
            verify(auditHelper, never()).logInternalEvent(any(), eq("sign_jwt"), any(), any(), any());
        }

        @Test
        @DisplayName("Fail: Config Decryption Failure")
        void signJwt_configDecryptionFails_shouldThrowSecretsEngineException() throws Exception {
            // Arrange
            EncryptionException decryptException = new EncryptionException("Config Decrypt fail");
            when(encryptionService.decrypt(eq(encryptedConfigBytes))).thenThrow(decryptException);

            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            // Exception comes from readKeyConfig
            assertThat(ex.getMessage()).isEqualTo("Failed to decrypt key config for key: " + keyName);
            assertThat(ex.getCause()).isEqualTo(decryptException);

            // Verify audit log was NOT called for signing success/failure
            verify(auditHelper, never()).logInternalEvent(any(), eq("sign_jwt"), any(), any(), any());
        }

        @Test
        @DisplayName("Fail: Material Decryption Failure")
        void signJwt_materialDecryptionFails_shouldThrowSecretsEngineException() throws Exception {
            // Arrange
            // Config read is successful
            EncryptionException decryptException = new EncryptionException("Material Decrypt fail");
            when(encryptionService.decrypt(eq(encryptedMaterialBytes))).thenThrow(decryptException);

            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            // Exception comes from getStoredKeyMaterial
            assertThat(ex.getMessage()).isEqualTo("Failed to decrypt key material bundle for key: " + keyName + ", version: " + currentVersion);
            assertThat(ex.getCause()).isEqualTo(decryptException);

            // Verify audit log was NOT called for signing success/failure
            verify(auditHelper, never()).logInternalEvent(any(), eq("sign_jwt"), any(), any(), any());
        }

        @Test
        @DisplayName("Fail: Config Deserialization Failure")
        void signJwt_configDeserializationFails_shouldThrowSecretsEngineException() throws Exception {
            // Arrange
            byte[] invalidConfigJson = "invalid json".getBytes();
            when(encryptionService.decrypt(eq(encryptedConfigBytes))).thenReturn(invalidConfigJson);
            // Simulate ObjectMapper failure
            IOException ioException = new JsonProcessingException("Bad JSON") {
            };
            when(objectMapper.readValue(eq(invalidConfigJson), eq(JwtKeyConfig.class))).thenThrow(ioException);


            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            // Exception comes from readKeyConfig
            assertThat(ex.getMessage()).isEqualTo("Failed to parse key config data for key: " + keyName);
            assertThat(ex.getCause()).isEqualTo(ioException);

            // Verify audit log was NOT called for signing success/failure
            verify(auditHelper, never()).logInternalEvent(any(), eq("sign_jwt"), any(), any(), any());
        }

        @Test
        @DisplayName("Fail: Material Deserialization Failure")
        void signJwt_materialDeserializationFails_shouldThrowSecretsEngineException() throws Exception {
            // Arrange
            // Config read is successful
            byte[] invalidMaterialJson = "invalid json".getBytes();
            when(encryptionService.decrypt(eq(encryptedMaterialBytes))).thenReturn(invalidMaterialJson);
            // Simulate ObjectMapper failure
            IOException ioException = new JsonProcessingException("Bad JSON") {
            };
            when(objectMapper.readValue(eq(invalidMaterialJson), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF))).thenThrow(ioException);

            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.signJwt(keyName, claims);
            });
            // Exception comes from getStoredKeyMaterial
            assertThat(ex.getMessage()).isEqualTo("Failed to parse key material data for key: " + keyName + ", version: " + currentVersion);
            assertThat(ex.getCause()).isEqualTo(ioException);

            // Verify audit log was NOT called for signing success/failure
            verify(auditHelper, never()).logInternalEvent(any(), eq("sign_jwt"), any(), any(), any());
        }

    } // End Nested class SignJwtTests

    // --- End Task 3.6 ---

    // Inside JwtSecretsEngineTest class...

    // --- Task 3.7: rotateKey Tests ---

    @Nested
    @DisplayName("rotateKey Tests")
    class RotateKeyTests {

        private final String keyName = "test-rotate-key";
        private final String configPath = String.format("jwt/keys/%s/config", keyName);
        private final int currentVersion = 1;
        private final int newVersion = 2;
        private final String currentMaterialPath = String.format("jwt/keys/%s/versions/%d", keyName, currentVersion); // Not directly used by rotate, but good context
        private final String newMaterialPath = String.format("jwt/keys/%s/versions/%d", keyName, newVersion);

        private JwtKeyConfig currentConfig;
        private JwtKeyConfig newConfig; // Expected config after rotation
        private JwtKeyDefinition testKeyDefinition;
        private byte[] currentConfigJsonBytes;
        private byte[] newConfigJsonBytes;
        private byte[] encryptedCurrentConfigBytes;
        private byte[] encryptedNewConfigBytes;
        private byte[] encryptedNewPrivateKeyBytes; // From generateAndStoreKeyPair
        private byte[] encryptedNewMaterialBundleBytes; // From generateAndStoreKeyPair
        private byte[] newMaterialJsonBytes; // From generateAndStoreKeyPair
        private byte[] cipherNewBundle;

        @BeforeEach
        void rotateKeySetup() throws Exception {
            // --- Common Arrange ---
            testKeyDefinition = new JwtKeyDefinition(JwtKeyType.RSA, 2048, null, Duration.ofDays(30)); // Example definition
            currentConfig = new JwtKeyConfig(currentVersion, testKeyDefinition.rotationPeriod(), Instant.now().minus(Duration.ofDays(31))); // Simulate due for rotation
            // newConfig will be created dynamically in tests/mocks

            byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE]; // Dummy nonce

            // Mock data for reading current config
            currentConfigJsonBytes = objectMapper.writeValueAsBytes(currentConfig);
            byte[] cipherCurrentConfig = "encryptedCurrentConfig".getBytes();
            ByteBuffer bbCurrentConfig = ByteBuffer.allocate(nonce.length + cipherCurrentConfig.length).put(nonce).put(cipherCurrentConfig);
            encryptedCurrentConfigBytes = bbCurrentConfig.array();
            EncryptedData currentEncryptedData = new EncryptedData(nonce, cipherCurrentConfig);

            // Mock data for generateAndStoreKeyPair (newVersion)
            // We need to mock the results of encryption *within* generateAndStoreKeyPair
            byte[] cipherNewPriv = "newPrivCipher".getBytes();
            ByteBuffer bbNewPriv = ByteBuffer.allocate(nonce.length + cipherNewPriv.length).put(nonce).put(cipherNewPriv);
            encryptedNewPrivateKeyBytes = bbNewPriv.array(); // Result of encrypting raw new private key

            StoredJwtKeyMaterial newMaterial = new StoredJwtKeyMaterial("newPubKeyB64", Base64.getEncoder().encodeToString(encryptedNewPrivateKeyBytes));
            newMaterialJsonBytes = objectMapper.writeValueAsBytes(newMaterial); // JSON payload before bundle encryption

            cipherNewBundle = "newBundleCipher".getBytes();
            ByteBuffer bbNewBundle = ByteBuffer.allocate(nonce.length + cipherNewBundle.length).put(nonce).put(cipherNewBundle);
            encryptedNewMaterialBundleBytes = bbNewBundle.array(); // Result of encrypting newMaterialJsonBytes
            EncryptedData newMaterialEncryptedData = new EncryptedData(nonce, cipherNewBundle);

            // Mock data for writing new config
            // newConfigJsonBytes and encryptedNewConfigBytes will be set up via ArgumentCaptor/mocking 'encrypt'

            // --- Default Mock Behaviors (Success Path) ---

            // Mock reading current config successfully
            lenient().when(storageBackend.get(eq(configPath))).thenReturn(Optional.of(currentEncryptedData));
            lenient().when(encryptionService.decrypt(eq(encryptedCurrentConfigBytes))).thenReturn(currentConfigJsonBytes);
            lenient().when(objectMapper.readValue(eq(currentConfigJsonBytes), eq(JwtKeyConfig.class))).thenReturn(currentConfig);

            // Mock dependencies for successful generateAndStoreKeyPair(keyName, newVersion)
            MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);
            JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
            lenient().when(properties.secrets()).thenReturn(secretsPropertiesMock);
            lenient().when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);
            lenient().when(jwtPropertiesMock.keys()).thenReturn(Map.of(keyName, testKeyDefinition)); // Need keys() and the definition
            // Mock the two encryption calls within generateAndStoreKeyPair
            // 1. Encrypt raw private key -> encryptedNewPrivateKeyBytes
            // 2. Encrypt material JSON -> encryptedNewMaterialBundleBytes
            // Use lenient because the order might vary slightly or other tests might call encrypt
            lenient().when(encryptionService.encrypt(any(byte[].class)))
                    .thenReturn(encryptedNewPrivateKeyBytes) // Assume first call is private key
                    .thenReturn(encryptedNewMaterialBundleBytes); // Assume second call is bundle
            lenient().when(objectMapper.writeValueAsBytes(any(StoredJwtKeyMaterial.class))).thenReturn(newMaterialJsonBytes);
            // storageBackend.put for new material path is verified, not mocked for return value

            // Mock dependencies for successful writeKeyConfig(keyName, newConfig)
            // We capture the newConfig object to verify it
            // We mock the encryption of the newConfigJsonBytes
            // storageBackend.put for config path is verified

        }

        @Test
        @DisplayName("Success: Should rotate key, generate new material, update config, and audit")
        void rotateKey_success() throws Exception {
            // Arrange
            // Capture the config object passed to writeKeyConfig's objectMapper call
            ArgumentCaptor<JwtKeyConfig> newConfigCaptor = ArgumentCaptor.forClass(JwtKeyConfig.class);
            // Prepare mock result for encrypting the new config
            byte[] capturedNewConfigJsonBytes = "{\"currentVersion\":2,...}".getBytes(); // Placeholder
            byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE];
            byte[] cipherNewConfig = "encryptedNewConfig".getBytes();
            ByteBuffer bbNewConfig = ByteBuffer.allocate(nonce.length + cipherNewConfig.length).put(nonce).put(cipherNewConfig);
            byte[] encryptedNewConfigResultBytes = bbNewConfig.array();
            EncryptedData newConfigEncryptedData = new EncryptedData(nonce, cipherNewConfig);


            // Mock the specific objectMapper call for the new config
            when(objectMapper.writeValueAsBytes(newConfigCaptor.capture())).thenReturn(capturedNewConfigJsonBytes);
            // --- FIX: Replace the single chained mock with separate, specific mocks ---
            // Use lenient() as these are just setup steps for the success path.
            // Use eq() where the input bytes are known from the @BeforeEach setup or capture.

            // Mock 1st encrypt call in generateAndStoreKeyPair (private key bytes - unknown)
            lenient().doReturn(encryptedNewPrivateKeyBytes)
                    .when(encryptionService).encrypt(any(byte[].class));

            // Mock 2nd encrypt call in generateAndStoreKeyPair (bundle bytes - known from setup)
            lenient().doReturn(encryptedNewMaterialBundleBytes)
                    .when(encryptionService).encrypt(eq(newMaterialJsonBytes)); // Use eq()

            // Mock 3rd encrypt call in writeKeyConfig (config bytes - known from capture/placeholder)
            lenient().doReturn(encryptedNewConfigResultBytes)
                    .when(encryptionService).encrypt(eq(capturedNewConfigJsonBytes)); // Use eq()
            // --- End Fix ---
            // Act
            assertDoesNotThrow(() -> jwtSecretsEngine.rotateKey(keyName));

            // Assert
            // 1. Verify readKeyConfig dependencies called
            verify(storageBackend).get(eq(configPath));
            verify(encryptionService).decrypt(eq(encryptedCurrentConfigBytes));
            verify(objectMapper).readValue(eq(currentConfigJsonBytes), eq(JwtKeyConfig.class));

            // 2. Verify generateAndStoreKeyPair dependencies called (indirectly)
            //    - Key definition lookup
            //verify(properties.jwt().keys()).get(keyName);
            //verify(properties.jwt().keys()).get(eq(keyName));
            //    - Encryption calls (verified via the ordered 'when' above)
            //    - ObjectMapper call for new material
            ArgumentCaptor<StoredJwtKeyMaterial> materialCaptor = ArgumentCaptor.forClass(StoredJwtKeyMaterial.class);
            verify(objectMapper, times(2)).writeValueAsBytes(materialCaptor.capture());
            //    - Storage put for new material
            ArgumentCaptor<EncryptedData> genStoreCaptor = ArgumentCaptor.forClass(EncryptedData.class);
            verify(storageBackend).put(eq(newMaterialPath), genStoreCaptor.capture());
            assertThat(genStoreCaptor.getValue().getCiphertextBytes()).isEqualTo(cipherNewBundle); // Check it stored the bundle ciphertext
            //    - Audit log for key generation
            verify(auditHelper).logInternalEvent(eq("jwt_operation"), eq("key_generation"), eq("success"), isNull(), any());


            // 3. Verify writeKeyConfig dependencies called (indirectly)
            //    - ObjectMapper call for new config (captured)
            JwtKeyConfig writtenConfig = newConfigCaptor.getValue();
            assertThat(writtenConfig.currentVersion()).isEqualTo(newVersion);
            assertThat(writtenConfig.rotationPeriod()).isEqualTo(testKeyDefinition.rotationPeriod());
            assertThat(writtenConfig.lastRotationTime()).isAfter(currentConfig.lastRotationTime());
            //    - Encryption call for new config (verified via the ordered 'when' above)
            //    - Storage put for config path
            ArgumentCaptor<EncryptedData> writeConfCaptor = ArgumentCaptor.forClass(EncryptedData.class);
            verify(storageBackend).put(eq(configPath), writeConfCaptor.capture());
            assertThat(writeConfCaptor.getValue().getCiphertextBytes()).isEqualTo(cipherNewConfig); // Check it stored the new config ciphertext
            //    - Audit log for config update
            verify(auditHelper).logInternalEvent(eq("jwt_operation"), eq("key_config_update"), eq("success"), isNull(), any());

            // 4. Verify final audit log for rotation success
            ArgumentCaptor<Map<String, Object>> rotationAuditCaptor = ArgumentCaptor.forClass(Map.class);
            verify(auditHelper).logInternalEvent(
                    eq("jwt_operation"),
                    eq("key_rotation"),
                    eq("success"),
                    isNull(),
                    rotationAuditCaptor.capture()
            );
            assertThat(rotationAuditCaptor.getValue())
                    .containsEntry("key_name", keyName)
                    .containsEntry("old_version", currentVersion)
                    .containsEntry("new_version", newVersion);
        }

        @Test
        @DisplayName("Fail: Config Not Found (Definition Missing in Properties)") // More accurate name
        void rotateKey_configNotFound_shouldThrowJwtKeyNotFoundException() throws Exception {
            // Arrange

            // --- FIX: Mock the properties chain to simulate the key definition NOT being found ---
            JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
            MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);

            // Make the properties chain return the mocks
            // Use lenient() if these might conflict with @BeforeEach, or just use when() if specific to this test
            when(properties.secrets()).thenReturn(secretsPropertiesMock);
            when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);
            // Simulate the keys map NOT containing the keyName
            when(jwtPropertiesMock.keys()).thenReturn(Collections.emptyMap());
            // Alternatively: when(jwtPropertiesMock.keys().get(eq(keyName))).thenReturn(null);
            // --- End FIX ---

            // Keep the original storage mock (optional, as getKeyDefinition should fail first now)
            // when(storageBackend.get(eq(configPath))).thenReturn(Optional.empty());

            // Act & Assert
            JwtKeyNotFoundException ex = assertThrows(JwtKeyNotFoundException.class, () -> {
                jwtSecretsEngine.rotateKey(keyName); // This should now fail in getKeyDefinition
            });
            // Assert the message from getKeyDefinition's exception
            assertThat(ex.getMessage()).isEqualTo("JWT key configuration not found for name: " + keyName);

            // Verify other actions didn't happen
            verify(storageBackend, never()).get(anyString()); // Should not even attempt to read config file
            verify(storageBackend, never()).put(anyString(), any());
            verify(encryptionService, never()).encrypt(any());
            verify(encryptionService, never()).decrypt(any());
            verify(auditHelper, never()).logInternalEvent(any(), any(), any(), any(), any()); // No audit expected if definition is missing
        }

        @Test
        @DisplayName("Fail: Vault Sealed")
        void rotateKey_vaultSealed_shouldThrowVaultSealedException() {
            // Arrange
            when(sealManager.isSealed()).thenReturn(true); // Override default

            // Act & Assert
            VaultSealedException ex = assertThrows(VaultSealedException.class, () -> {
                jwtSecretsEngine.rotateKey(keyName);
            });
            assertThat(ex.getMessage()).isEqualTo("Vault is sealed");

            // Verify minimal interactions
            verify(sealManager).isSealed();
            verify(storageBackend, never()).get(anyString());
            verify(storageBackend, never()).put(anyString(), any());
            verify(encryptionService, never()).decrypt(any());
            verify(encryptionService, never()).encrypt(any());
            verify(auditHelper, never()).logInternalEvent(any(), any(), any(), any(), any()); // No audit log expected if sealed check fails first
        }

        @Test
        @DisplayName("Fail: generateAndStoreKeyPair throws StorageException")
        void rotateKey_generateFailsWithStorageException_shouldThrowAndAudit() throws Exception {
            // Arrange
            // readKeyConfig is mocked for success in setup
            StorageException storageEx = new StorageException("Disk full during key generation");
            // Mock storageBackend.put for the *new material path* to throw
            doThrow(storageEx).when(storageBackend).put(eq(newMaterialPath), any(EncryptedData.class));

            // Mock ObjectMapper (needed before encrypt)
            when(objectMapper.writeValueAsBytes(any(StoredJwtKeyMaterial.class))).thenReturn(newMaterialJsonBytes);

            // --- FIX: Use more specific/robust mocks for the preceding encrypt calls ---
            // We need the two encrypt calls inside generateAndStoreKeyPair to succeed
            // Use lenient() as these are setup for the path *before* the intended failure
            // Use eq() for the second call where we know the input bytes from setup
            lenient().doReturn(encryptedNewPrivateKeyBytes)
                    .when(encryptionService).encrypt(any(byte[].class)); // Match first call (private key bytes are unknown)
            lenient().doReturn(encryptedNewMaterialBundleBytes)
                    .when(encryptionService).encrypt(eq(newMaterialJsonBytes)); // Match second call (bundle bytes are known)
            // --- End Fix ---


            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.rotateKey(keyName);
            });
            assertThat(ex.getMessage()).isEqualTo("Failed to store JWT key material for key: " + keyName);
            assertThat(ex.getCause()).isEqualTo(storageEx);

            // Verify audit log for rotation failure
            ArgumentCaptor<Map<String, Object>> auditCaptor = ArgumentCaptor.forClass(Map.class);
            verify(auditHelper).logInternalEvent(
                    eq("jwt_operation"),
                    eq("key_rotation"),
                    eq("failure"),
                    isNull(),
                    auditCaptor.capture()
            );
            assertThat(auditCaptor.getValue())
                    .containsEntry("key_name", keyName)
                    .containsEntry("attempted_new_version", newVersion)
                    .containsEntry("error", ex.getMessage());

            // Verify writeKeyConfig was not attempted
            verify(storageBackend, never()).put(eq(configPath), any(EncryptedData.class)); // Config path put should not happen
            verify(auditHelper, never()).logInternalEvent(any(), eq("key_config_update"), any(), any(), any());
            verify(auditHelper, never()).logInternalEvent(any(), eq("key_rotation"), eq("success"), any(), any());
        }

        @Test
        @DisplayName("Fail: writeKeyConfig throws EncryptionException")
        void rotateKey_writeConfigFailsWithEncryptionException_shouldThrowAndAudit() throws Exception {
            // Arrange
            // readKeyConfig success (setup)
            // generateAndStoreKeyPair needs to succeed before writeKeyConfig is called
            EncryptionException encryptEx = new EncryptionException("Failed encrypting new config");

            // Capture the config object and define the bytes it will serialize to
            ArgumentCaptor<JwtKeyConfig> newConfigCaptor = ArgumentCaptor.forClass(JwtKeyConfig.class);
            // Use the field 'newMaterialJsonBytes' which is set up in @BeforeEach
            // byte[] capturedNewConfigJsonBytes = "{\"currentVersion\":2,...}".getBytes(); // Placeholder - Use the actual variable
            byte[] capturedNewConfigJsonBytes; // Will be set by the objectMapper mock

            // Mock objectMapper to capture the config and return the placeholder bytes
            // We need to know these bytes *before* mocking encrypt(eq(...))
            // Let's use a fixed placeholder for the test
            byte[] placeholderConfigJsonBytes = "{\"version\":2}".getBytes();
            when(objectMapper.writeValueAsBytes(newConfigCaptor.capture())).thenReturn(placeholderConfigJsonBytes);

            // --- FIX: Use doReturn/doThrow with specific matchers where possible ---
            // Mock the sequence of encrypt calls:
            // 1st call (private key in generate): succeed. Use any() as bytes are unknown.
            // 2nd call (bundle in generate): succeed. Input is 'newMaterialJsonBytes' from setup.
            // 3rd call (config in write): fail. Input is 'placeholderConfigJsonBytes'.

            // IMPORTANT: Order matters with doReturn/doThrow. More specific matchers might need to come first,
            // but let's try matching the expected call order.
            // If using any(), it often needs to be the last resort or used carefully.

            // Let's try lenient stubbing for the first two calls (needed for generateAndStoreKeyPair)
            // and strict stubbing for the one we expect to throw.
            lenient().when(encryptionService.encrypt(any(byte[].class))) // Match first call (private key)
                    .thenReturn(encryptedNewPrivateKeyBytes);
            lenient().when(encryptionService.encrypt(eq(newMaterialJsonBytes))) // Match second call (bundle)
                    .thenReturn(encryptedNewMaterialBundleBytes);

            // Now, the strict stubbing for the call that should fail
            when(encryptionService.encrypt(eq(placeholderConfigJsonBytes))) // Match third call (config)
                    .thenThrow(encryptEx);
            // --- End Fix ---


            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.rotateKey(keyName);
            });
            assertThat(ex.getMessage()).isEqualTo("Failed to encrypt JWT key config for key: " + keyName);
            assertThat(ex.getCause()).isEqualTo(encryptEx);

            // Verify audit log for rotation failure
            ArgumentCaptor<Map<String, Object>> auditCaptor = ArgumentCaptor.forClass(Map.class);
            verify(auditHelper).logInternalEvent(
                    eq("jwt_operation"),
                    eq("key_rotation"),
                    eq("failure"),
                    isNull(),
                    auditCaptor.capture()
            );
            assertThat(auditCaptor.getValue())
                    .containsEntry("key_name", keyName)
                    .containsEntry("attempted_new_version", newVersion)
                    .containsEntry("error", ex.getMessage());

            // Verify generate succeeded (put for new material path happened)
            verify(storageBackend).put(eq(newMaterialPath), any(EncryptedData.class));
            // Verify config update audit did NOT happen
            verify(auditHelper, never()).logInternalEvent(any(), eq("key_config_update"), any(), any(), any());
            verify(auditHelper, never()).logInternalEvent(any(), eq("key_rotation"), eq("success"), any(), any());
        }

    } // End Nested class RotateKeyTests

    // --- End Task 3.7 ---


    // --- Task 3.8: getJwks Tests ---

    @Nested
    @DisplayName("getJwks Tests")
    class GetJwksTests {

        // --- Existing fields for key names, paths, etc. ---
        private final String keyNameRsa = "test-rsa-key";
        private final String keyNameEc = "test-ec-key";
        private final int version = 1;
        // Removed config paths as they are not directly used by getJwks anymore
        // private final String configPathRsa = String.format("jwt/keys/%s/config", keyNameRsa);
        // private final String configPathEc = String.format("jwt/keys/%s/config", keyNameEc);
        private final String materialPathRsa = String.format("jwt/keys/%s/versions/%d", keyNameRsa, version); // Relative key
        private final String materialPathEc = String.format("jwt/keys/%s/versions/%d", keyNameEc, version);   // Relative key
        private final String keyIdRsa = keyNameRsa + "-" + version;
        private final String keyIdEc = keyNameEc + "-" + version;

        // ---> Define RELATIVE versions directory paths <---
        private final String relativeVersionsPathRsa = String.format("jwt/keys/%s/versions", keyNameRsa);
        private final String relativeVersionsPathEc = String.format("jwt/keys/%s/versions", keyNameEc);
        // ---> End definition <---

        // --- Existing fields for definitions, materials, keys, etc. ---
        private JwtKeyDefinition rsaDefinition;
        private JwtKeyDefinition ecDefinition;
        // Removed configs as they are not directly needed for JWKS retrieval logic itself
        // private JwtKeyConfig rsaConfig;
        // private JwtKeyConfig ecConfig;
        private StoredJwtKeyMaterial rsaMaterial;
        private StoredJwtKeyMaterial ecMaterial;
        // Removed config JSON/encrypted bytes
        private byte[] rsaMaterialJsonBytes;
        private byte[] ecMaterialJsonBytes;
        private byte[] encryptedRsaMaterialBytes;
        private byte[] encryptedEcMaterialBytes;
        private PublicKey rsaPublicKey;
        private PublicKey ecPublicKey;
        private byte[] rsaPublicKeyBytes; // X.509 format
        private byte[] ecPublicKeyBytes;  // X.509 format

        private EncryptedData encryptedRsaMaterialData;
        private EncryptedData encryptedEcMaterialData; // <-- Added mock data for EC material


        @BeforeEach
        void getJwksSetup() throws Exception {
            // --- Common Arrange ---
            byte[] nonce = new byte[EncryptionService.NONCE_LENGTH_BYTE];

            // Keys
            KeyPair rsaKeyPair = generateTestRsaKeyPair();
            rsaPublicKey = rsaKeyPair.getPublic();
            rsaPublicKeyBytes = rsaPublicKey.getEncoded();
            KeyPair ecKeyPair = generateTestEcKeyPair();
            ecPublicKey = ecKeyPair.getPublic();
            ecPublicKeyBytes = ecPublicKey.getEncoded();

            // Definitions
            rsaDefinition = new JwtKeyDefinition(JwtKeyType.RSA, 2048, null, Duration.ofDays(90));
            ecDefinition = new JwtKeyDefinition(JwtKeyType.EC, null, "P-256", Duration.ofDays(90));

            // Materials
            rsaMaterial = new StoredJwtKeyMaterial(Base64.getEncoder().encodeToString(rsaPublicKeyBytes), "dummyEncryptedPrivateKeyB64");
            ecMaterial = new StoredJwtKeyMaterial(Base64.getEncoder().encodeToString(ecPublicKeyBytes), "dummyEncryptedPrivateKeyB64");

            // JSON Bytes
            rsaMaterialJsonBytes = "{\"publicKeyB64\":\"rsa...\"}".getBytes();
            ecMaterialJsonBytes = "{\"publicKeyB64\":\"ec...\"}".getBytes();
            // Removed objectMapper mocks for config
            lenient().when(objectMapper.writeValueAsBytes(eq(rsaMaterial))).thenReturn(rsaMaterialJsonBytes);
            lenient().when(objectMapper.writeValueAsBytes(eq(ecMaterial))).thenReturn(ecMaterialJsonBytes);

            // Encrypted Bytes
            byte[] cipherRsaMaterial = "encRsaMat".getBytes();
            byte[] cipherEcMaterial = "encEcMat".getBytes();
            encryptedRsaMaterialBytes = ByteBuffer.allocate(nonce.length + cipherRsaMaterial.length).put(nonce).put(cipherRsaMaterial).array();
            encryptedEcMaterialBytes = ByteBuffer.allocate(nonce.length + cipherEcMaterial.length).put(nonce).put(cipherEcMaterial).array();

            // Encrypted Data Objects
            encryptedRsaMaterialData = new EncryptedData(nonce, cipherRsaMaterial);
            encryptedEcMaterialData = new EncryptedData(nonce, cipherEcMaterial); // <-- Use for EC mock

            // --- Default Mock Behaviors ---
            // Mock properties chain for key definitions
            MssmProperties.SecretsProperties secretsPropertiesMock = mock(MssmProperties.SecretsProperties.class);
            JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
            lenient().when(properties.secrets()).thenReturn(secretsPropertiesMock);
            lenient().when(secretsPropertiesMock.jwt()).thenReturn(jwtPropertiesMock);
            lenient().when(jwtPropertiesMock.keys()).thenReturn(Map.of(keyNameRsa, rsaDefinition, keyNameEc, ecDefinition));

            // --- REMOVE Mocks for filesystem path ---
            // MssmProperties.StorageProperties storagePropertiesMock = mock(MssmProperties.StorageProperties.class);
            // MssmProperties.StorageProperties.FileSystemProperties filesystemPropertiesMock = mock(MssmProperties.StorageProperties.FileSystemProperties.class);
            // lenient().when(storagePropertiesMock.filesystem()).thenReturn(filesystemPropertiesMock);
            // lenient().when(filesystemPropertiesMock.path()).thenReturn("/mock/storage/path"); // REMOVE THIS
            // lenient().when(properties.storage()).thenReturn(storagePropertiesMock); // REMOVE THIS

            // --- ADD Mocks for new storageBackend methods ---
            // For RSA success path:
            lenient().when(storageBackend.isDirectory(eq(relativeVersionsPathRsa))).thenReturn(true);
            lenient().when(storageBackend.listDirectory(eq(relativeVersionsPathRsa))).thenReturn(List.of(version + ".json")); // e.g., ["1.json"]

            // For EC success path:
            lenient().when(storageBackend.isDirectory(eq(relativeVersionsPathEc))).thenReturn(true);
            lenient().when(storageBackend.listDirectory(eq(relativeVersionsPathEc))).thenReturn(List.of(version + ".json")); // e.g., ["1.json"]
            // --- End ADD Mocks ---

            // --- Update existing mocks to use relative paths/keys where appropriate ---
            // RSA Material Path Mocks
            lenient().when(storageBackend.get(eq(materialPathRsa))).thenReturn(Optional.of(encryptedRsaMaterialData)); // Use relative key 'materialPathRsa'
            lenient().when(encryptionService.decrypt(eq(encryptedRsaMaterialBytes))).thenReturn(rsaMaterialJsonBytes);
            lenient().when(objectMapper.readValue(eq(rsaMaterialJsonBytes), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF))).thenReturn(rsaMaterial);

            // EC Material Path Mocks
            lenient().when(storageBackend.get(eq(materialPathEc))).thenReturn(Optional.of(encryptedEcMaterialData)); // Use relative key 'materialPathEc'
            lenient().when(encryptionService.decrypt(eq(encryptedEcMaterialBytes))).thenReturn(ecMaterialJsonBytes);
            lenient().when(objectMapper.readValue(eq(ecMaterialJsonBytes), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF))).thenReturn(ecMaterial);

            // Removed mocks related to reading/parsing config files as they aren't hit by getJwks
        }

        // Inside the GetJwksTests nested class...

        @Test
        @DisplayName("Fail: No Key Versions Found in Storage (Directory Exists but Empty)")
        void getJwks_whenNoVersionsFoundInStorage_shouldThrowJwtKeyNotFoundException() throws Exception {
            // Arrange
            // Key definition exists (mocked in setup)
            // Versions directory exists (mocked in setup to return true for isDirectory)
            // Mock listDirectory to return an empty list
            when(storageBackend.listDirectory(eq(relativeVersionsPathRsa))).thenReturn(Collections.emptyList());

            // Act & Assert
            JwtKeyNotFoundException ex = assertThrows(JwtKeyNotFoundException.class, () -> {
                jwtSecretsEngine.getJwks(keyNameRsa);
            });
            // This is the crucial check - ensure it throws when the list is empty after checking the directory
            assertThat(ex.getMessage()).isEqualTo("No valid key versions found for key: " + keyNameRsa);

            // Verify interactions
            verify(storageBackend).isDirectory(eq(relativeVersionsPathRsa)); // Checked directory existence
            verify(storageBackend).listDirectory(eq(relativeVersionsPathRsa)); // Checked directory contents
            verify(storageBackend, never()).get(startsWith("jwt/keys/" + keyNameRsa + "/versions/")); // Never tried to get specific version files
            verify(encryptionService, never()).decrypt(any()); // No decryption attempted
            verify(objectMapper, never()).readValue(any(byte[].class), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF)); // No parsing attempted

            // Verify failure audit log
            ArgumentCaptor<Map<String, Object>> auditCaptor = ArgumentCaptor.forClass(Map.class);
            verify(auditHelper).logInternalEvent(
                    eq("jwt_operation"),
                    eq("get_jwks"),
                    eq("failure"), // Expect failure outcome
                    isNull(),
                    auditCaptor.capture()
            );
            assertThat(auditCaptor.getValue())
                    .containsEntry("key_name", keyNameRsa)
                    .containsEntry("error", ex.getMessage()); // Check error message in audit
        }

        // --- Keep the existing tests below this one ---
        // e.g., getJwks_versionsDirectoryNotFound()
        // e.g., getJwks_isDirectoryThrowsStorageException()
        // etc.

        @Test
        @DisplayName("Success: Should return JWKS with single RSA key")
        void getJwks_successRsa() throws Exception {
            // Arrange (Defaults from setup)

            // Act
            Map<String, Object> jwksMap = jwtSecretsEngine.getJwks(keyNameRsa);

            // Assert
            // ... (JWKS content assertions remain the same) ...
            assertThat(jwksMap).isNotNull();
            assertThat(jwksMap).containsKey("keys");
            assertThat(jwksMap.get("keys")).isInstanceOf(List.class);
            @SuppressWarnings("unchecked") // Safe cast after instanceof check
            List<Map<String, Object>> keysList = (List<Map<String, Object>>) jwksMap.get("keys");
            assertThat(keysList).hasSize(1);
            Map<String, Object> jwk = keysList.get(0);
            assertThat(jwk).containsEntry("kty", "RSA").containsEntry("kid", keyIdRsa);


            // Verify interactions (Updated)
            verify(storageBackend).isDirectory(eq(relativeVersionsPathRsa)); // Verify new check
            verify(storageBackend).listDirectory(eq(relativeVersionsPathRsa)); // Verify new list call
            // Verify material retrieval (using relative key)
            verify(storageBackend).get(eq(materialPathRsa));
            verify(encryptionService).decrypt(eq(encryptedRsaMaterialBytes));
            verify(objectMapper).readValue(eq(rsaMaterialJsonBytes), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF));

            // Verify Audit Log (remains the same)
            ArgumentCaptor<Map<String, Object>> auditCaptor = ArgumentCaptor.forClass(Map.class);
            verify(auditHelper).logInternalEvent(
                    eq("jwt_operation"), eq("get_jwks"), eq("success"), isNull(), auditCaptor.capture()
            );
            assertThat(auditCaptor.getValue())
                    .containsEntry("key_name", keyNameRsa)
                    .containsEntry("versions_included", List.of(version));
        }

        @Test
        @DisplayName("Success: Should return JWKS with single EC key")
        void getJwks_successEc() throws Exception { // The previously failing test
            // Arrange (Defaults from setup)

            // Act
            Map<String, Object> jwksMap = jwtSecretsEngine.getJwks(keyNameEc); // Line 1311 in original trace

            // Assert
            // ... (JWKS content assertions remain the same) ...
            assertThat(jwksMap).isNotNull();
            assertThat(jwksMap).containsKey("keys");
            assertThat(jwksMap.get("keys")).isInstanceOf(List.class);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keysList = (List<Map<String, Object>>) jwksMap.get("keys");
            assertThat(keysList).hasSize(1);
            Map<String, Object> jwk = keysList.get(0);
            assertThat(jwk).containsEntry("kty", "EC").containsEntry("kid", keyIdEc);


            // Verify interactions (Updated)
            verify(storageBackend).isDirectory(eq(relativeVersionsPathEc)); // Verify new check
            verify(storageBackend).listDirectory(eq(relativeVersionsPathEc)); // Verify new list call
            // Verify material retrieval (using relative key)
            verify(storageBackend).get(eq(materialPathEc));
            verify(encryptionService).decrypt(eq(encryptedEcMaterialBytes));
            verify(objectMapper).readValue(eq(ecMaterialJsonBytes), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF));

            // Verify Audit Log (remains the same)
            ArgumentCaptor<Map<String, Object>> auditCaptor = ArgumentCaptor.forClass(Map.class);
            verify(auditHelper).logInternalEvent(
                    eq("jwt_operation"), eq("get_jwks"), eq("success"), isNull(), auditCaptor.capture()
            );
            assertThat(auditCaptor.getValue())
                    .containsEntry("key_name", keyNameEc)
                    .containsEntry("versions_included", List.of(version));
        }

        @Test
        @DisplayName("Fail: Versions Directory Not Found")
        void getJwks_versionsDirectoryNotFound() throws Exception {
            // Arrange
            // Mock isDirectory to return false
            when(storageBackend.isDirectory(eq(relativeVersionsPathRsa))).thenReturn(false);

            // Act & Assert
            JwtKeyNotFoundException ex = assertThrows(JwtKeyNotFoundException.class, () -> {
                jwtSecretsEngine.getJwks(keyNameRsa);
            });
            assertThat(ex.getMessage()).isEqualTo("No key versions found for key: " + keyNameRsa);

            // Verify isDirectory was called, but listDirectory and others were not
            verify(storageBackend).isDirectory(eq(relativeVersionsPathRsa));
            verify(storageBackend, never()).listDirectory(anyString());
            verify(storageBackend, never()).get(startsWith("jwt/keys/" + keyNameRsa + "/versions/")); // Check material wasn't read
            verify(auditHelper).logInternalEvent(anyString(), eq("get_jwks"), eq("failure"), any(), any()); // Verify failure audit
        }

        @Test
        @DisplayName("Fail: StorageException during isDirectory check")
        void getJwks_isDirectoryThrowsStorageException() throws Exception {
            // Arrange
            StorageException storageEx = new StorageException("Permission denied checking directory");
            when(storageBackend.isDirectory(eq(relativeVersionsPathRsa))).thenThrow(storageEx);

            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.getJwks(keyNameRsa);
            });
            assertThat(ex.getMessage()).isEqualTo("Storage error while retrieving JWKS for key: " + keyNameRsa);
            assertThat(ex.getCause()).isEqualTo(storageEx);

            // Verify interactions
            verify(storageBackend).isDirectory(eq(relativeVersionsPathRsa));
            verify(storageBackend, never()).listDirectory(anyString());
            verify(storageBackend, never()).get(startsWith("jwt/keys/" + keyNameRsa + "/versions/"));
            verify(auditHelper).logInternalEvent(anyString(), eq("get_jwks"), eq("failure"), any(), any());
        }

        @Test
        @DisplayName("Fail: StorageException during listDirectory")
        void getJwks_listDirectoryThrowsStorageException() throws Exception {
            // Arrange
            StorageException storageEx = new StorageException("I/O error listing directory");
            // isDirectory succeeds
            when(storageBackend.isDirectory(eq(relativeVersionsPathRsa))).thenReturn(true);
            // listDirectory fails
            when(storageBackend.listDirectory(eq(relativeVersionsPathRsa))).thenThrow(storageEx);

            // Act & Assert
            SecretsEngineException ex = assertThrows(SecretsEngineException.class, () -> {
                jwtSecretsEngine.getJwks(keyNameRsa);
            });
            assertThat(ex.getMessage()).isEqualTo("Storage error while retrieving JWKS for key: " + keyNameRsa);
            assertThat(ex.getCause()).isEqualTo(storageEx);

            // Verify interactions
            verify(storageBackend).isDirectory(eq(relativeVersionsPathRsa));
            verify(storageBackend).listDirectory(eq(relativeVersionsPathRsa));
            verify(storageBackend, never()).get(startsWith("jwt/keys/" + keyNameRsa + "/versions/"));
            verify(auditHelper).logInternalEvent(anyString(), eq("get_jwks"), eq("failure"), any(), any());
        }


        // ... other getJwks failure tests (vault sealed, config not found, material not found, etc.)
        // These tests generally don't need changes as the failures happen *before* or *after*
        // the directory listing logic, OR within getStoredKeyMaterial which already uses storageBackend.
        // Exception: configNotFound test needs updating as config isn't read anymore.
        // Let's remove the configNotFound test from GetJwksTests as getKeyDefinition is called first.

        @Test
        @DisplayName("Fail: Key Definition Not Found (in properties)")
        void getJwks_keyDefinitionNotFound() throws Exception {
            // Arrange
            // Mock the properties chain to return an empty map for keys
            JwtProperties jwtPropertiesMock = mock(JwtProperties.class);
            lenient().when(properties.secrets().jwt()).thenReturn(jwtPropertiesMock);
            when(jwtPropertiesMock.keys()).thenReturn(Collections.emptyMap()); // Key not defined

            // Act & Assert
            JwtKeyNotFoundException ex = assertThrows(JwtKeyNotFoundException.class, () -> {
                jwtSecretsEngine.getJwks(keyNameRsa);
            });
            assertThat(ex.getMessage()).isEqualTo("JWT key configuration not found for name: " + keyNameRsa);

            // Verify minimal interactions (should fail before storage access)
            verify(storageBackend, never()).isDirectory(anyString());
            verify(storageBackend, never()).listDirectory(anyString());
            verify(storageBackend, never()).get(anyString());
            verify(auditHelper).logInternalEvent(anyString(), eq("get_jwks"), eq("failure"), any(), any());
        }


        // --- The Material Not Found test is still relevant ---
        @Test
        @DisplayName("Fail: Key Material Not Found for Listed Version")
        void getJwks_materialNotFoundForListedVersion() throws Exception {
            // Arrange
            // Directory listing succeeds (default setup)
            // Mock getStoredKeyMaterial to throw (or its internal storageBackend.get to return empty)
            // Let's mock storageBackend.get specifically for the material path to return empty
            when(storageBackend.get(eq(materialPathRsa))).thenReturn(Optional.empty());

            // Act & Assert
            // Since the loop continues, it should result in an empty JWK list and throw at the end
            JwtKeyNotFoundException ex = assertThrows(JwtKeyNotFoundException.class, () -> {
                jwtSecretsEngine.getJwks(keyNameRsa);
            });
            assertThat(ex.getMessage()).isEqualTo("No valid key versions found for key: " + keyNameRsa); // Changed assertion


            // Verify interactions
            verify(storageBackend).isDirectory(eq(relativeVersionsPathRsa));
            verify(storageBackend).listDirectory(eq(relativeVersionsPathRsa));
            verify(storageBackend).get(eq(materialPathRsa)); // Attempted to get material
            // Decrypt/Parse for material should not happen
            verify(encryptionService, never()).decrypt(eq(encryptedRsaMaterialBytes));
            verify(objectMapper, never()).readValue(eq(rsaMaterialJsonBytes), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF));
            // Failure audit should happen
            verify(auditHelper).logInternalEvent(anyString(), eq("get_jwks"), eq("failure"), any(), any());
        }


        // --- Other failure tests like Base64 decode, reconstruct, algorithm mapping remain valid ---
        // --- Add a test for multiple versions ---
        @Test
        @DisplayName("Success: Should return JWKS with multiple RSA keys sorted descending")
        void getJwks_successMultipleVersionsRsa() throws Exception {
            // Arrange
            int version1 = 1;
            int version2 = 2;
            String materialPathV1 = String.format("jwt/keys/%s/versions/%d", keyNameRsa, version1);
            String materialPathV2 = String.format("jwt/keys/%s/versions/%d", keyNameRsa, version2);
            String keyIdV1 = keyNameRsa + "-" + version1;
            String keyIdV2 = keyNameRsa + "-" + version2;

            // Mock directory listing with multiple versions (unsorted)
            when(storageBackend.isDirectory(eq(relativeVersionsPathRsa))).thenReturn(true);
            when(storageBackend.listDirectory(eq(relativeVersionsPathRsa))).thenReturn(List.of(version1 + ".json", version2 + ".json"));

            // Mock material retrieval for both versions (need distinct data/mocks)
            // V1 (use setup defaults where possible)
            StoredJwtKeyMaterial rsaMaterialV1 = rsaMaterial; // Reuse setup object
            byte[] rsaMaterialJsonBytesV1 = rsaMaterialJsonBytes;
            byte[] encryptedRsaMaterialBytesV1 = encryptedRsaMaterialBytes;
            EncryptedData encryptedRsaMaterialDataV1 = encryptedRsaMaterialData;
            lenient().when(storageBackend.get(eq(materialPathV1))).thenReturn(Optional.of(encryptedRsaMaterialDataV1));
            lenient().when(encryptionService.decrypt(eq(encryptedRsaMaterialBytesV1))).thenReturn(rsaMaterialJsonBytesV1);
            lenient().when(objectMapper.readValue(eq(rsaMaterialJsonBytesV1), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF))).thenReturn(rsaMaterialV1);

            // V2 (create new distinct data)
            KeyPair rsaKeyPairV2 = generateTestRsaKeyPair(); // Generate distinct key
            PublicKey rsaPublicKeyV2 = rsaKeyPairV2.getPublic();
            byte[] rsaPublicKeyBytesV2 = rsaPublicKeyV2.getEncoded();
            StoredJwtKeyMaterial rsaMaterialV2 = new StoredJwtKeyMaterial(Base64.getEncoder().encodeToString(rsaPublicKeyBytesV2), "dummyEncV2");
            byte[] rsaMaterialJsonBytesV2 = "{\"publicKeyB64\":\"rsaV2...\"}".getBytes();
            byte[] encryptedRsaMaterialBytesV2 = "encRsaMatV2".getBytes(); // Simplified for mock
            // Need to create a valid EncryptedData object for V2
            byte[] nonceV2 = new byte[EncryptionService.NONCE_LENGTH_BYTE]; // Can reuse nonce length
            byte[] cipherV2 = "encRsaMatV2Cipher".getBytes(); // Distinct ciphertext
            ByteBuffer bbV2 = ByteBuffer.allocate(nonceV2.length + cipherV2.length).put(nonceV2).put(cipherV2);
            byte[] encryptedRsaMaterialBytesV2_Full = bbV2.array(); // Full nonce+ciphertext
            EncryptedData encryptedRsaMaterialDataV2 = new EncryptedData(nonceV2, cipherV2); // Correct EncryptedData

            lenient().when(storageBackend.get(eq(materialPathV2))).thenReturn(Optional.of(encryptedRsaMaterialDataV2));
            // Mock decrypt to return the V2 JSON bytes when given the V2 full encrypted bytes
            lenient().when(encryptionService.decrypt(eq(encryptedRsaMaterialBytesV2_Full))).thenReturn(rsaMaterialJsonBytesV2);
            lenient().when(objectMapper.readValue(eq(rsaMaterialJsonBytesV2), eq(JwtSecretsEngine.KEY_MATERIAL_TYPE_REF))).thenReturn(rsaMaterialV2);


            // Act
            Map<String, Object> jwksMap = jwtSecretsEngine.getJwks(keyNameRsa);

            // Assert
            assertThat(jwksMap).isNotNull();
            assertThat(jwksMap).containsKey("keys");
            assertThat(jwksMap.get("keys")).isInstanceOf(List.class);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keysList = (List<Map<String, Object>>) jwksMap.get("keys");
            assertThat(keysList).hasSize(2);

            // Verify sorting (v2 should be first due to descending sort on version)
            assertThat(keysList.get(0)).containsEntry("kid", keyIdV2);
            assertThat(keysList.get(1)).containsEntry("kid", keyIdV1);


            // Verify interactions
            verify(storageBackend).isDirectory(eq(relativeVersionsPathRsa));
            verify(storageBackend).listDirectory(eq(relativeVersionsPathRsa));
            verify(storageBackend).get(eq(materialPathV1)); // Check both were requested
            verify(storageBackend).get(eq(materialPathV2));

            // Verify Audit Log
            ArgumentCaptor<Map<String, Object>> auditCaptor = ArgumentCaptor.forClass(Map.class);
            verify(auditHelper).logInternalEvent(
                    eq("jwt_operation"), eq("get_jwks"), eq("success"), isNull(), auditCaptor.capture()
            );
            // Order in the list doesn't strictly matter for assertion
            assertThat(auditCaptor.getValue())
                    .containsEntry("key_name", keyNameRsa)
                    .hasEntrySatisfying("versions_included", versions -> {
                        // Use AssertJ's standard list assertion
                        assertThat(versions)
                                .asInstanceOf(InstanceOfAssertFactories.list(Integer.class))
                                .containsExactlyInAnyOrder(version1, version2);
                    });
        }


    } // End Nested class GetJwksTests

    // --- Task 3.5: reconstructPrivateKey / reconstructPublicKey Tests ---
    // NOTE: These tests use Reflection to access private methods directly,
    // fulfilling the explicit requirement of Task 3.5 in the plan.
    // Generally, testing private methods directly makes tests brittle.
    // A better long-term approach would be indirect testing via public methods
    // (signJwt, getJwks) or refactoring these helpers into a testable utility class.

    // --- Task 3.5: reconstructPrivateKey / reconstructPublicKey Tests ---

    @Nested
    @DisplayName("reconstructPrivateKey Tests (using Reflection)")
    class ReconstructPrivateKeyTests {

        private Method getReconstructPrivateKeyMethod() throws NoSuchMethodException {
            // Get the private method signature: reconstructPrivateKey(byte[], MssmProperties.JwtKeyType)
            Method method = JwtSecretsEngine.class.getDeclaredMethod(
                    "reconstructPrivateKey", byte[].class, MssmProperties.JwtKeyType.class
            );
            method.setAccessible(true); // Make it callable
            return method;
        }

        @Test
        @DisplayName("Should reconstruct valid RSA private key")
        void reconstructPrivateKey_validRsa() throws Exception {
            // Arrange
            KeyPair rsaKeyPair = generateTestRsaKeyPair();
            byte[] pkcs8Bytes = rsaKeyPair.getPrivate().getEncoded(); // PKCS#8 format
            Method reconstructMethod = getReconstructPrivateKeyMethod();

            // Act
            Object result = reconstructMethod.invoke(jwtSecretsEngine, pkcs8Bytes, JwtKeyType.RSA);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).isInstanceOf(RSAPrivateKey.class);
        }

        @Test
        @DisplayName("Should reconstruct valid EC private key")
        void reconstructPrivateKey_validEc() throws Exception {
            // Arrange
            KeyPair ecKeyPair = generateTestEcKeyPair();
            byte[] pkcs8Bytes = ecKeyPair.getPrivate().getEncoded(); // PKCS#8 format
            Method reconstructMethod = getReconstructPrivateKeyMethod();

            // Act
            Object result = reconstructMethod.invoke(jwtSecretsEngine, pkcs8Bytes, JwtKeyType.EC);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).isInstanceOf(ECPrivateKey.class);
        }

        @Test
        @DisplayName("Should throw SecretsEngineException for invalid bytes")
        void reconstructPrivateKey_invalidBytes_shouldThrow() throws Exception {
            // Arrange
            byte[] invalidBytes = new byte[]{1, 2, 3, 4}; // Clearly invalid PKCS#8
            Method reconstructMethod = getReconstructPrivateKeyMethod();

            // Act & Assert
            // Reflection wraps the actual exception in InvocationTargetException
            InvocationTargetException thrown = assertThrows(InvocationTargetException.class, () -> {
                reconstructMethod.invoke(jwtSecretsEngine, invalidBytes, JwtKeyType.RSA);
            });

            // Check the cause chain: InvocationTargetException -> SecretsEngineException -> InvalidKeySpecException
            assertThat(thrown.getCause()).isInstanceOf(SecretsEngineException.class);
            assertThat(thrown.getCause().getMessage()).isEqualTo("Failed to reconstruct private key for signing.");
            assertThat(thrown.getCause().getCause()).isInstanceOf(InvalidKeySpecException.class);
        }
    }

    @Nested
    @DisplayName("reconstructPublicKey Tests (using Reflection)")
    class ReconstructPublicKeyTests {

        private Method getReconstructPublicKeyMethod() throws NoSuchMethodException {
            // Get the private method signature: reconstructPublicKey(byte[], MssmProperties.JwtKeyType)
            Method method = JwtSecretsEngine.class.getDeclaredMethod(
                    "reconstructPublicKey", byte[].class, MssmProperties.JwtKeyType.class
            );
            method.setAccessible(true); // Make it callable
            return method;
        }

        @Test
        @DisplayName("Should reconstruct valid RSA public key")
        void reconstructPublicKey_validRsa() throws Exception {
            // Arrange
            KeyPair rsaKeyPair = generateTestRsaKeyPair();
            byte[] x509Bytes = rsaKeyPair.getPublic().getEncoded(); // X.509 format
            Method reconstructMethod = getReconstructPublicKeyMethod();

            // Act
            Object result = reconstructMethod.invoke(jwtSecretsEngine, x509Bytes, JwtKeyType.RSA);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).isInstanceOf(RSAPublicKey.class);
        }

        @Test
        @DisplayName("Should reconstruct valid EC public key")
        void reconstructPublicKey_validEc() throws Exception {
            // Arrange
            KeyPair ecKeyPair = generateTestEcKeyPair();
            byte[] x509Bytes = ecKeyPair.getPublic().getEncoded(); // X.509 format
            Method reconstructMethod = getReconstructPublicKeyMethod();

            // Act
            Object result = reconstructMethod.invoke(jwtSecretsEngine, x509Bytes, JwtKeyType.EC);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).isInstanceOf(ECPublicKey.class);
        }

        @Test
        @DisplayName("Should throw SecretsEngineException for invalid bytes")
        void reconstructPublicKey_invalidBytes_shouldThrow() throws Exception {
            // Arrange
            byte[] invalidBytes = new byte[]{1, 2, 3, 4}; // Clearly invalid X.509
            Method reconstructMethod = getReconstructPublicKeyMethod();

            // Act & Assert
            InvocationTargetException thrown = assertThrows(InvocationTargetException.class, () -> {
                reconstructMethod.invoke(jwtSecretsEngine, invalidBytes, JwtKeyType.RSA);
            });

            // Check the cause chain: InvocationTargetException -> SecretsEngineException -> InvalidKeySpecException
            assertThat(thrown.getCause()).isInstanceOf(SecretsEngineException.class);
            assertThat(thrown.getCause().getMessage()).isEqualTo("Failed to reconstruct public key.");
            assertThat(thrown.getCause().getCause()).isInstanceOf(InvalidKeySpecException.class);
        }
    }

    // --- End Task 3.5 ---


    private static KeyPair generateTestRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048); // Use a valid size
        return kpg.generateKeyPair();
    }

    private static KeyPair generateTestEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        // Use a valid curve name consistent with config/engine
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecSpec);
        return kpg.generateKeyPair();
    }

}