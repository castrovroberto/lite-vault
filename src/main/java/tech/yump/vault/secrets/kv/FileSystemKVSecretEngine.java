package tech.yump.vault.secrets.kv;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import tech.yump.vault.core.VaultSealedException;
import tech.yump.vault.crypto.EncryptionService;
import tech.yump.vault.storage.EncryptedData;
import tech.yump.vault.storage.StorageBackend;
import tech.yump.vault.storage.StorageException;

@Slf4j
@Service
@RequiredArgsConstructor
public class FileSystemKVSecretEngine implements KVSecretEngine {

    private final StorageBackend storageBackend;
    private final EncryptionService encryptionService;
    private final ObjectMapper objectMapper;

    private static final TypeReference<Map<String, String>> MAP_TYPE_REFERENCE = new TypeReference<>() {};

    @Override
    public Optional<Map<String, String>> read(String path) throws KVEngineException {
        validatePath(path);
        log.debug("Attempting to read KV secrets from path: {}", path);

        try {
            Optional<EncryptedData> encryptedDataOptional = storageBackend.get(path);

            if (encryptedDataOptional.isEmpty()) {
                log.debug("No KV secrets found at path: {}", path);
                return Optional.empty();
            }

            EncryptedData storedData = encryptedDataOptional.get();

            // --- CORRECTED DECRYPTION ---
            // 1. Get nonce and ciphertext bytes separately from EncryptedData
            byte[] nonce = storedData.getNonceBytes();
            byte[] ciphertext = storedData.getCiphertextBytes();

            // 2. Combine them back into the format expected by EncryptionService.decrypt
            ByteBuffer byteBuffer = ByteBuffer.allocate(nonce.length + ciphertext.length);
            byteBuffer.put(nonce);
            byteBuffer.put(ciphertext);
            byte[] nonceAndCiphertext = byteBuffer.array();

            // 3. Decrypt the combined byte array
            byte[] decryptedBytes = encryptionService.decrypt(nonceAndCiphertext);
            // --- END CORRECTION ---

            // Deserialize the byte array back into a Map
            Map<String, String> secrets = objectMapper.readValue(decryptedBytes, MAP_TYPE_REFERENCE);
            log.info("Successfully read and decrypted KV secrets from path: {}", path);
            return Optional.of(secrets);

        } catch (StorageException e) {
            log.error("Storage error reading KV secrets from path {}: {}", path, e.getMessage(), e);
            throw new KVEngineException("Failed to read secrets from storage at path: " + path, e);
        } catch (VaultSealedException e) {
            log.warn("Cannot read KV secrets from path {}: Vault is sealed.", path);
            throw new KVEngineException("Vault is sealed, cannot decrypt secrets.", e);
        } catch (EncryptionService.EncryptionException e) {
            log.error("Decryption error reading KV secrets from path {}: {}", path, e.getMessage(), e);
            // Could indicate data corruption or wrong key
            throw new KVEngineException("Failed to decrypt secrets at path: " + path, e);
        } catch (IOException e) { // Catch Jackson deserialization errors
            log.error("Deserialization error reading KV secrets from path {}: {}", path, e.getMessage(), e);
            // This might happen if the stored data is corrupted or not a valid map JSON
            throw new KVEngineException("Failed to parse secrets data at path: " + path, e);
        } catch (IllegalStateException | IllegalArgumentException e) { // Catch potential Base64 errors from EncryptedData
            log.error("Error processing stored encrypted data structure for path {}: {}", path, e.getMessage(), e);
            throw new KVEngineException("Failed to process stored data structure at path: " + path, e);
        }
    }

    @Override
    public void write(String path, Map<String, String> secrets) throws KVEngineException {
        validatePath(path);
        if (secrets == null) {
            throw new IllegalArgumentException("Secrets map cannot be null for write operation.");
        }
        log.debug("Attempting to write KV secrets to path: {}", path);

        try {
            // Serialize the Map to JSON bytes
            byte[] plaintextBytes = objectMapper.writeValueAsBytes(secrets);

            // --- CORRECTED ENCRYPTION ---
            // 1. Encrypt the JSON bytes - returns combined nonce || ciphertext
            byte[] nonceAndCiphertext = encryptionService.encrypt(plaintextBytes);

            // 2. Split the combined array into nonce and ciphertext parts
            //    (Assuming NONCE_LENGTH_BYTE is accessible or known, e.g., 12)
            //    It's better if EncryptionService provides this constant or a helper.
            //    Let's hardcode 12 for now based on EncryptionService.NONCE_LENGTH_BYTE
            final int nonceLength = EncryptionService.NONCE_LENGTH_BYTE; // Use the constant
            if (nonceAndCiphertext.length < nonceLength) {
                throw new KVEngineException("Encrypted data is too short, indicates an encryption error.");
            }
            ByteBuffer bb = ByteBuffer.wrap(nonceAndCiphertext);
            byte[] nonce = new byte[nonceLength];
            bb.get(nonce);
            byte[] ciphertext = new byte[bb.remaining()];
            bb.get(ciphertext);

            // 3. Create the EncryptedData object for storage
            EncryptedData dataToStore = new EncryptedData(nonce, ciphertext);
            // --- END CORRECTION ---

            // Store the structured EncryptedData object using the path as the key
            storageBackend.put(path, dataToStore);
            log.info("Successfully encrypted and wrote KV secrets to path: {}", path);

        } catch (JsonProcessingException e) {
            log.error("Serialization error writing KV secrets to path {}: {}", path, e.getMessage(), e);
            throw new KVEngineException("Failed to serialize secrets map for path: " + path, e);
        } catch (VaultSealedException e) {
            log.warn("Cannot write KV secrets to path {}: Vault is sealed.", path);
            throw new KVEngineException("Vault is sealed, cannot encrypt secrets.", e);
        } catch (EncryptionService.EncryptionException e) {
            log.error("Encryption error writing KV secrets to path {}: {}", path, e.getMessage(), e);
            throw new KVEngineException("Failed to encrypt secrets for path: " + path, e);
        } catch (StorageException e) {
            log.error("Storage error writing KV secrets to path {}: {}", path, e.getMessage(), e);
            throw new KVEngineException("Failed to write secrets to storage at path: " + path, e);
        }
    }

    @Override
    public void delete(String path) throws KVEngineException {
        validatePath(path);
        log.debug("Attempting to delete KV secrets at path: {}", path);

        try {
            storageBackend.delete(path);
            log.info("Successfully requested deletion of KV secrets at path: {} (if they existed)", path);
        } catch (StorageException e) {
            log.error("Storage error deleting KV secrets at path {}: {}", path, e.getMessage(), e);
            throw new KVEngineException("Failed to delete secrets from storage at path: " + path, e);
        }
    }

    private void validatePath(String path) {
        if (!StringUtils.hasText(path)) {
            throw new IllegalArgumentException("Path cannot be null or empty.");
        }
        // Add any additional path validation specific to the KV engine if needed
        // For now, rely on StorageBackend's validation for traversal etc.
        // We might want to enforce a prefix like "kv/" later, but for now, accept any valid storage key.
    }
}