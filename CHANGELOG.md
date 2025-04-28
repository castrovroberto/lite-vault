# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **File System Storage Backend (Task 4):**
  - Defined `StorageBackend` interface for persistence operations (`put`, `get`, `delete`).
  - Implemented `FileSystemStorageBackend` as a Spring `@Component`.
  - Stores/Retrieves `EncryptedData` DTOs as JSON files on the local filesystem.
  - Uses Jackson `ObjectMapper` for JSON serialization/deserialization.
  - Implements path resolution with sanitization and validation to prevent traversal.
  - Base storage path configurable via `mssm.storage.filesystem.path` property (defaults to `./vault-data`).
  - Includes `@PostConstruct` validation for base path existence and permissions.
  - Added custom `StorageException` for storage-related errors.
- **Encrypted Storage Format Definition (Task 3):**
  - Defined a JSON structure for storing encrypted data (`nonce`, `ciphertext`, `version`, `timestamp`).
  - Created `EncryptedData.java` DTO in `tech.yump.vault.storage` package to represent this format.
  - Uses Base64 encoding for nonce and ciphertext within the JSON structure.
  - Added convenience methods in `EncryptedData` for Base64 encoding/decoding.
  - Leverages Jackson (via Spring Boot Web) for future JSON serialization/deserialization.
  - Implemented `EncryptionService.java` providing core cryptographic operations.
  - Uses **AES-256-GCM** for authenticated encryption (AEAD), fulfilling NFR-SEC-100.
  - Generates a unique 12-byte nonce per encryption operation, prepended to the ciphertext.
  - Handles nonce extraction and GCM tag verification during decryption.
  - Added custom `EncryptionService.EncryptionException` for cryptographic errors.
  - Registered BouncyCastle security provider (`bcprov-jdk18on`) for JCE operations.
  - Added basic SLF4j logging to the service.
  - Initialized project structure with Maven and Spring Boot parent.
  - Configured `pom.xml` with Java 21, Spring Boot dependencies (Web, Test), Lombok, and BouncyCastle.
  - Added standard `.gitignore` file.
  - Created basic `src/main/java` and `src/test/java` directory structures.
  - Added placeholder `LiteVaultApplication` and `LiteVaultApplicationTest`.

### Security


 ---
