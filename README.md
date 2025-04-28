# Minimal Secure Secrets Manager (MSSM) - LiteVault

**Version:** 1.0.0-SNAPSHOT

A minimal implementation of a secure secrets manager inspired by HashiCorp Vault, focusing on core security primitives and essential features like dynamic secrets and key rotation. Built with Java 21 and Spring Boot.

## Project Goal

To provide a secure, centralized system for managing dynamic database credentials, JWT key rotation, and secure storage of static secrets (like password peppers), reducing risks associated with hardcoded or statically managed sensitive information.

*(Keep Introduction, Scope, etc. if you have them)*

## Current Status & Features (In Progress)

- **Project Setup:** Maven project initialized with Java 21 and Spring Boot. Basic directory structure and `.gitignore` in place.
- **Core Encryption:**
    - **Implemented:** Foundational cryptographic layer using **AES-256-GCM** (`EncryptionService.java`). Provides authenticated encryption for data at rest.
    - **Note:** Currently uses a temporary, hardcoded key for testing (See Security section).
- **Storage:** JSON format (`EncryptedData.java`) for persistent storage (version, Base64 nonce/cyphertext, timestamp).
    - **Implemented:** Basic persistence layer via `FileSystemStorageBackend`, storing encrypted JSON blobs on local disk. Configurable path via properties. 
- **Sealing:** *Not Implemented
- **API:** *Not Implemented*
- **Authentication/Authorization:** *Not Implemented*
- **Secrets Engines:** *Not Implemented*

## Security Considerations

- **Encryption at Rest:** Core data is encrypted using AES-256-GCM `EncryptionService` and stored persistengly as JSON files via the `FileSystemStorageBackend` (NFR-SEC-100, F-CORE-100).
- **Encryption in Transit:** API communication will be secured via TLS 1.2+ (NFR-SEC-110). *(Planned)*
- **Sealing:** The master encryption key will not be persisted directly. An unseal mechanism will be required to load the key into memory (F-CORE-140). *(Planned)*
- **Temporary Key:** The current `EncryptionService` uses a **temporary, insecure, hardcoded key** for development. This is a critical placeholder and **must** be replaced by the secure sealing/unsealing mechanism (Task 5).

## Getting Started

*(Instructions for building/running will go here later)*

## Project Roadmap (Atomic Tasks - Phase 1)

Based on `project/mssm-atomic-tasks-v1-0.md`:

- [x] **Task 1:** Initialize Project & Basic Structure
- [x] **Task 2:** Implement Core Encryption/Decryption Logic (AES-GCM)
- [x] **Task 3:** Define Encrypted Storage Format
- [x] **Task 4:** Implement Basic File System Storage Backend
- [ ] **Task 5:** Implement Core Seal/Unseal Logic
- [ ] **Task 6:** Set Up Minimal HTTP Server & Routing
- [ ] **Task 7:** Create `/sys/seal-status` API Endpoint
- [ ] **Task 8:** Configure Basic TLS for API Server
- [ ] **Task 9:** Implement Basic Configuration Loading
- [ ] **Task 10:** Write Unit Tests for Encryption & Storage

*(Keep other sections like Contributing, License etc. if you have them)*

---