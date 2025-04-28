# Task 8: Configure Basic TLS for API Server

## Goal
Secure the API communication by enabling HTTPS using a self-signed certificate for local development.  
This fulfills requirement **NFR-SEC-110** (TLS 1.2+ in transit) and builds upon **F-CORE-150** (TLS-secured REST API).

## Prerequisites
- Task 6 & 7 completed (HTTP server running, basic endpoints exist).
- JDK installed (includes the `keytool` utility).
- Spring Boot Web (`spring-boot-starter-web`) is configured.

## Step-by-Step Implementation

### Step 1: Generate a Keystore with a Self-Signed Certificate
We need a certificate and private key to enable TLS.

1. Open a Terminal or Command Prompt.
2. Run `keytool` with the following command:

```bash
keytool -genkeypair     -alias litevault     -keyalg RSA     -keysize 2048     -storetype PKCS12     -keystore src/main/resources/litevault-keystore.p12     -validity 365     -storepass <password>     -keypass <password>     -dname "CN=localhost, OU=Development, O=LiteVault, L=City, ST=State, C=US"
```

- **Explanation**:
  - `-alias litevault`: Alias to identify this certificate.
  - `-keyalg RSA`: RSA algorithm.
  - `-keysize 2048`: 2048-bit key.
  - `-storetype PKCS12`: Modern keystore format.
  - `-keystore src/main/resources/litevault-keystore.p12`: Location of the keystore.
  - `-validity 365`: Certificate valid for 1 year.
  - `-dname`: Distinguished name with Common Name `localhost`.

3. Verify that `litevault-keystore.p12` exists.

### Step 2: Configure Spring Boot for SSL/TLS

Edit `src/main/resources/application.properties`:

```properties
# --- Server Configuration ---
server.port=8443

# --- SSL/TLS Configuration ---
server.ssl.enabled=true
server.ssl.key-store=classpath:litevault-keystore.p12
server.ssl.key-store-password=<password>
server.ssl.key-store-type=PKCS12
server.ssl.key-alias=litevault
server.ssl.protocol=TLS
server.ssl.enabled-protocols=TLSv1.3,TLSv1.2

# --- Other Configurations ---
mssm.storage.filesystem.path=./lite-vault-data
# mssm.master.key.b64=YOUR_GENERATED_BASE64_KEY_HERE
```

- **Key Points**:
  - Enforces secure HTTPS communication.
  - Limits protocols to TLS 1.2 and 1.3.

### Step 3: Add Keystore to `.gitignore`

Update `.gitignore`:

```
# Keystore files
*.p12
*.jks
*.keystore
```

### Step 4: Run and Verify

1. Run the application:

```bash
mvn spring-boot:run
```

2. Check server logs:

```
Tomcat started on port(s): 8443 (https)
```

3. Test the endpoint with `curl`:

```bash
curl -k https://localhost:8443/sys/seal-status
```

Expected JSON output:

```json
{"sealed":true}
```

4. Confirm HTTP requests fail:

```bash
curl http://localhost:8080/sys/seal-status # Should fail
```

5. Optional: Access via browser (accept the self-signed cert warning).

---

## Completion of Task 8

- ✅ A self-signed keystore (`litevault-keystore.p12`) was generated.
- ✅ Spring Boot server was configured for SSL/TLS.
- ✅ Only secure TLS 1.2 and 1.3 protocols enabled.
- ✅ Verified secure HTTPS access with `curl`.

## What's Achieved

The API server communication is now encrypted using TLS, securing data in transit, and fulfilling **NFR-SEC-110** for local development.

---

## Next Step

**Task 9: Implement Basic Configuration Loading.**
