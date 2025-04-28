
# MSSM Administrator and Application Journey Manual

## Administrator Journeys

### Journey 1: Initial Setup and Unsealing
- **User:** Administrator
- **Goal:** Get the MSSM instance running securely and ready for configuration/use.
- **Prerequisites:** Access to the server where MSSM will run, ability to set environment variables or configuration files.

**Steps:**
1. Generate the TLS keystore (`litevault-keystore.p12`) using the provided script or keytool.
2. Securely generate a strong AES-256 master key (e.g., using `openssl rand -base64 32`).
3. Configure the environment:
    - Set `MSSM_KEYSTORE_PASSWORD` environment variable to the keystore password.
    - Set `MSSM_MASTER_B64` environment variable (or `mssm.master.b64` property) to the Base64 encoded master key.
    - Configure the storage path (`mssm.storage.filesystem.path` property).
4. Start the MSSM application (e.g., `java -jar lite-vault.jar`).
5. Verify startup: Check logs for successful unsealing message.
6. Verify operational status: Make an HTTPS request to `GET /sys/seal-status` and expect `{"sealed": false}`.

**Outcome:** MSSM is running, unsealed, listening on HTTPS, and ready to serve requests.

---

### Journey 2: Configuring Static Secret Access (KV Store)
- **User:** Administrator
- **Goal:** Define a static token and policy for an application to access a designated KV store path.

**Steps:**
1. Decide on a logical path for the application's secrets (e.g., `kv/data/my-app/config`).
2. Generate a secure, unique static token (e.g., using `openssl rand -hex 16`).
3. Define a policy granting read/write/delete to the path.
4. Associate the static token with the policy.
5. Restart/reload MSSM to apply configuration.
6. Securely provide the token to the application owner.

**Outcome:** Application now has token-based access to specific KV paths.

---

### Journey 3: Configuring Dynamic Database Credential Access (PostgreSQL)
- **User:** Administrator
- **Goal:** Configure MSSM to issue temporary PostgreSQL credentials.

**Steps:**
1. Define a MSSM role and SQL for user creation/revocation.
2. Configure database connection details and credentials.
3. Define token and policy for the application.
4. Restart MSSM.
5. Distribute the token securely.

**Outcome:** Application obtains temporary, short-lived database credentials.

---

### Journey 4: Configuring and Rotating a JWT Signing Key
- **User:** Administrator
- **Goal:** Manage and rotate JWT signing keys via MSSM.

**Steps (Setup):**
1. Configure named JWT key and parameters.
2. Define policies for signing and rotating the key.
3. Associate policies with tokens.
4. Restart MSSM.

**Steps (Manual Rotation):**
1. POST to `/v1/jwt/rotate/<key-name>` using admin token.
2. Confirm rotation through JWKS endpoint.

**Outcome:** Secure JWT key management and rotation.

---

## Application/Service Journeys

### Journey 5: Retrieving a Static Secret (KV Store)
- **User:** Application/Service
- **Goal:** Fetch static configuration secrets securely.

**Steps:**
1. Send a GET request to `https://mssm-host:8443/v1/kv/data/<path>` with token.
2. Parse JSON response for configuration values.

**Outcome:** Application retrieves static secrets securely.

---

### Journey 6: Obtaining Dynamic Database Credentials (PostgreSQL)
- **User:** Application/Service
- **Goal:** Fetch temporary credentials for database access.

**Steps:**
1. Send a request to `https://mssm-host:8443/v1/db/creds/<role>`.
2. Parse response for username, password, lease_id, and TTL.

**Outcome:** Application connects to the database securely with short-lived credentials.

---

### Journey 7: Requesting a Signed JWT
- **User:** Application/Service
- **Goal:** Obtain a centrally signed JWT.

**Steps:**
1. POST claims JSON to `/v1/jwt/sign/<key-name>` with token.
2. Receive and use signed JWT.

**Outcome:** Application gets JWTs signed with managed keys.

---

### Journey 8: Verifying a Signed JWT (Resource Server)
- **User:** Application/Service
- **Goal:** Validate JWTs using MSSM public keys.

**Steps:**
1. Fetch JWKS from `/v1/jwt/jwks/<key-name>`.
2. Validate JWTs using received public keys.

**Outcome:** Resource servers validate JWTs securely without needing private keys.

---

## Summary
This manual outlines the core administrative and service journeys needed to securely deploy, manage, and use MSSM functionalities. These journeys cover initial setup, secret management, dynamic database credential issuance, JWT signing and validation — enabling a fully functional secret management lifecycle.
