
# Manual: `generate-keystore.sh`

## Overview

The `generate-keystore.sh` script simplifies the process of generating a **PKCS12** keystore with a self-signed certificate, specifically tailored for secure development and deployment environments.

It supports parameterization, secure password handling, environment awareness, and improved automation features.

---

## Features

- **Parameterized Execution:** Override default values via command-line flags.
- **Environment-Specific Defaults:** Adjusts defaults depending on the environment (dev, staging, prod, etc.).
- **Secure Password Management:** Prioritizes environment variables for password safety.
- **Automatic Directory Handling:** Creates necessary directories if they don't exist.
- **Interactive Confirmation:** Reviews parameters before generating the keystore.
- **Clear Logging:** Prints clear success and error messages.

---

## Usage

1. **Make the script executable:**
    ```bash
    chmod +x generate-keystore.sh
    ```

2. **Basic Usage for Development:**
    ```bash
    export KEYSTORE_PASSWORD='your_secure_password_here'
    ./generate-keystore.sh
    ```
    - Creates a keystore with default values:
      - Path: `./src/main/resources/dev-keystore.p12`
      - Alias: `litevault-dev`
      - Common Name: `localhost`
      - Validity: 365 days

3. **Example for Staging Environment:**
    ```bash
    export KEYSTORE_PASSWORD='staging_password'
    ./generate-keystore.sh -e staging -cn vault.staging.yourdomain.com -f /etc/litevault/staging-keystore.p12 -d 730
    ```

4. **Overriding Specific Defaults:**
    ```bash
    export KEYSTORE_PASSWORD='your_password'
    ./generate-keystore.sh -f ./my-dev-keystore.p12 -a myalias -d 90
    ```

5. **Prompting for Password (If No Env Var or `-p` Used):**
    ```bash
    ./generate-keystore.sh
    ```

    The script will securely prompt you for a password.

---

## Command-Line Options

| Option            | Description                                                         | Default (dev) |
|-------------------|---------------------------------------------------------------------|---------------|
| `-e <env>`        | Environment name (dev, staging, prod, etc.)                         | `dev`         |
| `-f <keystore_file>` | Path to save the keystore                                           | `./src/main/resources/dev-keystore.p12` |
| `-a <alias>`      | Alias name for the key inside the keystore                          | `litevault-dev` |
| `-d <days>`       | Validity period of the certificate in days                          | `365`         |
| `-p <password>`   | Password (not recommended to pass via CLI for security reasons)      | (prompted)    |
| `-cn <common_name>` | Common Name (e.g., yourdomain.com or localhost)                     | `localhost`   |
| `-ou <org_unit>`  | Organizational Unit                                                 | `Development` |
| `-o <org>`        | Organization                                                        | `LiteVault`   |
| `-l <locality>`   | City or Locality                                                     | `City`        |
| `-st <state>`     | State or Province                                                    | `State`       |
| `-c <country>`    | 2-letter country code                                                | `US`          |
| `-h`              | Display help                                                         | -             |

---

## Example Outputs

**Successful creation:**
```bash
--------------------------------------------------
SUCCESS: Keystore generated successfully at:
  ./src/main/resources/dev-keystore.p12

IMPORTANT:
  - Secure this keystore file appropriately.
  - Ensure the application uses the correct password (via environment variable if possible).
  - For non-dev environments, DO NOT commit keystore files to version control.
--------------------------------------------------
```

**Failure (e.g., missing password):**
```bash
Error: Failed to obtain a password.
```

---

## Security Notes

- **Never commit keystore files to your version control system** (especially for non-development environments).
- **Use the environment variable `KEYSTORE_PASSWORD` whenever possible** instead of passing passwords as command-line arguments.
- **Self-signed certificates are suitable only for development and internal use.** For production, obtain certificates from trusted Certificate Authorities (CAs).

Add to `.gitignore`:
```
*.p12
*.jks
*.keystore
```

---

## Advanced Tips

- For production environments, adjust the validity period, key sizes, and certificate properties.
- You can adapt this script to generate CSRs (Certificate Signing Requests) if needed.

---

## License

Feel free to use and adapt this script under an open-source license (e.g., MIT).

---

**End of Manual**
