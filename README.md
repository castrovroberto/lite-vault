# LiteVault - Minimal Secure Secrets Manager

[![Version](https://img.shields.io/badge/version-0.4.0-blue.svg)](https://github.com/your-repo/lite-vault)
[![Java](https://img.shields.io/badge/Java-21-orange.svg)](https://openjdk.java.net/projects/jdk/21/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-green.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A lightweight, secure secrets management solution inspired by HashiCorp Vault, built with Java 21 and Spring Boot.

## 🎯 Purpose

LiteVault provides a centralized, secure system for managing sensitive information including:
- **Dynamic Database Credentials** - Generate temporary database users with automatic cleanup
- **JWT Key Management** - Automated key rotation and signing capabilities  
- **Static Secrets Storage** - Secure storage for API keys, passwords, and configuration
- **Audit Logging** - Complete audit trail of all secret operations

Perfect for organizations needing enterprise-grade secrets management without the complexity of full Vault deployments.

## 🏗️ Architecture

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   HTTP API      │    │  Authentication  │    │  Authorization  │
│  (Spring Boot)  │◄──►│   (Tokens)      │◄──►│   (Policies)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                                               │
         ▼                                               ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Secrets Engines │    │ Encryption Layer │    │  Audit System   │
│  KV │ DB │ JWT  │◄──►│   AES-256-GCM   │    │   (Structured)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌──────────────────┐
│ Storage Backend │    │   Seal Manager   │
│  (Filesystem)   │    │  (Key Lifecycle) │
└─────────────────┘    └──────────────────┘
```

### Security Model

- **🔐 Encryption at Rest**: AES-256-GCM for all stored data
- **🔒 TLS in Transit**: HTTPS with configurable certificates  
- **🗝️ Seal/Unseal**: Vault starts sealed, requires master key to operate
- **👤 Authentication**: Token-based access control
- **🛡️ Authorization**: Policy-based permissions (ACL)
- **📝 Audit Logging**: Complete audit trail in structured JSON

## ✨ Features

### 🗃️ Key-Value Storage
- Store and retrieve arbitrary key-value pairs
- Automatic encryption of all data
- RESTful API with path-based organization

### 🗄️ Dynamic Database Credentials  
- Generate temporary PostgreSQL users on-demand
- Configurable TTL and permissions
- Automatic credential revocation
- Support for custom SQL templates

### 🔑 JWT Management
- RSA and ECDSA key generation
- Automatic key rotation
- JWKS endpoint for public key distribution
- Version management for seamless rotation

### 🔍 Audit & Monitoring
- Structured JSON audit logs
- Authentication and authorization events  
- All secret operations tracked
- No sensitive data in logs

## 🚀 Quick Start

### Prerequisites
- Java 21+
- Maven 3.6+
- PostgreSQL (for dynamic credentials)

### 1. Generate TLS Certificate
```bash
./generate-keystore.sh
export MSSM_KEYSTORE_PASSWORD="your-secure-password"
```

### 2. Set Master Key
```bash
export MSSM_MASTER_B64=$(openssl rand -base64 32)
```

### 3. Configure Database (Optional)
```bash
export MSSM_DB_POSTGRES_PASSWORD="your-db-admin-password"
```

### 4. Build & Run
```bash
mvn clean package
java -jar target/lite-vault-*.jar
```

### 5. Test the API
```bash
# Check status
curl -k https://localhost:8443/

# Store a secret (requires token)
curl -k -X PUT \
  -H "X-Vault-Token: dev-token-123" \
  -H "Content-Type: application/json" \
  -d '{"password": "secret123"}' \
  https://localhost:8443/v1/kv/data/myapp/config

# Get dynamic DB credentials
curl -k -H "X-Vault-Token: dev-token-123" \
  https://localhost:8443/v1/db/creds/readonly
```

## 📖 API Documentation

Once running, access the interactive API documentation:

- **Swagger UI**: https://localhost:8443/swagger-ui.html
- **OpenAPI Spec**: https://localhost:8443/v3/api-docs

### Key Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/kv/data/{path}` | GET/PUT/DELETE | Key-value operations |
| `/v1/db/creds/{role}` | GET | Generate DB credentials |
| `/v1/jwt/sign/{key}` | POST | Sign JWT tokens |
| `/v1/jwt/jwks/{key}` | GET | Public keys (JWKS) |
| `/v1/jwt/rotate/{key}` | POST | Rotate signing keys |
| `/sys/seal-status` | GET | Check seal status |

## ⚙️ Configuration

### Environment Variables
```bash
# Required
MSSM_MASTER_B64=<base64-encoded-master-key>
MSSM_KEYSTORE_PASSWORD=<keystore-password>

# Database (if using dynamic credentials)
MSSM_DB_POSTGRES_PASSWORD=<admin-password>
```

### Key Configuration Sections

<details>
<summary>📝 <strong>Static Tokens & Policies</strong></summary>

```yaml
mssm:
  auth:
    static-tokens:
      enabled: true
      mappings:
        - token: "admin-token"
          policies: ["admin-policy"]
        - token: "app-token"  
          policies: ["kv-reader", "db-user"]

  policies:
    admin-policy:
      rules:
        - path: "*"
          capabilities: ["READ", "WRITE", "DELETE"]
    kv-reader:
      rules:
        - path: "kv/data/*"
          capabilities: ["READ"]
```
</details>

<details>
<summary>🗄️ <strong>Database Roles</strong></summary>

```yaml
mssm:
  secrets:
    db:
      postgres:
        connection-url: "jdbc:postgresql://localhost:5432/myapp"
        username: "litevault_admin"
        roles:
          readonly:
            creation-statements:
              - "CREATE ROLE \"{{username}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
              - "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{username}}\";"
            revocation-statements:
              - "DROP ROLE IF EXISTS \"{{username}}\";"
            default-ttl: "1h"
```
</details>

<details>
<summary>🔑 <strong>JWT Keys</strong></summary>

```yaml
mssm:
  secrets:
    jwt:
      keys:
        api-signing-key:
          type: "RSA"
          key-size: 2048
          rotation-period: "24h"
        mobile-signing-key:
          type: "EC"
          curve: "P-256"
          rotation-period: "168h"
```
</details>

## 🧪 Testing

### Unit Tests
```bash
mvn test
```

### Integration Tests  
```bash
mvn test -Dtest=*IntegrationTest
```

### Manual Testing Script
```bash
./lite-vault-cli.sh
```

## 🔧 Development

### Project Structure
```
src/main/java/tech/yump/vault/
├── api/           # REST controllers
├── auth/          # Authentication & authorization
├── config/        # Configuration classes
├── crypto/        # Encryption services
├── secrets/       # Secrets engines (KV, DB, JWT)
├── storage/       # Storage backends
├── audit/         # Audit logging
└── seal/          # Seal/unseal management
```

### Adding New Secrets Engines

1. Implement `SecretsEngine` or `DynamicSecretsEngine`
2. Add configuration properties
3. Register in Spring context
4. Add API endpoints
5. Include audit logging

## 🔒 Security Considerations

### Production Deployment
- [ ] Use CA-signed certificates (not self-signed)
- [ ] Secure master key distribution 
- [ ] Network segmentation for database access
- [ ] Regular key rotation policies
- [ ] Monitor audit logs
- [ ] Backup encryption keys securely

### Known Limitations
- Single-node deployment only
- File-based storage backend
- Manual unsealing required
- No built-in secret versioning (KV engine)

## 📚 Documentation

- [Configuration Guide](docs/configuration.md) *(Coming Soon)*
- [API Reference](docs/api.md) *(Coming Soon)*
- [Security Best Practices](docs/security.md) *(Coming Soon)*
- [Deployment Guide](docs/deployment.md) *(Coming Soon)*

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Inspired by [HashiCorp Vault](https://www.vaultproject.io/) and built with:
- [Spring Boot](https://spring.io/projects/spring-boot)
- [BouncyCastle](https://www.bouncycastle.org/)
- [JJWT](https://github.com/jwtk/jjwt)

---

<div align="center">
  <sub>Built with ❤️ for secure secrets management</sub>
</div>