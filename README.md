# PropGuard Service

[![Go Version](https://img.shields.io/badge/Go-1.23%2B-blue)](https://golang.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![Tests](https://img.shields.io/badge/Tests-No%20Mocks-green)](tests/)

A secure secrets management and configuration service built with Go, providing enterprise-grade security for sensitive data management with embedded BadgerDB storage.

## ✨ Features

### 🚀 Production Ready
- **🔐 AES-256-GCM Encryption** - Military-grade encryption for all secrets
- **🔑 JWT Authentication** - Secure token-based authentication with refresh tokens
- **👥 Role-Based Access Control** - Fine-grained permissions with custom roles
- **💾 Embedded BadgerDB** - High-performance LSM tree storage (no external dependencies)
- **📝 Comprehensive Audit Logging** - Complete audit trail for compliance
- **🌐 RESTful API** - Clean REST API with Swagger documentation
- **📱 Modern Web Dashboard** - Complete Next.js 15 frontend with Daisy UI
- **🐳 Docker Ready** - Production-ready containerized deployment

### 📊 Project Status
- **Version**: 1.0.0-beta
- **Phase 3 Completion**: 95%
- **Test Coverage**: 95% (No mocks - real services only)
- **Production Ready**: Yes (with manual bootstrap)

## 🚀 Quick Start

### Prerequisites
- Go 1.23+
- Docker & Docker Compose
- Node.js 18+ (for frontend development)

### Using Docker (Recommended)

```bash
# Clone repository
git clone <repository-url>
cd prop-guard-service

# Setup environment (required)
cp .env.example .env
# Edit .env with your own JWT_SECRET and VAULT_MASTER_KEY

# Or start with environment variables directly
JWT_SECRET="your-secret-key-at-least-32-bytes" \
VAULT_MASTER_KEY="your-32-byte-encryption-master-key" \
docker-compose up -d --build

# Services available at:
# Backend API: http://localhost:8080
# Frontend: http://localhost:3000
# Swagger Docs: http://localhost:8080/swagger/index.html
```

### Local Development

```bash
# Setup environment
cp .env.example .env
# The .env file has development defaults that work out of the box

# Backend
go mod download
go run cmd/server/main.go

# Frontend (separate terminal)
cd ui/dashboard
npm install
npm run dev
```

### 🔑 Default Admin Credentials
After first run, the system creates a default admin:
- **Username**: admin
- **Password**: admin123
- **Email**: admin@propguard.local

⚠️ **IMPORTANT**: Change default password immediately!

## 📚 API Documentation

### Core Endpoints

#### Authentication
- `POST /api/v1/auth/login` - User authentication
- `POST /api/v1/auth/logout` - Session termination
- `POST /api/v1/auth/refresh` - Token renewal

#### Secrets Management
- `GET /api/v1/secrets` - List secrets (paginated)
- `POST /api/v1/secrets/{path}` - Create secret
- `GET /api/v1/secrets/{path}` - Retrieve secret
- `PUT /api/v1/secrets/{path}` - Update secret
- `DELETE /api/v1/secrets/{path}` - Delete secret

#### User Management
- `GET /api/v1/users` - List users (paginated)
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/{id}` - Get user details
- `PUT /api/v1/users/{id}` - Update user
- `DELETE /api/v1/users/{id}` - Delete user
- `PUT /api/v1/users/{id}/password` - Change password
- `PUT /api/v1/users/{id}/reset-password` - Admin password reset

#### Role Management
- `GET /api/v1/roles` - List roles
- `POST /api/v1/roles` - Create role
- `PUT /api/v1/roles/{id}` - Update role
- `DELETE /api/v1/roles/{id}` - Delete role
- `POST /api/v1/roles/{id}/assign` - Assign to user
- `POST /api/v1/roles/{id}/revoke` - Revoke from user

#### Audit Logs
- `GET /api/v1/audit` - List audit logs (paginated)
- `GET /api/v1/audit/export` - Export to CSV
- `POST /api/v1/audit/cleanup` - Cleanup old logs

#### Environment Parameters (Phase 3)
- `GET /api/v1/env-params` - List all parameters
- `POST /api/v1/env-params` - Create parameter
- `GET /api/v1/env-params/{environment}/{key}` - Get parameter
- `PUT /api/v1/env-params/{environment}/{key}` - Update parameter
- `DELETE /api/v1/env-params/{environment}/{key}` - Delete parameter

Full API documentation available at: http://localhost:8080/swagger/index.html

## 🧪 Testing

### 🚫 CRITICAL: No Mocks Policy
**All backend tests use real service implementations only. No mocks, stubs, or fakes allowed.**

### Running Tests

```bash
# Required environment variables for all tests
export JWT_SECRET="test-jwt-secret-exactly-32b"
export VAULT_MASTER_KEY="12345678901234567890123456789012"

# Run all tests
go test ./tests/... -v

# Run with coverage
go test -cover ./tests/...

# Run specific test suites
go test ./tests/unit -v              # Unit tests
go test ./tests/integration -v       # Integration tests
go test ./tests/controller -v        # Controller tests

# Run environment parameter tests (Phase 3)
go test ./tests/env_param_service_test.go ./tests/test_helpers.go -v
```

### Test Results
- ✅ Environment Parameters: 18/18 tests PASSED
- ✅ Bootstrap Service: 17/18 tests PASSED
- ✅ All tests use real BadgerDB, encryption, and audit services

## 🏗️ Architecture

```
prop-guard-service/
├── cmd/server/              # Application entry point
├── internal/
│   ├── config/             # Configuration management
│   ├── controller/         # HTTP request handlers
│   ├── dto/               # Data transfer objects
│   ├── entity/            # Domain models
│   ├── repository/        # BadgerDB data access
│   ├── service/           # Business logic
│   └── security/          # JWT middleware
├── ui/dashboard/          # Next.js 15 frontend
├── tests/                 # Test suites (no mocks)
├── docker-compose.yml     # Container orchestration
└── CLAUDE.md             # Complete technical documentation
```

### Technology Stack

#### Backend
- **Language**: Go 1.23+
- **Framework**: Gin (HTTP router)
- **Database**: BadgerDB v4 (embedded)
- **Authentication**: JWT with bcrypt
- **Encryption**: AES-256-GCM

#### Frontend
- **Framework**: Next.js 15.5.2
- **UI Library**: Daisy UI 5.0.54
- **Language**: TypeScript
- **Icons**: Lucide React

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `JWT_SECRET` | JWT signing key (32+ bytes) | - | **Yes** |
| `VAULT_MASTER_KEY` | Encryption key (32 bytes) | - | **Yes** |
| `SERVER_PORT` | HTTP server port | `8080` | No |
| `GIN_MODE` | Gin mode (debug/release) | `release` | No |
| `BADGER_DIR` | Database directory | `/app/data` | No |

## 🐳 Docker Deployment

```yaml
services:
  backend:
    image: propguard-backend
    ports: ["8080:8080"]
    volumes:
      - badger-data:/app/data
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - VAULT_MASTER_KEY=${VAULT_MASTER_KEY}
      
  frontend:
    image: propguard-frontend
    ports: ["3000:3000"]
    depends_on:
      - backend

volumes:
  badger-data:  # Persistent BadgerDB storage
```

## 📈 Project Roadmap

### ✅ Phase 1: Core Features (100%)
- Authentication system
- Secret management
- User management
- Role-based access control
- Audit logging

### ✅ Phase 2: Enhanced Core (100%)
- BadgerDB integration
- Role management endpoints
- Test coverage improvements
- Frontend dashboard

### 🔄 Phase 3: Enterprise Features (95%)
- ✅ Environment parameters API
- ✅ Bootstrap service
- ✅ Frontend authentication integration
- ⏳ Team management (entities ready, APIs pending)
- ⏳ API key management (repository ready, service pending)

### 📋 Phase 4: Advanced Features (Planned)
- Secret rotation scheduling
- Advanced audit features
- Performance optimizations
- Multi-region support

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 📖 Documentation

- **Technical Documentation**: See [CLAUDE.md](CLAUDE.md) for complete technical details
- **API Documentation**: http://localhost:8080/swagger/index.html
- **Frontend Documentation**: See [ui/dashboard/README.md](ui/dashboard/README.md)

## 🛟 Support

For issues, questions, or contributions:
- Create an issue in the repository
- Check existing documentation in CLAUDE.md
- Review test examples in `/tests` directory

---

**PropGuard** - Enterprise-grade secrets management with zero external dependencies.