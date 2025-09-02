# PropGuard - Go Implementation

A secure secrets management system written in Go, converted from the original Java/Spring Boot implementation.

## Features

- **Secure Secret Storage**: AES-256-GCM encryption for all secrets
- **JWT Authentication**: Stateless authentication with role-based access control
- **MongoDB Backend**: Scalable document database for persistence
- **Audit Logging**: Comprehensive audit trail for all operations
- **REST API**: Clean RESTful API with Swagger documentation
- **Docker Support**: Containerized deployment ready

## Quick Start

### Prerequisites

- Go 1.21+
- MongoDB 4.4+
- Docker (optional)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd PropGuard
   ```

2. **Install dependencies**
   ```bash
   make deps
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run the application**
   ```bash
   make run
   ```

The server will start on `http://localhost:8080`

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | HTTP server port | `8080` |
| `MONGODB_URI` | MongoDB connection URI | `mongodb://localhost:27017` |
| `MONGODB_DATABASE` | Database name | `PropGuard` |
| `JWT_SECRET` | JWT signing secret | Change in production |
| `VAULT_MASTER_KEY` | Master encryption key | Change in production |
| `AUDIT_RETENTION_DAYS` | Audit log retention | `90` |

## API Documentation

Once the server is running, access the Swagger documentation at:
- `http://localhost:8080/swagger/index.html`

### Authentication

1. **Login**
   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}'
   ```

2. **Use the returned JWT token in subsequent requests**
   ```bash
   curl -H "Authorization: Bearer <token>" \
     http://localhost:8080/api/v1/secrets/
   ```

### Secret Operations

- `POST /api/v1/secrets/{path}` - Create secret
- `GET /api/v1/secrets/{path}` - Retrieve secret
- `PUT /api/v1/secrets/{path}` - Update secret
- `DELETE /api/v1/secrets/{path}` - Delete secret
- `GET /api/v1/secrets/` - List secrets

## Development

### Building

```bash
# Build binary
make build

# Run tests
make test

# Run with development mode
make dev

# Generate swagger docs
make swagger
```

### Docker

```bash
# Build image
make docker-build

# Run container
make docker-run
```

## Architecture

```
cmd/server/          # Application entry point
internal/
├── config/          # Configuration management
├── controller/      # HTTP handlers
├── dto/             # Data transfer objects
├── entity/          # Domain models
├── repository/      # Data access layer
├── security/        # Authentication & authorization
└── service/         # Business logic
```

## Security Features

- **Encryption**: All secrets encrypted with AES-256-GCM
- **Authentication**: JWT-based stateless authentication
- **Authorization**: Role-based access control
- **Audit Trail**: Complete operation logging
- **Input Validation**: Request validation and sanitization

## Migration from Java

This Go implementation maintains API compatibility with the original Java version while providing:

- **Better Performance**: Lower memory usage and faster startup
- **Single Binary**: No JVM required
- **Simplified Deployment**: Docker-friendly architecture
- **Modern Stack**: Clean architecture with dependency injection

## Production Deployment

1. **Set secure secrets**
   ```bash
   export JWT_SECRET="your-secure-random-secret"
   export VAULT_MASTER_KEY="your-master-encryption-key"
   ```

2. **Use a production MongoDB instance**
   ```bash
   export MONGODB_URI="mongodb://prod-cluster/PropGuard"
   ```

3. **Deploy with Docker**
   ```bash
   docker run -d \
     --name PropGuard \
     -p 8080:8080 \
     --env-file .env \
     PropGuard:latest
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the Apache 2.0 License.