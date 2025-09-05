# Build stage
FROM golang:1.23.4-alpine3.19 AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Install swag with pinned version (cached layer)
RUN go install github.com/swaggo/swag/cmd/swag@v1.16.3

# Copy source code
COPY . .

# Generate swagger documentation
RUN swag init -g cmd/server/main.go -o docs/ --parseDependency --parseInternal

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o propguard cmd/server/main.go

# Final stage
FROM alpine:3.22

# Install ca-certificates and wget for health checks
RUN apk --no-cache add ca-certificates wget

# Create non-root user
RUN addgroup -g 1000 -S propguard && \
    adduser -u 1000 -S propguard -G propguard

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/propguard .

# Create data directory and set permissions
RUN mkdir -p /app/data && \
    chown -R propguard:propguard /app

# Switch to non-root user
USER propguard

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider -O- http://localhost:8080/health || exit 1

# Run the application
CMD ["./propguard"]