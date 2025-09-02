.PHONY: help build run test clean deps swagger docker-build docker-run

# Variables
BINARY_NAME=jvault
DOCKER_IMAGE=jvault:latest
GO=go
GOFLAGS=-v

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Download dependencies
	$(GO) mod download
	$(GO) mod tidy

build: ## Build the application
	$(GO) build $(GOFLAGS) -o bin/$(BINARY_NAME) cmd/server/main.go

run: ## Run the application
	$(GO) run cmd/server/main.go

dev: ## Run the application in development mode
	GIN_MODE=debug $(GO) run cmd/server/main.go

test: ## Run tests
	$(GO) test -v ./...

test-coverage: ## Run tests with coverage
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

clean: ## Clean build artifacts
	rm -rf bin/
	rm -f coverage.out coverage.html

swagger: ## Generate swagger documentation
	swag init -g cmd/server/main.go -o docs

docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE) .

docker-run: ## Run Docker container
	docker run -p 8080:8080 --env-file .env $(DOCKER_IMAGE)

lint: ## Run linter
	golangci-lint run

fmt: ## Format code
	$(GO) fmt ./...
	goimports -w .