.PHONY: help build run test clean deps swagger docker-build docker-run docs deploy dev stop logs quick

# Variables
BINARY_NAME=propguard
DOCKER_IMAGE=propguard:latest
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

dev-local: ## Run the application in development mode
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
	@echo "📚 Generating Swagger documentation..."
	@swag init -g cmd/server/main.go -o docs/ --parseDependency --parseInternal

docs: swagger ## Alias for swagger

# Docker Compose commands
deploy: ## Generate docs + build + deploy with Docker Compose (Go-powered)
	@go run cmd/build-deploy/main.go

dev: swagger ## Development mode with logs
	@echo "🛠️ Starting development environment..."
	@docker-compose up --build

quick: ## Quick build and deploy without swagger generation
	@docker-compose up --build -d

# Go Build Tool Commands
build-tool: ## Build the Go build tool binary
	@go build -o bin/build-deploy cmd/build-deploy/main.go

full-build: ## Full build with all steps (test, lint, docs, build)
	@go run cmd/build-deploy/main.go -mode=full

dev-go: ## Development mode using Go build tool  
	@go run cmd/build-deploy/main.go -mode=dev

clean-build: ## Clean and build using Go build tool
	@go run cmd/build-deploy/main.go -mode=clean

stop: ## Stop all services
	@echo "⏹️ Stopping all services..."
	@docker-compose down

logs: ## View logs
	@docker-compose logs -f

clean-docker: ## Clean up Docker resources
	@echo "🧹 Cleaning up Docker resources..."
	@docker-compose down -v --remove-orphans
	@docker system prune -f

# Legacy Docker commands (single container)
docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMAGE) .

docker-run: ## Run Docker container
	docker run -p 8080:8080 --env-file .env $(DOCKER_IMAGE)

lint: ## Run linter
	golangci-lint run

fmt: ## Format code
	$(GO) fmt ./...
	goimports -w .