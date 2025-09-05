package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "PropGuard/docs"
	"PropGuard/internal/config"
	"PropGuard/internal/controller"
	"PropGuard/internal/repository"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title PropGuard API
// @version 1.0
// @description A secure secrets management system with BadgerDB
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@propguard.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize BadgerDB
	badgerConfig := repository.BadgerConfig{
		Dir:                cfg.Badger.Dir,
		ValueLogFileSize:   cfg.Badger.ValueLogFileSize,
		MemTableSize:       cfg.Badger.MemTableSize,
		BlockCacheSize:     cfg.Badger.BlockCacheSize,
		IndexCacheSize:     cfg.Badger.IndexCacheSize,
		NumVersionsToKeep:  cfg.Badger.NumVersionsToKeep,
		NumLevelZeroTables: cfg.Badger.NumLevelZeroTables,
		Compression:        cfg.Badger.Compression,
	}

	// Add encryption key if encryption is enabled
	if cfg.Badger.EncryptionEnabled {
		badgerConfig.EncryptionKey = []byte(cfg.Vault.MasterKey)
	}

	badgerClient, err := repository.NewBadgerClient(badgerConfig)
	if err != nil {
		log.Fatalf("Failed to connect to BadgerDB: %v", err)
	}
	defer func() {
		if err := badgerClient.Close(); err != nil {
			log.Printf("Error closing BadgerDB: %v", err)
		}
	}()

	// Test BadgerDB connection
	if err := badgerClient.Ping(); err != nil {
		log.Fatalf("BadgerDB health check failed: %v", err)
	}
	log.Println("BadgerDB connection established successfully")

	// Context for operations
	ctx := context.Background()
	log.Println("PropGuard system starting with BadgerDB backend")

	// Bootstrap system if needed
	bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)
	if isFirstRun, _ := bootstrapService.IsFirstRun(ctx); isFirstRun {
		log.Println("🚀 First run detected - bootstrapping...")
		if err := bootstrapService.RunBootstrap(ctx); err != nil {
			log.Fatalf("Bootstrap failed: %v", err)
		}
	}

	// Initialize repositories
	userRepo := repository.NewBadgerUserRepository(badgerClient)
	secretRepo := repository.NewBadgerSecretRepository(badgerClient)
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, cfg.Vault.AuditRetentionDays)
	// apiKeyRepo := repository.NewBadgerAPIKeyRepository(badgerClient) // Removed - service not used
	roleRepo := repository.NewBadgerRoleRepository(badgerClient)

	// Initialize services
	encryptionService := service.NewEncryptionService(cfg.Vault.MasterKey)
	auditService := service.NewAuditService(auditRepo)
	authService := service.NewAuthService(userRepo, auditService, cfg.JWT.Secret, cfg.JWT.ExpiryHours)
	secretService := service.NewSecretService(secretRepo, userRepo, encryptionService, auditService)
	userService := service.NewUserService(userRepo, auditService)
	// envParamService := service.NewEnvParamService() // Removed - service not used

	// Initialize middleware
	jwtMiddleware := security.NewJWTMiddleware(authService)

	// Initialize controllers
	authController := controller.NewAuthController(authService)
	secretController := controller.NewSecretController(secretService, jwtMiddleware)
	userController := controller.NewUserController(userService, jwtMiddleware)
	roleController := controller.NewRoleController(roleRepo, auditService, jwtMiddleware)
	auditController := controller.NewAuditController(auditRepo, auditService, jwtMiddleware)
	// Batch keys controller removed - dependencies not available

	// Setup Gin router
	router := setupRouter(authController, secretController, userController, roleController, auditController, badgerClient)

	// Create HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting PropGuard server on port %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server shutdown complete")
}

func setupRouter(authController *controller.AuthController, secretController *controller.SecretController, userController *controller.UserController, roleController *controller.RoleController, auditController *controller.AuditController, badgerClient *repository.BadgerClient) *gin.Engine {
	// Set Gin mode based on environment
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Add middleware
	router.Use(gin.Recovery())
	router.Use(gin.Logger())
	router.Use(corsMiddleware())

	// Enhanced health check endpoint
	router.GET("/health", func(c *gin.Context) {
		stats := badgerClient.GetStats()
		healthStatus := gin.H{
			"status":      "healthy",
			"time":        time.Now().Unix(),
			"environment": os.Getenv("GIN_MODE"),
			"database":    "BadgerDB",
			"db_stats":    stats,
		}

		// Test BadgerDB connectivity
		if err := badgerClient.Ping(); err != nil {
			healthStatus["database_status"] = "unhealthy"
			healthStatus["database_error"] = err.Error()
			c.JSON(http.StatusServiceUnavailable, healthStatus)
			return
		}
		healthStatus["database_status"] = "healthy"

		// Add service info
		healthStatus["service"] = "PropGuard API"
		healthStatus["version"] = "1.0"

		c.JSON(http.StatusOK, healthStatus)
	})

	// Serve static files for React dashboard
	router.Static("/assets", "./static/assets")

	// Dashboard routes - serve React app
	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	// API documentation route
	router.GET("/docs", func(c *gin.Context) {
		readmeContent, err := ioutil.ReadFile("README.md")
		if err != nil {
			c.String(http.StatusInternalServerError, "Error reading README: %v", err)
			return
		}

		// Convert markdown to basic HTML formatting
		content := string(readmeContent)
		content = strings.ReplaceAll(content, "\n", "<br>")
		content = strings.ReplaceAll(content, "# ", "<h1>")
		content = strings.ReplaceAll(content, "<br><h1>", "</h1><h1>")
		content = strings.ReplaceAll(content, "## ", "<h2>")
		content = strings.ReplaceAll(content, "<br><h2>", "</h2><h2>")
		content = strings.ReplaceAll(content, "### ", "<h3>")
		content = strings.ReplaceAll(content, "<br><h3>", "</h3><h3>")

		html := `<!DOCTYPE html>
<html>
<head>
    <title>PropGuard - Documentation</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1000px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        h1 { color: #333; border-bottom: 2px solid #333; }
        h2 { color: #666; border-bottom: 1px solid #666; }
        h3 { color: #999; }
        code { background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
        pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 20px; text-decoration: none; color: #007cba; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">Dashboard</a>
        <a href="/health">Health Check</a>
        <a href="/swagger/index.html">API Documentation</a>
        <a href="/api/v1/">API v1</a>
    </div>
    ` + content + `
</body>
</html>`

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, html)
	})

	// Swagger documentation
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		authController.RegisterRoutes(v1)
		secretController.RegisterRoutes(v1)
		userController.RegisterRoutes(v1)
		roleController.RegisterRoutes(v1)
		auditController.RegisterRoutes(v1)
		// Batch keys routes removed - service dependencies not available
	}

	return router
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get allowed origins from environment, default to localhost for development
		allowedOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
		if allowedOrigins == "" {
			// Development default - restrict to localhost
			allowedOrigins = "http://localhost:3000,http://localhost:3001,http://localhost:8080"
		}

		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			// Check if origin is in allowed list
			origins := strings.Split(allowedOrigins, ",")
			for _, allowedOrigin := range origins {
				if strings.TrimSpace(allowedOrigin) == origin {
					c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
		}

		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
