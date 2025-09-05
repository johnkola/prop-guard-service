package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"PropGuard/internal/config"
	"PropGuard/internal/controller"
	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	os.Setenv("GIN_MODE", "test")
	os.Setenv("JWT_SECRET", "test-jwt-secret-exactly-32b")
	os.Setenv("VAULT_MASTER_KEY", "12345678901234567890123456789012")
}

type APIKeyTestServices struct {
	BadgerClient     *repository.BadgerClient
	Config           *config.Config
	APIKeyService    service.APIKeyService
	APIKeyController *controller.APIKeyController
	JWTMiddleware    *security.JWTMiddleware
	AuthService      service.AuthService
	UserService      service.UserService
	TestUser         *entity.VaultUser
}

func setupAPIKeyTestServices(t *testing.T) *APIKeyTestServices {
	// Create unique temporary directory for this test
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("propguard_apikey_test_%d_%s", time.Now().UnixNano(), t.Name()))
	err := os.MkdirAll(tmpDir, 0755)
	require.NoError(t, err)

	// Setup fresh test configuration for each test
	testConfig := &config.Config{
		JWT: config.JWTConfig{
			Secret:      "test-jwt-secret-exactly-32b",
			ExpiryHours: 24,
		},
		Vault: config.VaultConfig{
			MasterKey: "12345678901234567890123456789012",
		},
		Badger: config.BadgerConfig{
			Dir:                tmpDir,
			ValueLogFileSize:   1 << 26,  // 64MB
			MemTableSize:       1 << 20,  // 1MB
			BlockCacheSize:     1 << 20,  // 1MB
			IndexCacheSize:     1 << 19,  // 512KB
			BaseTableSize:      8 << 20,  // 8MB
			ValueThreshold:     32 << 10, // 32KB
			NumVersionsToKeep:  1,
			NumLevelZeroTables: 1,
			Compression:        false,
		},
	}

	// Initialize BadgerDB with test configuration
	badgerConfig := repository.BadgerConfig{
		Dir:                testConfig.Badger.Dir,
		ValueLogFileSize:   testConfig.Badger.ValueLogFileSize,
		MemTableSize:       testConfig.Badger.MemTableSize,
		BlockCacheSize:     testConfig.Badger.BlockCacheSize,
		IndexCacheSize:     testConfig.Badger.IndexCacheSize,
		BaseTableSize:      testConfig.Badger.BaseTableSize,
		ValueThreshold:     testConfig.Badger.ValueThreshold,
		NumVersionsToKeep:  testConfig.Badger.NumVersionsToKeep,
		NumLevelZeroTables: testConfig.Badger.NumLevelZeroTables,
		Compression:        testConfig.Badger.Compression,
	}

	badgerClient, err := repository.NewBadgerClient(badgerConfig)
	require.NoError(t, err)

	// Test BadgerDB connectivity
	err = badgerClient.Ping()
	require.NoError(t, err)

	// Initialize repositories and services
	userRepo := repository.NewBadgerUserRepository(badgerClient)
	apiKeyRepo := repository.NewBadgerAPIKeyRepository(badgerClient)
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)

	// Initialize services
	auditService := service.NewAuditService(auditRepo)
	authService := service.NewAuthService(userRepo, auditService, testConfig.JWT.Secret, testConfig.JWT.ExpiryHours)
	userService := service.NewUserService(userRepo, auditService)
	apiKeyService := service.NewAPIKeyService(apiKeyRepo, userRepo, auditService)

	// Initialize middleware
	jwtMiddleware := security.NewJWTMiddleware(authService)

	// Initialize API key controller
	apiKeyController := controller.NewAPIKeyController(apiKeyService, jwtMiddleware)

	// Create a test user
	ctx := context.Background()
	hashedPassword, err := service.HashPassword("testpass123")
	require.NoError(t, err)

	testUser := entity.NewVaultUser("apitest", "apitest@example.com", hashedPassword)
	testUser.RoleIDs = []string{"role_admin"}
	err = userRepo.Create(ctx, testUser)
	require.NoError(t, err)

	// Clean up function
	t.Cleanup(func() {
		if badgerClient != nil {
			badgerClient.Close()
		}
		os.RemoveAll(tmpDir)
	})

	return &APIKeyTestServices{
		BadgerClient:     badgerClient,
		Config:           testConfig,
		APIKeyService:    apiKeyService,
		APIKeyController: apiKeyController,
		JWTMiddleware:    jwtMiddleware,
		AuthService:      authService,
		UserService:      userService,
		TestUser:         testUser,
	}
}

func generateAPIKeyTestJWT(services *APIKeyTestServices) string {
	token, _ := services.AuthService.GenerateToken(services.TestUser.ID.String(), services.TestUser.Username)
	return token
}

func TestAPIKeyController_CreateAPIKey_Success(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Create API key request
	createRequest := dto.CreateAPIKeyRequest{
		Name:        "Test API Key",
		Description: "API key for testing",
		Scopes:      []string{"secrets:read", "secrets:write"},
		ExpiresAt:   time.Now().Add(30 * 24 * time.Hour), // 30 days
	}

	jsonData, err := json.Marshal(createRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/api-keys", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Test API Key", response["name"])
	assert.Equal(t, "API key for testing", response["description"])
	assert.Contains(t, response, "id")
	assert.Contains(t, response, "key")
	assert.Contains(t, response, "created_at")
	assert.Equal(t, services.TestUser.ID.String(), response["user_id"])

	// Verify scopes
	scopes := response["scopes"].([]interface{})
	assert.Contains(t, scopes, "secrets:read")
	assert.Contains(t, scopes, "secrets:write")
}

func TestAPIKeyController_GetAPIKey_Success(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Create a test API key first
	ctx := context.Background()
	apiKey := &entity.APIKey{
		ID:          entity.GenerateUUID(),
		Name:        "Get Test Key",
		Description: "API key for get test",
		UserID:      services.TestUser.ID,
		Scopes:      []string{"secrets:read"},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsActive:    true,
	}

	_, err := services.APIKeyService.CreateAPIKey(ctx, apiKey, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/api-keys/"+apiKey.ID.String(), nil)
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Get Test Key", response["name"])
	assert.Equal(t, "API key for get test", response["description"])
	assert.Equal(t, apiKey.ID.String(), response["id"])
	// Key should not be returned in GET responses for security
	assert.NotContains(t, response, "key")
}

func TestAPIKeyController_UpdateAPIKey_Success(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Create a test API key first
	ctx := context.Background()
	apiKey := &entity.APIKey{
		ID:          entity.GenerateUUID(),
		Name:        "Update Test Key",
		Description: "API key for update test",
		UserID:      services.TestUser.ID,
		Scopes:      []string{"secrets:read"},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsActive:    true,
	}

	_, err := services.APIKeyService.CreateAPIKey(ctx, apiKey, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Update API key request
	updateRequest := dto.UpdateAPIKeyRequest{
		Name:        "Updated API Key",
		Description: "Updated description",
		Scopes:      []string{"secrets:read", "users:read"},
		IsActive:    true,
	}

	jsonData, err := json.Marshal(updateRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("PUT", "/api/v1/api-keys/"+apiKey.ID.String(), bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Updated API Key", response["name"])
	assert.Equal(t, "Updated description", response["description"])
	assert.Equal(t, apiKey.ID.String(), response["id"])

	// Verify updated scopes
	scopes := response["scopes"].([]interface{})
	assert.Contains(t, scopes, "secrets:read")
	assert.Contains(t, scopes, "users:read")
}

func TestAPIKeyController_ListAPIKeys_Success(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Create multiple test API keys
	ctx := context.Background()
	apiKeys := []*entity.APIKey{
		{
			ID:          entity.GenerateUUID(),
			Name:        "API Key Alpha",
			Description: "First test API key",
			UserID:      services.TestUser.ID,
			Scopes:      []string{"secrets:read"},
			ExpiresAt:   time.Now().Add(24 * time.Hour),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			IsActive:    true,
		},
		{
			ID:          entity.GenerateUUID(),
			Name:        "API Key Beta",
			Description: "Second test API key",
			UserID:      services.TestUser.ID,
			Scopes:      []string{"users:read"},
			ExpiresAt:   time.Now().Add(24 * time.Hour),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			IsActive:    true,
		},
	}

	for _, apiKey := range apiKeys {
		_, err := services.APIKeyService.CreateAPIKey(ctx, apiKey, services.TestUser.ID.String())
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/api-keys?limit=10&offset=0", nil)
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "api_keys")
	assert.Contains(t, response, "total")
	assert.Contains(t, response, "limit")
	assert.Contains(t, response, "offset")

	apiKeysData := response["api_keys"].([]interface{})
	assert.GreaterOrEqual(t, len(apiKeysData), 2)
}

func TestAPIKeyController_DeleteAPIKey_Success(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Create a test API key first
	ctx := context.Background()
	apiKey := &entity.APIKey{
		ID:          entity.GenerateUUID(),
		Name:        "Delete Test Key",
		Description: "API key for delete test",
		UserID:      services.TestUser.ID,
		Scopes:      []string{"secrets:read"},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsActive:    true,
	}

	_, err := services.APIKeyService.CreateAPIKey(ctx, apiKey, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("DELETE", "/api/v1/api-keys/"+apiKey.ID.String(), nil)
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "API key deleted successfully", response["message"])
}

func TestAPIKeyController_ToggleAPIKey_Success(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Create a test API key first
	ctx := context.Background()
	apiKey := &entity.APIKey{
		ID:          entity.GenerateUUID(),
		Name:        "Toggle Test Key",
		Description: "API key for toggle test",
		UserID:      services.TestUser.ID,
		Scopes:      []string{"secrets:read"},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsActive:    true,
	}

	_, err := services.APIKeyService.CreateAPIKey(ctx, apiKey, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Toggle API key request (deactivate)
	toggleRequest := dto.ToggleAPIKeyRequest{
		IsActive: false,
	}

	jsonData, err := json.Marshal(toggleRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("PATCH", "/api/v1/api-keys/"+apiKey.ID.String()+"/toggle", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "API key status updated successfully", response["message"])
	assert.Equal(t, false, response["is_active"])
}

func TestAPIKeyController_GetUsage_Success(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Create a test API key first
	ctx := context.Background()
	apiKey := &entity.APIKey{
		ID:          entity.GenerateUUID(),
		Name:        "Usage Test Key",
		Description: "API key for usage test",
		UserID:      services.TestUser.ID,
		Scopes:      []string{"secrets:read"},
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		IsActive:    true,
	}

	_, err := services.APIKeyService.CreateAPIKey(ctx, apiKey, services.TestUser.ID.String())
	require.NoError(t, err)

	// Record some usage
	err = services.APIKeyService.RecordUsage(ctx, apiKey.ID.String(), "GET", "/secrets/test", 200)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/api-keys/"+apiKey.ID.String()+"/usage", nil)
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "total_requests")
	assert.Contains(t, response, "last_used_at")
	assert.Contains(t, response, "usage_by_endpoint")
}

func TestAPIKeyController_CreateAPIKey_InvalidJSON(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with invalid JSON
	req, err := http.NewRequest("POST", "/api/v1/api-keys", bytes.NewBufferString(`{"invalid json`))
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAPIKeyController_GetAPIKey_NotFound(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request for non-existent API key
	nonExistentID := entity.GenerateUUID().String()
	req, err := http.NewRequest("GET", "/api/v1/api-keys/"+nonExistentID, nil)
	require.NoError(t, err)

	token := generateAPIKeyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAPIKeyController_Unauthorized_NoToken(t *testing.T) {
	services := setupAPIKeyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register API key routes
	services.APIKeyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request without JWT token
	req, err := http.NewRequest("GET", "/api/v1/api-keys", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
