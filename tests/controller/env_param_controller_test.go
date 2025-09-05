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

type EnvParamTestServices struct {
	BadgerClient       *repository.BadgerClient
	Config             *config.Config
	EnvParamService    service.EnvParamService
	EnvParamController *controller.EnvParamController
}

func setupEnvParamTestServices(t *testing.T) *EnvParamTestServices {
	// Create unique temporary directory for this test
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("propguard_envparam_test_%d_%s", time.Now().UnixNano(), t.Name()))
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
	envParamRepo := repository.NewBadgerEnvParamRepository(badgerClient)
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)

	// Initialize services
	encryptionService := service.NewEncryptionService(testConfig.Vault.MasterKey)
	auditService := service.NewAuditService(auditRepo)
	envParamService := service.NewEnvParamService(envParamRepo, encryptionService, auditService)

	// Initialize controller
	envParamController := controller.NewEnvParamController(envParamService)

	// Clean up function
	t.Cleanup(func() {
		if badgerClient != nil {
			badgerClient.Close()
		}
		os.RemoveAll(tmpDir)
	})

	return &EnvParamTestServices{
		BadgerClient:       badgerClient,
		Config:             testConfig,
		EnvParamService:    envParamService,
		EnvParamController: envParamController,
	}
}

func TestEnvParamController_CreateEnvParam_Success(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.POST("/env-params", services.EnvParamController.CreateEnvParam)

	// Create env param request
	createRequest := dto.CreateEnvParamRequest{
		Environment: "test",
		Key:         "DATABASE_URL",
		Value:       "postgresql://user:pass@localhost/testdb",
		Description: "Test database connection string",
		IsEncrypted: true,
	}

	jsonData, err := json.Marshal(createRequest)
	require.NoError(t, err)

	// Make request
	req, err := http.NewRequest("POST", "/env-params", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "test", response["environment"])
	assert.Equal(t, "DATABASE_URL", response["key"])
	assert.Equal(t, "Test database connection string", response["description"])
	assert.Equal(t, true, response["is_encrypted"])
	assert.Contains(t, response, "id")
	assert.Contains(t, response, "created_at")
	// Value should not be returned in response for security
	assert.NotContains(t, response, "value")
}

func TestEnvParamController_GetEnvParam_Success(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Create a test env param first
	ctx := context.Background()
	envParam := &entity.EnvParam{
		ID:          entity.GenerateUUID(),
		Environment: "prod",
		Key:         "API_KEY",
		Value:       "secret-api-key-value",
		Description: "Production API key",
		IsEncrypted: true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := services.EnvParamService.CreateEnvParam(ctx, envParam)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.GET("/env-params/:environment/:key", services.EnvParamController.GetEnvParam)

	// Make request
	req, err := http.NewRequest("GET", "/env-params/prod/API_KEY", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "prod", response["environment"])
	assert.Equal(t, "API_KEY", response["key"])
	assert.Equal(t, "secret-api-key-value", response["value"])
	assert.Equal(t, "Production API key", response["description"])
	assert.Equal(t, true, response["is_encrypted"])
	assert.Equal(t, envParam.ID.String(), response["id"])
}

func TestEnvParamController_UpdateEnvParam_Success(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Create a test env param first
	ctx := context.Background()
	envParam := &entity.EnvParam{
		ID:          entity.GenerateUUID(),
		Environment: "staging",
		Key:         "REDIS_URL",
		Value:       "redis://localhost:6379",
		Description: "Redis connection string",
		IsEncrypted: false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := services.EnvParamService.CreateEnvParam(ctx, envParam)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.PUT("/env-params/:environment/:key", services.EnvParamController.UpdateEnvParam)

	// Update env param request
	updateRequest := dto.UpdateEnvParamRequest{
		Value:       "redis://staging-redis:6379",
		Description: "Updated Redis connection for staging",
		IsEncrypted: true,
	}

	jsonData, err := json.Marshal(updateRequest)
	require.NoError(t, err)

	// Make request
	req, err := http.NewRequest("PUT", "/env-params/staging/REDIS_URL", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "staging", response["environment"])
	assert.Equal(t, "REDIS_URL", response["key"])
	assert.Equal(t, "Updated Redis connection for staging", response["description"])
	assert.Equal(t, true, response["is_encrypted"])
	assert.Equal(t, envParam.ID.String(), response["id"])
	// Value should not be returned for encrypted params
	assert.NotContains(t, response, "value")
}

func TestEnvParamController_ListEnvParams_Success(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Create multiple test env params for the same environment
	ctx := context.Background()
	envParams := []*entity.EnvParam{
		{
			ID:          entity.GenerateUUID(),
			Environment: "dev",
			Key:         "DB_HOST",
			Value:       "dev-db.example.com",
			Description: "Development database host",
			IsEncrypted: false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          entity.GenerateUUID(),
			Environment: "dev",
			Key:         "DB_PASSWORD",
			Value:       "dev-secret-password",
			Description: "Development database password",
			IsEncrypted: true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, param := range envParams {
		err := services.EnvParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.GET("/env-params/:environment", services.EnvParamController.ListEnvParams)

	// Make request
	req, err := http.NewRequest("GET", "/env-params/dev", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "parameters")
	assert.Contains(t, response, "environment")
	assert.Equal(t, "dev", response["environment"])

	parameters := response["parameters"].([]interface{})
	assert.GreaterOrEqual(t, len(parameters), 2)

	// Verify parameter structure
	firstParam := parameters[0].(map[string]interface{})
	assert.Contains(t, firstParam, "key")
	assert.Contains(t, firstParam, "description")
	assert.Contains(t, firstParam, "is_encrypted")
	assert.Contains(t, firstParam, "created_at")
}

func TestEnvParamController_ListAllEnvParams_Success(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Create test env params in multiple environments
	ctx := context.Background()
	envParams := []*entity.EnvParam{
		{
			ID:          entity.GenerateUUID(),
			Environment: "prod",
			Key:         "SERVICE_URL",
			Value:       "https://api.example.com",
			Description: "Production service URL",
			IsEncrypted: false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          entity.GenerateUUID(),
			Environment: "test",
			Key:         "TEST_TOKEN",
			Value:       "test-token-value",
			Description: "Test authentication token",
			IsEncrypted: true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, param := range envParams {
		err := services.EnvParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.GET("/env-params", services.EnvParamController.ListAllEnvParams)

	// Make request
	req, err := http.NewRequest("GET", "/env-params", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "parameters")
	assert.Contains(t, response, "total")

	parameters := response["parameters"].([]interface{})
	assert.GreaterOrEqual(t, len(parameters), 2)

	total := response["total"].(float64)
	assert.GreaterOrEqual(t, total, float64(2))
}

func TestEnvParamController_GetEnvironments_Success(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Create test env params in different environments
	ctx := context.Background()
	envParams := []*entity.EnvParam{
		{
			ID:          entity.GenerateUUID(),
			Environment: "production",
			Key:         "DB_URL",
			Value:       "prod-db",
			Description: "Production database",
			IsEncrypted: true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          entity.GenerateUUID(),
			Environment: "staging",
			Key:         "API_URL",
			Value:       "staging-api",
			Description: "Staging API",
			IsEncrypted: false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          entity.GenerateUUID(),
			Environment: "development",
			Key:         "LOG_LEVEL",
			Value:       "debug",
			Description: "Development log level",
			IsEncrypted: false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, param := range envParams {
		err := services.EnvParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.GET("/env-params/environments", services.EnvParamController.GetEnvironments)

	// Make request
	req, err := http.NewRequest("GET", "/env-params/environments", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "environments")

	environments := response["environments"].([]interface{})
	assert.GreaterOrEqual(t, len(environments), 3)

	// Convert to strings for easier checking
	envNames := make([]string, len(environments))
	for i, env := range environments {
		envNames[i] = env.(string)
	}

	assert.Contains(t, envNames, "production")
	assert.Contains(t, envNames, "staging")
	assert.Contains(t, envNames, "development")
}

func TestEnvParamController_BulkCreateEnvParams_Success(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.POST("/env-params/bulk", services.EnvParamController.BulkCreateEnvParams)

	// Bulk create request
	bulkRequest := dto.BulkCreateEnvParamsRequest{
		Environment: "integration",
		Parameters: []dto.EnvParamData{
			{
				Key:         "SERVICE_A_URL",
				Value:       "http://service-a:8080",
				Description: "Service A endpoint",
				IsEncrypted: false,
			},
			{
				Key:         "SERVICE_A_API_KEY",
				Value:       "super-secret-api-key",
				Description: "Service A API authentication key",
				IsEncrypted: true,
			},
			{
				Key:         "CACHE_TTL",
				Value:       "3600",
				Description: "Cache time to live in seconds",
				IsEncrypted: false,
			},
		},
	}

	jsonData, err := json.Marshal(bulkRequest)
	require.NoError(t, err)

	// Make request
	req, err := http.NewRequest("POST", "/env-params/bulk", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "created_count")
	assert.Contains(t, response, "environment")
	assert.Equal(t, "integration", response["environment"])
	assert.Equal(t, float64(3), response["created_count"])
}

func TestEnvParamController_GetEnvParams_Batch(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Create test env params first
	ctx := context.Background()
	envParams := []*entity.EnvParam{
		{
			ID:          entity.GenerateUUID(),
			Environment: "batch",
			Key:         "KEY1",
			Value:       "value1",
			Description: "First key",
			IsEncrypted: false,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          entity.GenerateUUID(),
			Environment: "batch",
			Key:         "KEY2",
			Value:       "value2",
			Description: "Second key",
			IsEncrypted: true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, param := range envParams {
		err := services.EnvParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.POST("/env-params/:environment/batch", services.EnvParamController.GetEnvParams)

	// Batch get request
	batchRequest := dto.BatchGetEnvParamsRequest{
		Keys: []string{"KEY1", "KEY2"},
	}

	jsonData, err := json.Marshal(batchRequest)
	require.NoError(t, err)

	// Make request
	req, err := http.NewRequest("POST", "/env-params/batch/batch", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "parameters")
	assert.Contains(t, response, "environment")
	assert.Equal(t, "batch", response["environment"])

	parameters := response["parameters"].(map[string]interface{})
	assert.Contains(t, parameters, "KEY1")
	assert.Contains(t, parameters, "KEY2")
	assert.Equal(t, "value1", parameters["KEY1"])
	assert.Equal(t, "value2", parameters["KEY2"])
}

func TestEnvParamController_DeleteEnvParam_Success(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Create a test env param first
	ctx := context.Background()
	envParam := &entity.EnvParam{
		ID:          entity.GenerateUUID(),
		Environment: "temp",
		Key:         "TEMP_KEY",
		Value:       "temp-value",
		Description: "Temporary key for deletion test",
		IsEncrypted: false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := services.EnvParamService.CreateEnvParam(ctx, envParam)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.DELETE("/env-params/:environment/:key", services.EnvParamController.DeleteEnvParam)

	// Make request
	req, err := http.NewRequest("DELETE", "/env-params/temp/TEMP_KEY", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Environment parameter deleted successfully", response["message"])
}

func TestEnvParamController_CreateEnvParam_InvalidJSON(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.POST("/env-params", services.EnvParamController.CreateEnvParam)

	// Make request with invalid JSON
	req, err := http.NewRequest("POST", "/env-params", bytes.NewBufferString(`{"invalid json`))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEnvParamController_GetEnvParam_NotFound(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.GET("/env-params/:environment/:key", services.EnvParamController.GetEnvParam)

	// Make request for non-existent env param
	req, err := http.NewRequest("GET", "/env-params/nonexistent/MISSING_KEY", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestEnvParamController_CreateEnvParam_ValidationError(t *testing.T) {
	services := setupEnvParamTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register env param routes
	router.POST("/env-params", services.EnvParamController.CreateEnvParam)

	// Create env param request with missing required fields
	createRequest := dto.CreateEnvParamRequest{
		Environment: "", // Missing environment
		Key:         "", // Missing key
		Value:       "some-value",
		Description: "Test description",
		IsEncrypted: false,
	}

	jsonData, err := json.Marshal(createRequest)
	require.NoError(t, err)

	// Make request
	req, err := http.NewRequest("POST", "/env-params", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
