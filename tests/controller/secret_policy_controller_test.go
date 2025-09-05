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

type SecretPolicyTestServices struct {
	BadgerClient      *repository.BadgerClient
	Config            *config.Config
	PolicyService     service.SecretPolicyService
	GenerationService service.SecretGenerationService
	PolicyController  *controller.SecretPolicyController
	JWTMiddleware     *security.JWTMiddleware
	AuthService       service.AuthService
	TestUser          *entity.VaultUser
}

func setupSecretPolicyTestServices(t *testing.T) *SecretPolicyTestServices {
	// Create unique temporary directory for this test
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("propguard_policy_test_%d_%s", time.Now().UnixNano(), t.Name()))
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
	secretRepo := repository.NewBadgerSecretRepository(badgerClient)
	secretPolicyRepo := repository.NewBadgerSecretPolicyRepository(badgerClient)
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)

	// Initialize services
	auditService := service.NewAuditService(auditRepo)
	authService := service.NewAuthService(userRepo, auditService, testConfig.JWT.Secret, testConfig.JWT.ExpiryHours)
	generationService := service.NewSecretGenerationService()
	policyService := service.NewSecretPolicyService(secretPolicyRepo, secretRepo, generationService, auditService)

	// Initialize middleware
	jwtMiddleware := security.NewJWTMiddleware(authService)

	// Initialize policy controller
	policyController := controller.NewSecretPolicyController(policyService, generationService, jwtMiddleware)

	// Create a test user
	ctx := context.Background()
	hashedPassword, err := service.HashPassword("testpass123")
	require.NoError(t, err)

	testUser := entity.NewVaultUser("policytest", "policytest@example.com", hashedPassword)
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

	return &SecretPolicyTestServices{
		BadgerClient:      badgerClient,
		Config:            testConfig,
		PolicyService:     policyService,
		GenerationService: generationService,
		PolicyController:  policyController,
		JWTMiddleware:     jwtMiddleware,
		AuthService:       authService,
		TestUser:          testUser,
	}
}

func generatePolicyTestJWT(services *SecretPolicyTestServices) string {
	token, _ := services.AuthService.GenerateToken(services.TestUser.ID.String(), services.TestUser.Username)
	return token
}

func TestSecretPolicyController_CreatePolicy_Success(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Create policy request
	createRequest := dto.CreateSecretPolicyRequest{
		Name:        "Test Password Policy",
		Description: "Policy for testing password generation",
		PathPattern: "secrets/test/*",
		Rules: map[string]interface{}{
			"password_length":   16,
			"require_uppercase": true,
			"require_lowercase": true,
			"require_numbers":   true,
			"require_symbols":   true,
			"rotation_days":     90,
		},
		IsActive: true,
	}

	jsonData, err := json.Marshal(createRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/secret-policies", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Test Password Policy", response["name"])
	assert.Equal(t, "Policy for testing password generation", response["description"])
	assert.Equal(t, "secrets/test/*", response["path_pattern"])
	assert.Contains(t, response, "id")
	assert.Contains(t, response, "created_at")
	assert.Equal(t, services.TestUser.ID.String(), response["created_by"])
	assert.Equal(t, true, response["is_active"])

	// Verify rules
	rules := response["rules"].(map[string]interface{})
	assert.Equal(t, float64(16), rules["password_length"])
	assert.Equal(t, true, rules["require_uppercase"])
}

func TestSecretPolicyController_GetPolicy_Success(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Create a test policy first
	ctx := context.Background()
	policy := &entity.SecretPolicy{
		ID:          entity.GenerateUUID(),
		Name:        "Get Test Policy",
		Description: "Policy for get test",
		PathPattern: "secrets/prod/*",
		Rules: map[string]interface{}{
			"password_length": 12,
			"rotation_days":   30,
		},
		CreatedBy: services.TestUser.ID.String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		IsActive:  true,
	}

	err := services.PolicyService.CreatePolicy(ctx, policy, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/secret-policies/"+policy.ID.String(), nil)
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Get Test Policy", response["name"])
	assert.Equal(t, "Policy for get test", response["description"])
	assert.Equal(t, "secrets/prod/*", response["path_pattern"])
	assert.Equal(t, policy.ID.String(), response["id"])
	assert.Equal(t, true, response["is_active"])
}

func TestSecretPolicyController_UpdatePolicy_Success(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Create a test policy first
	ctx := context.Background()
	policy := &entity.SecretPolicy{
		ID:          entity.GenerateUUID(),
		Name:        "Update Test Policy",
		Description: "Policy for update test",
		PathPattern: "secrets/dev/*",
		Rules: map[string]interface{}{
			"password_length": 8,
		},
		CreatedBy: services.TestUser.ID.String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		IsActive:  true,
	}

	err := services.PolicyService.CreatePolicy(ctx, policy, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Update policy request
	updateRequest := dto.UpdateSecretPolicyRequest{
		Name:        "Updated Policy Name",
		Description: "Updated description",
		PathPattern: "secrets/staging/*",
		Rules: map[string]interface{}{
			"password_length":   14,
			"require_uppercase": true,
			"require_numbers":   true,
			"rotation_days":     60,
		},
		IsActive: false,
	}

	jsonData, err := json.Marshal(updateRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("PUT", "/api/v1/secret-policies/"+policy.ID.String(), bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Updated Policy Name", response["name"])
	assert.Equal(t, "Updated description", response["description"])
	assert.Equal(t, "secrets/staging/*", response["path_pattern"])
	assert.Equal(t, policy.ID.String(), response["id"])
	assert.Equal(t, false, response["is_active"])

	// Verify updated rules
	rules := response["rules"].(map[string]interface{})
	assert.Equal(t, float64(14), rules["password_length"])
	assert.Equal(t, true, rules["require_uppercase"])
	assert.Equal(t, float64(60), rules["rotation_days"])
}

func TestSecretPolicyController_ListPolicies_Success(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Create multiple test policies
	ctx := context.Background()
	policies := []*entity.SecretPolicy{
		{
			ID:          entity.GenerateUUID(),
			Name:        "Policy Alpha",
			Description: "First test policy",
			PathPattern: "secrets/alpha/*",
			Rules: map[string]interface{}{
				"password_length": 10,
			},
			CreatedBy: services.TestUser.ID.String(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			IsActive:  true,
		},
		{
			ID:          entity.GenerateUUID(),
			Name:        "Policy Beta",
			Description: "Second test policy",
			PathPattern: "secrets/beta/*",
			Rules: map[string]interface{}{
				"password_length": 16,
				"rotation_days":   90,
			},
			CreatedBy: services.TestUser.ID.String(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			IsActive:  true,
		},
	}

	for _, policy := range policies {
		err := services.PolicyService.CreatePolicy(ctx, policy, services.TestUser.ID.String())
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/secret-policies?limit=10&offset=0", nil)
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "policies")
	assert.Contains(t, response, "total")
	assert.Contains(t, response, "limit")
	assert.Contains(t, response, "offset")

	policies_data := response["policies"].([]interface{})
	assert.GreaterOrEqual(t, len(policies_data), 2)

	// Verify policy structure
	firstPolicy := policies_data[0].(map[string]interface{})
	assert.Contains(t, firstPolicy, "id")
	assert.Contains(t, firstPolicy, "name")
	assert.Contains(t, firstPolicy, "path_pattern")
	assert.Contains(t, firstPolicy, "is_active")
}

func TestSecretPolicyController_DeletePolicy_Success(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Create a test policy first
	ctx := context.Background()
	policy := &entity.SecretPolicy{
		ID:          entity.GenerateUUID(),
		Name:        "Delete Test Policy",
		Description: "Policy for delete test",
		PathPattern: "secrets/delete/*",
		Rules: map[string]interface{}{
			"password_length": 12,
		},
		CreatedBy: services.TestUser.ID.String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		IsActive:  true,
	}

	err := services.PolicyService.CreatePolicy(ctx, policy, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("DELETE", "/api/v1/secret-policies/"+policy.ID.String(), nil)
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Secret policy deleted successfully", response["message"])
}

func TestSecretPolicyController_GenerateSecret_Success(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Generate secret request
	generateRequest := dto.GenerateSecretRequest{
		Type: "password",
		Options: map[string]interface{}{
			"length":            16,
			"include_uppercase": true,
			"include_lowercase": true,
			"include_numbers":   true,
			"include_symbols":   true,
		},
	}

	jsonData, err := json.Marshal(generateRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/secret-policies/generate", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "secret")
	assert.Contains(t, response, "type")
	assert.Equal(t, "password", response["type"])

	// Verify generated secret
	secret := response["secret"].(string)
	assert.Len(t, secret, 16)
	assert.NotEmpty(t, secret)
}

func TestSecretPolicyController_ValidateSecret_Success(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Create a test policy first
	ctx := context.Background()
	policy := &entity.SecretPolicy{
		ID:          entity.GenerateUUID(),
		Name:        "Validation Policy",
		Description: "Policy for validation test",
		PathPattern: "secrets/validate/*",
		Rules: map[string]interface{}{
			"password_length":   12,
			"require_uppercase": true,
			"require_lowercase": true,
			"require_numbers":   true,
		},
		CreatedBy: services.TestUser.ID.String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		IsActive:  true,
	}

	err := services.PolicyService.CreatePolicy(ctx, policy, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Validate secret request
	validateRequest := dto.ValidateSecretRequest{
		SecretPath:  "secrets/validate/test",
		SecretValue: "ValidPass123", // Meets policy requirements
	}

	jsonData, err := json.Marshal(validateRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/secret-policies/validate", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "valid")
	assert.Contains(t, response, "violations")

	// The secret should be valid according to policy
	assert.Equal(t, true, response["valid"])

	violations := response["violations"].([]interface{})
	assert.Equal(t, 0, len(violations)) // Should have no violations
}

func TestSecretPolicyController_ValidateSecret_PolicyViolation(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Create a test policy with strict requirements
	ctx := context.Background()
	policy := &entity.SecretPolicy{
		ID:          entity.GenerateUUID(),
		Name:        "Strict Validation Policy",
		Description: "Strict policy for validation test",
		PathPattern: "secrets/strict/*",
		Rules: map[string]interface{}{
			"password_length":   20, // Requires 20+ characters
			"require_uppercase": true,
			"require_lowercase": true,
			"require_numbers":   true,
			"require_symbols":   true,
		},
		CreatedBy: services.TestUser.ID.String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		IsActive:  true,
	}

	err := services.PolicyService.CreatePolicy(ctx, policy, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Validate secret request with weak password
	validateRequest := dto.ValidateSecretRequest{
		SecretPath:  "secrets/strict/test",
		SecretValue: "weak123", // Does not meet policy requirements
	}

	jsonData, err := json.Marshal(validateRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/secret-policies/validate", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "valid")
	assert.Contains(t, response, "violations")

	// The secret should be invalid due to policy violations
	assert.Equal(t, false, response["valid"])

	violations := response["violations"].([]interface{})
	assert.Greater(t, len(violations), 0) // Should have violations
}

func TestSecretPolicyController_CreatePolicy_InvalidJSON(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with invalid JSON
	req, err := http.NewRequest("POST", "/api/v1/secret-policies", bytes.NewBufferString(`{"invalid json`))
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretPolicyController_GetPolicy_NotFound(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request for non-existent policy
	nonExistentID := entity.GenerateUUID().String()
	req, err := http.NewRequest("GET", "/api/v1/secret-policies/"+nonExistentID, nil)
	require.NoError(t, err)

	token := generatePolicyTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSecretPolicyController_Unauthorized_NoToken(t *testing.T) {
	services := setupSecretPolicyTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register policy routes
	services.PolicyController.RegisterRoutes(router.Group("/api/v1"))

	// Make request without JWT token
	req, err := http.NewRequest("GET", "/api/v1/secret-policies", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
