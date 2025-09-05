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

type RoleTestServices struct {
	BadgerClient   *repository.BadgerClient
	Config         *config.Config
	RoleRepo       repository.RoleRepository
	RoleController *controller.RoleController
	JWTMiddleware  *security.JWTMiddleware
	AuthService    service.AuthService
	AuditService   service.AuditService
	TestUser       *entity.VaultUser
}

func setupRoleTestServices(t *testing.T) *RoleTestServices {
	// Create unique temporary directory for this test
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("propguard_role_test_%d_%s", time.Now().UnixNano(), t.Name()))
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
	roleRepo := repository.NewBadgerRoleRepository(badgerClient)
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)

	// Initialize services
	auditService := service.NewAuditService(auditRepo)
	authService := service.NewAuthService(userRepo, auditService, testConfig.JWT.Secret, testConfig.JWT.ExpiryHours)

	// Initialize middleware
	jwtMiddleware := security.NewJWTMiddleware(authService)

	// Initialize role controller
	roleController := controller.NewRoleController(roleRepo, auditService, jwtMiddleware)

	// Create a test user
	ctx := context.Background()
	hashedPassword, err := service.HashPassword("testpass123")
	require.NoError(t, err)

	testUser := entity.NewVaultUser("roletest", "roletest@example.com", hashedPassword)
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

	return &RoleTestServices{
		BadgerClient:   badgerClient,
		Config:         testConfig,
		RoleRepo:       roleRepo,
		RoleController: roleController,
		JWTMiddleware:  jwtMiddleware,
		AuthService:    authService,
		AuditService:   auditService,
		TestUser:       testUser,
	}
}

func generateRoleTestJWT(services *RoleTestServices) string {
	token, _ := services.AuthService.GenerateToken(services.TestUser.ID.String(), services.TestUser.Username)
	return token
}

func TestRoleController_CreateRole_Success(t *testing.T) {
	services := setupRoleTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Create role request
	createRequest := dto.CreateRoleRequest{
		Name:        "Test Role",
		Description: "A test role for unit testing",
		Permissions: []string{
			"secrets:read",
			"secrets:write",
			"users:read",
		},
	}

	jsonData, err := json.Marshal(createRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/roles", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Test Role", response["name"])
	assert.Equal(t, "A test role for unit testing", response["description"])
	assert.Contains(t, response, "id")
	assert.Contains(t, response, "created_at")

	// Verify permissions
	permissions := response["permissions"].([]interface{})
	assert.Contains(t, permissions, "secrets:read")
	assert.Contains(t, permissions, "secrets:write")
	assert.Contains(t, permissions, "users:read")
}

func TestRoleController_GetRole_Success(t *testing.T) {
	services := setupRoleTestServices(t)

	// Create a test role first
	ctx := context.Background()
	role := &entity.Role{
		ID:          "role_test_get",
		Name:        "Get Test Role",
		Description: "Role for get test",
		Permissions: []string{"secrets:read", "users:read"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   services.TestUser.ID.String(),
		IsActive:    true,
	}

	err := services.RoleRepo.Create(ctx, role)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/roles/"+role.ID, nil)
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Get Test Role", response["name"])
	assert.Equal(t, "Role for get test", response["description"])
	assert.Equal(t, role.ID, response["id"])

	// Verify permissions
	permissions := response["permissions"].([]interface{})
	assert.Contains(t, permissions, "secrets:read")
	assert.Contains(t, permissions, "users:read")
}

func TestRoleController_UpdateRole_Success(t *testing.T) {
	services := setupRoleTestServices(t)

	// Create a test role first
	ctx := context.Background()
	role := &entity.Role{
		ID:          "role_test_update",
		Name:        "Update Test Role",
		Description: "Role for update test",
		Permissions: []string{"secrets:read"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   services.TestUser.ID.String(),
		IsActive:    true,
	}

	err := services.RoleRepo.Create(ctx, role)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Update role request
	updateRequest := dto.UpdateRoleRequest{
		Name:        "Updated Role Name",
		Description: "Updated description",
		Permissions: []string{
			"secrets:read",
			"secrets:write",
			"users:read",
			"audit:read",
		},
	}

	jsonData, err := json.Marshal(updateRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("PUT", "/api/v1/roles/"+role.ID, bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Updated Role Name", response["name"])
	assert.Equal(t, "Updated description", response["description"])
	assert.Equal(t, role.ID, response["id"])

	// Verify updated permissions
	permissions := response["permissions"].([]interface{})
	assert.Contains(t, permissions, "secrets:read")
	assert.Contains(t, permissions, "secrets:write")
	assert.Contains(t, permissions, "users:read")
	assert.Contains(t, permissions, "audit:read")
}

func TestRoleController_ListRoles_Success(t *testing.T) {
	services := setupRoleTestServices(t)

	// Create multiple test roles
	ctx := context.Background()
	roles := []*entity.Role{
		{
			ID:          "role_alpha",
			Name:        "Role Alpha",
			Description: "First test role",
			Permissions: []string{"secrets:read"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			CreatedBy:   services.TestUser.ID.String(),
			IsActive:    true,
		},
		{
			ID:          "role_beta",
			Name:        "Role Beta",
			Description: "Second test role",
			Permissions: []string{"users:read"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			CreatedBy:   services.TestUser.ID.String(),
			IsActive:    true,
		},
	}

	for _, role := range roles {
		err := services.RoleRepo.Create(ctx, role)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/roles", nil)
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response []interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(response), 2)

	// Verify role data structure
	firstRole := response[0].(map[string]interface{})
	assert.Contains(t, firstRole, "id")
	assert.Contains(t, firstRole, "name")
	assert.Contains(t, firstRole, "description")
	assert.Contains(t, firstRole, "permissions")
	assert.Contains(t, firstRole, "is_active")
}

func TestRoleController_DeleteRole_Success(t *testing.T) {
	services := setupRoleTestServices(t)

	// Create a test role first
	ctx := context.Background()
	role := &entity.Role{
		ID:          "role_test_delete",
		Name:        "Delete Test Role",
		Description: "Role for delete test",
		Permissions: []string{"secrets:read"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   services.TestUser.ID.String(),
		IsActive:    true,
	}

	err := services.RoleRepo.Create(ctx, role)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("DELETE", "/api/v1/roles/"+role.ID, nil)
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Role deleted successfully", response["message"])
}

func TestRoleController_AssignRole_Success(t *testing.T) {
	services := setupRoleTestServices(t)

	// Create a test role first
	ctx := context.Background()
	role := &entity.Role{
		ID:          "role_test_assign",
		Name:        "Assign Test Role",
		Description: "Role for assign test",
		Permissions: []string{"secrets:read"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   services.TestUser.ID.String(),
		IsActive:    true,
	}

	err := services.RoleRepo.Create(ctx, role)
	require.NoError(t, err)

	// Create another test user to assign role to
	hashedPassword, err := service.HashPassword("assigntest123")
	require.NoError(t, err)

	assignUser := entity.NewVaultUser("assigntest", "assign@example.com", hashedPassword)
	userRepo := repository.NewBadgerUserRepository(services.BadgerClient)
	err = userRepo.Create(ctx, assignUser)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Assign role request
	assignRequest := dto.AssignRoleRequest{
		UserID: assignUser.ID.String(),
	}

	jsonData, err := json.Marshal(assignRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/roles/"+role.ID+"/assign", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Role assigned successfully", response["message"])
}

func TestRoleController_RevokeRole_Success(t *testing.T) {
	services := setupRoleTestServices(t)

	// Create a test role first
	ctx := context.Background()
	role := &entity.Role{
		ID:          "role_test_revoke",
		Name:        "Revoke Test Role",
		Description: "Role for revoke test",
		Permissions: []string{"secrets:read"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   services.TestUser.ID.String(),
		IsActive:    true,
	}

	err := services.RoleRepo.Create(ctx, role)
	require.NoError(t, err)

	// Create another test user and assign role first
	hashedPassword, err := service.HashPassword("revoketest123")
	require.NoError(t, err)

	revokeUser := entity.NewVaultUser("revoketest", "revoke@example.com", hashedPassword)
	revokeUser.RoleIDs = []string{role.ID}
	userRepo := repository.NewBadgerUserRepository(services.BadgerClient)
	err = userRepo.Create(ctx, revokeUser)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Revoke role request
	revokeRequest := dto.RevokeRoleRequest{
		UserID: revokeUser.ID.String(),
	}

	jsonData, err := json.Marshal(revokeRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/roles/"+role.ID+"/revoke", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Role revoked successfully", response["message"])
}

func TestRoleController_GetRolePermissions_Success(t *testing.T) {
	services := setupRoleTestServices(t)

	// Create a test role first
	ctx := context.Background()
	role := &entity.Role{
		ID:          "role_test_permissions",
		Name:        "Permissions Test Role",
		Description: "Role for permissions test",
		Permissions: []string{
			"secrets:read",
			"secrets:write",
			"users:read",
			"audit:read",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: services.TestUser.ID.String(),
		IsActive:  true,
	}

	err := services.RoleRepo.Create(ctx, role)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/roles/"+role.ID+"/permissions", nil)
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "role_id")
	assert.Contains(t, response, "permissions")
	assert.Equal(t, role.ID, response["role_id"])

	// Verify permissions
	permissions := response["permissions"].([]interface{})
	assert.Contains(t, permissions, "secrets:read")
	assert.Contains(t, permissions, "secrets:write")
	assert.Contains(t, permissions, "users:read")
	assert.Contains(t, permissions, "audit:read")
}

func TestRoleController_CreateRole_InvalidJSON(t *testing.T) {
	services := setupRoleTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with invalid JSON
	req, err := http.NewRequest("POST", "/api/v1/roles", bytes.NewBufferString(`{"invalid json`))
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleController_GetRole_NotFound(t *testing.T) {
	services := setupRoleTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Make request for non-existent role
	req, err := http.NewRequest("GET", "/api/v1/roles/nonexistent_role", nil)
	require.NoError(t, err)

	token := generateRoleTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRoleController_Unauthorized_NoToken(t *testing.T) {
	services := setupRoleTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register role routes
	services.RoleController.RegisterRoutes(router.Group("/api/v1"))

	// Make request without JWT token
	req, err := http.NewRequest("GET", "/api/v1/roles", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
