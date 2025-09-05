package controller

import (
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

type AuditTestServices struct {
	BadgerClient    *repository.BadgerClient
	Config          *config.Config
	AuditRepo       repository.AuditRepository
	AuditController *controller.AuditController
	JWTMiddleware   *security.JWTMiddleware
	AuthService     service.AuthService
	AuditService    service.AuditService
	TestUser        *entity.VaultUser
}

func setupAuditTestServices(t *testing.T) *AuditTestServices {
	// Create unique temporary directory for this test
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("propguard_audit_test_%d_%s", time.Now().UnixNano(), t.Name()))
	err := os.MkdirAll(tmpDir, 0755)
	require.NoError(t, err)

	// Setup fresh test configuration for each test
	testConfig := &config.Config{
		JWT: config.JWTConfig{
			Secret:      "test-jwt-secret-exactly-32b",
			ExpiryHours: 24,
		},
		Vault: config.VaultConfig{
			MasterKey:          "12345678901234567890123456789012",
			AuditRetentionDays: 30,
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
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, testConfig.Vault.AuditRetentionDays)

	// Initialize services
	auditService := service.NewAuditService(auditRepo)
	authService := service.NewAuthService(userRepo, auditService, testConfig.JWT.Secret, testConfig.JWT.ExpiryHours)

	// Initialize middleware
	jwtMiddleware := security.NewJWTMiddleware(authService)

	// Initialize audit controller
	auditController := controller.NewAuditController(auditRepo, auditService, jwtMiddleware)

	// Create a test user
	ctx := context.Background()
	hashedPassword, err := service.HashPassword("testpass123")
	require.NoError(t, err)

	testUser := entity.NewVaultUser("audittest", "audittest@example.com", hashedPassword)
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

	return &AuditTestServices{
		BadgerClient:    badgerClient,
		Config:          testConfig,
		AuditRepo:       auditRepo,
		AuditController: auditController,
		JWTMiddleware:   jwtMiddleware,
		AuthService:     authService,
		AuditService:    auditService,
		TestUser:        testUser,
	}
}

func generateAuditTestJWT(services *AuditTestServices) string {
	token, _ := services.AuthService.GenerateToken(services.TestUser.ID.String(), services.TestUser.Username)
	return token
}

func TestAuditController_GetAuditLogs_Success(t *testing.T) {
	services := setupAuditTestServices(t)

	// Create some test audit logs first
	ctx := context.Background()
	testLogs := []entity.AuditLog{
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_CREATE",
			Resource:  "secrets/test/key1",
			Details:   "Created secret in test environment",
			IPAddress: "127.0.0.1",
			UserAgent: "test-client",
			Timestamp: time.Now().Add(-2 * time.Hour),
			Success:   true,
		},
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_READ",
			Resource:  "secrets/test/key1",
			Details:   "Read secret from test environment",
			IPAddress: "127.0.0.1",
			UserAgent: "test-client",
			Timestamp: time.Now().Add(-1 * time.Hour),
			Success:   true,
		},
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_DELETE",
			Resource:  "secrets/test/key2",
			Details:   "Failed to delete non-existent secret",
			IPAddress: "127.0.0.1",
			UserAgent: "test-client",
			Timestamp: time.Now().Add(-30 * time.Minute),
			Success:   false,
		},
	}

	for _, log := range testLogs {
		err := services.AuditRepo.Create(ctx, &log)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/audit/logs?limit=10&offset=0", nil)
	require.NoError(t, err)

	token := generateAuditTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "logs")
	assert.Contains(t, response, "total")
	assert.Contains(t, response, "limit")
	assert.Contains(t, response, "offset")

	logs := response["logs"].([]interface{})
	assert.GreaterOrEqual(t, len(logs), 3)

	// Verify log structure
	firstLog := logs[0].(map[string]interface{})
	assert.Contains(t, firstLog, "id")
	assert.Contains(t, firstLog, "user_id")
	assert.Contains(t, firstLog, "action")
	assert.Contains(t, firstLog, "resource")
	assert.Contains(t, firstLog, "timestamp")
	assert.Contains(t, firstLog, "success")
}

func TestAuditController_GetAuditLogs_WithFilters(t *testing.T) {
	services := setupAuditTestServices(t)

	// Create test audit logs with different actions
	ctx := context.Background()
	testLogs := []entity.AuditLog{
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "USER_LOGIN",
			Resource:  "auth/login",
			Details:   "User login successful",
			IPAddress: "127.0.0.1",
			UserAgent: "test-client",
			Timestamp: time.Now().Add(-1 * time.Hour),
			Success:   true,
		},
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_CREATE",
			Resource:  "secrets/prod/database",
			Details:   "Created database secret",
			IPAddress: "127.0.0.1",
			UserAgent: "test-client",
			Timestamp: time.Now().Add(-30 * time.Minute),
			Success:   true,
		},
	}

	for _, log := range testLogs {
		err := services.AuditRepo.Create(ctx, &log)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Test filtering by action
	req, err := http.NewRequest("GET", "/api/v1/audit/logs?action=SECRET_CREATE&limit=10", nil)
	require.NoError(t, err)

	token := generateAuditTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	logs := response["logs"].([]interface{})
	assert.GreaterOrEqual(t, len(logs), 1)

	// Verify filtered results
	for _, logInterface := range logs {
		log := logInterface.(map[string]interface{})
		action := log["action"].(string)
		assert.Equal(t, "SECRET_CREATE", action)
	}
}

func TestAuditController_GetAuditLogs_WithUserFilter(t *testing.T) {
	services := setupAuditTestServices(t)

	// Create another test user
	ctx := context.Background()
	hashedPassword, err := service.HashPassword("otheruser123")
	require.NoError(t, err)

	otherUser := entity.NewVaultUser("otheruser", "other@example.com", hashedPassword)
	userRepo := repository.NewBadgerUserRepository(services.BadgerClient)
	err = userRepo.Create(ctx, otherUser)
	require.NoError(t, err)

	// Create test audit logs from different users
	testLogs := []entity.AuditLog{
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_READ",
			Resource:  "secrets/test/key1",
			Details:   "Read by original user",
			IPAddress: "127.0.0.1",
			UserAgent: "test-client",
			Timestamp: time.Now().Add(-1 * time.Hour),
			Success:   true,
		},
		{
			ID:        entity.GenerateUUID(),
			UserID:    otherUser.ID.String(),
			Action:    "SECRET_READ",
			Resource:  "secrets/test/key2",
			Details:   "Read by other user",
			IPAddress: "192.168.1.100",
			UserAgent: "other-client",
			Timestamp: time.Now().Add(-30 * time.Minute),
			Success:   true,
		},
	}

	for _, log := range testLogs {
		err := services.AuditRepo.Create(ctx, &log)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Test filtering by user ID
	req, err := http.NewRequest("GET", "/api/v1/audit/logs?user_id="+services.TestUser.ID.String()+"&limit=10", nil)
	require.NoError(t, err)

	token := generateAuditTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	logs := response["logs"].([]interface{})
	assert.GreaterOrEqual(t, len(logs), 1)

	// Verify filtered results - all logs should be from the test user
	for _, logInterface := range logs {
		log := logInterface.(map[string]interface{})
		userID := log["user_id"].(string)
		assert.Equal(t, services.TestUser.ID.String(), userID)
	}
}

func TestAuditController_GetAuditLog_Success(t *testing.T) {
	services := setupAuditTestServices(t)

	// Create a test audit log first
	ctx := context.Background()
	testLog := entity.AuditLog{
		ID:        entity.GenerateUUID(),
		UserID:    services.TestUser.ID.String(),
		Action:    "SECRET_UPDATE",
		Resource:  "secrets/prod/api-key",
		Details:   "Updated API key secret with new rotation",
		IPAddress: "10.0.0.1",
		UserAgent: "PropGuard-CLI/1.0",
		Timestamp: time.Now().Add(-15 * time.Minute),
		Success:   true,
	}

	err := services.AuditRepo.Create(ctx, &testLog)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/audit/logs/"+testLog.ID.String(), nil)
	require.NoError(t, err)

	token := generateAuditTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, testLog.ID.String(), response["id"])
	assert.Equal(t, testLog.UserID, response["user_id"])
	assert.Equal(t, testLog.Action, response["action"])
	assert.Equal(t, testLog.Resource, response["resource"])
	assert.Equal(t, testLog.Details, response["details"])
	assert.Equal(t, testLog.IPAddress, response["ip_address"])
	assert.Equal(t, testLog.UserAgent, response["user_agent"])
	assert.Equal(t, testLog.Success, response["success"])
}

func TestAuditController_ExportAuditLogs_CSV(t *testing.T) {
	services := setupAuditTestServices(t)

	// Create test audit logs for export
	ctx := context.Background()
	testLogs := []entity.AuditLog{
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_CREATE",
			Resource:  "secrets/prod/database",
			Details:   "Created database connection secret",
			IPAddress: "192.168.1.10",
			UserAgent: "PropGuard-Web/1.0",
			Timestamp: time.Now().Add(-2 * time.Hour),
			Success:   true,
		},
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "USER_LOGIN",
			Resource:  "auth/login",
			Details:   "Successful login attempt",
			IPAddress: "192.168.1.10",
			UserAgent: "Mozilla/5.0",
			Timestamp: time.Now().Add(-1 * time.Hour),
			Success:   true,
		},
	}

	for _, log := range testLogs {
		err := services.AuditRepo.Create(ctx, &log)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token for CSV export
	req, err := http.NewRequest("GET", "/api/v1/audit/export?format=csv&limit=100", nil)
	require.NoError(t, err)

	token := generateAuditTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "attachment")

	// Verify CSV content structure
	csvContent := w.Body.String()
	assert.Contains(t, csvContent, "ID,User ID,Action,Resource,Details")
	assert.Contains(t, csvContent, "SECRET_CREATE")
	assert.Contains(t, csvContent, "USER_LOGIN")
	assert.Contains(t, csvContent, "secrets/prod/database")
}

func TestAuditController_GetAuditStats_Success(t *testing.T) {
	services := setupAuditTestServices(t)

	// Create test audit logs with different outcomes
	ctx := context.Background()
	testLogs := []entity.AuditLog{
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_CREATE",
			Resource:  "secrets/prod/key1",
			Details:   "Success",
			IPAddress: "127.0.0.1",
			UserAgent: "test",
			Timestamp: time.Now().Add(-1 * time.Hour),
			Success:   true,
		},
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_CREATE",
			Resource:  "secrets/prod/key2",
			Details:   "Success",
			IPAddress: "127.0.0.1",
			UserAgent: "test",
			Timestamp: time.Now().Add(-50 * time.Minute),
			Success:   true,
		},
		{
			ID:        entity.GenerateUUID(),
			UserID:    services.TestUser.ID.String(),
			Action:    "SECRET_DELETE",
			Resource:  "secrets/prod/key3",
			Details:   "Failed - not found",
			IPAddress: "127.0.0.1",
			UserAgent: "test",
			Timestamp: time.Now().Add(-30 * time.Minute),
			Success:   false,
		},
	}

	for _, log := range testLogs {
		err := services.AuditRepo.Create(ctx, &log)
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/audit/stats", nil)
	require.NoError(t, err)

	token := generateAuditTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "total_events")
	assert.Contains(t, response, "successful_events")
	assert.Contains(t, response, "failed_events")
	assert.Contains(t, response, "events_by_action")
	assert.Contains(t, response, "recent_activity")

	// Verify stats
	totalEvents := response["total_events"].(float64)
	assert.GreaterOrEqual(t, totalEvents, float64(3))

	successfulEvents := response["successful_events"].(float64)
	assert.GreaterOrEqual(t, successfulEvents, float64(2))

	failedEvents := response["failed_events"].(float64)
	assert.GreaterOrEqual(t, failedEvents, float64(1))
}

func TestAuditController_CleanupAuditLogs_Success(t *testing.T) {
	services := setupAuditTestServices(t)

	// Create old audit logs that should be cleaned up
	ctx := context.Background()
	oldLog := entity.AuditLog{
		ID:        entity.GenerateUUID(),
		UserID:    services.TestUser.ID.String(),
		Action:    "SECRET_READ",
		Resource:  "secrets/old/key",
		Details:   "Old log for cleanup",
		IPAddress: "127.0.0.1",
		UserAgent: "test",
		Timestamp: time.Now().Add(-40 * 24 * time.Hour), // 40 days ago
		Success:   true,
	}

	err := services.AuditRepo.Create(ctx, &oldLog)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token for cleanup
	req, err := http.NewRequest("POST", "/api/v1/audit/cleanup", nil)
	require.NoError(t, err)

	token := generateAuditTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "message")
	assert.Contains(t, response, "cleaned_count")
	assert.Equal(t, "Audit logs cleanup completed", response["message"])
}

func TestAuditController_GetAuditLog_NotFound(t *testing.T) {
	services := setupAuditTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Make request for non-existent audit log
	nonExistentID := entity.GenerateUUID().String()
	req, err := http.NewRequest("GET", "/api/v1/audit/logs/"+nonExistentID, nil)
	require.NoError(t, err)

	token := generateAuditTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuditController_Unauthorized_NoToken(t *testing.T) {
	services := setupAuditTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register audit routes
	services.AuditController.RegisterRoutes(router.Group("/api/v1"))

	// Make request without JWT token
	req, err := http.NewRequest("GET", "/api/v1/audit/logs", nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
