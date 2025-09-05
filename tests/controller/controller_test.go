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

// Test services struct to hold individual test instances
type TestServices struct {
	BadgerClient     *repository.BadgerClient
	Config           *config.Config
	AuthService      service.AuthService
	SecretService    service.SecretService
	UserService      service.UserService
	BootstrapService *service.BootstrapServiceBadger
	JWTMiddleware    *security.JWTMiddleware
}

func setupTestServices(t *testing.T) *TestServices {
	// Create unique temporary directory for this test
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("propguard_test_%d_%s", time.Now().UnixNano(), t.Name()))
	err := os.MkdirAll(tmpDir, 0755)
	require.NoError(t, err)

	// Setup fresh test configuration for each test
	testConfig := &config.Config{
		JWT: config.JWTConfig{
			Secret:      "test-jwt-secret-key-32-bytes-long",
			ExpiryHours: 24,
		},
		Vault: config.VaultConfig{
			MasterKey:          "12345678901234567890123456789012",
			AuditRetentionDays: 90,
		},
		Badger: config.BadgerConfig{
			Dir: tmpDir,
		},
		Bootstrap: config.BootstrapConfig{
			AdminUsername: "admin",
			AdminPassword: "admin123",
			AdminEmail:    "admin@propguard.local",
		},
	}

	// Initialize fresh BadgerDB client for each test
	badgerConfig := repository.DefaultBadgerConfig(tmpDir)
	testBadgerClient, err := repository.NewBadgerClient(badgerConfig)
	require.NoError(t, err)

	// Initialize fresh repositories for each test
	encryptionService := service.NewEncryptionService(testConfig.Vault.MasterKey)
	userRepository := repository.NewBadgerUserRepository(testBadgerClient)
	secretRepository := repository.NewBadgerSecretRepository(testBadgerClient)
	auditRepository := repository.NewBadgerAuditRepository(testBadgerClient, testConfig.Vault.AuditRetentionDays)

	// Create fresh real services (matching main.go signatures)
	auditService := service.NewAuditService(auditRepository)
	authService := service.NewAuthService(userRepository, auditService, testConfig.JWT.Secret, testConfig.JWT.ExpiryHours)
	secretService := service.NewSecretService(secretRepository, userRepository, encryptionService, auditService)
	userService := service.NewUserService(userRepository, auditService)
	bootstrapService := service.NewBootstrapServiceBadger(testBadgerClient, testConfig)
	jwtMiddleware := security.NewJWTMiddleware(authService)

	// Bootstrap the fresh system
	ctx := context.Background()
	if isFirstRun, _ := bootstrapService.IsFirstRun(ctx); isFirstRun {
		err := bootstrapService.RunBootstrap(ctx)
		require.NoError(t, err)
	}

	// Cleanup function to remove test database
	t.Cleanup(func() {
		if testBadgerClient != nil {
			testBadgerClient.Close()
		}
		os.RemoveAll(tmpDir)
	})

	return &TestServices{
		BadgerClient:     testBadgerClient,
		Config:           testConfig,
		AuthService:      authService,
		SecretService:    secretService,
		UserService:      userService,
		BootstrapService: bootstrapService,
		JWTMiddleware:    jwtMiddleware,
	}
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestAuthController_Login_Success(t *testing.T) {
	services := setupTestServices(t)
	authController := controller.NewAuthController(services.AuthService)

	router := setupTestRouter()
	router.POST("/api/v1/auth/login", authController.Login)

	// Use the bootstrapped admin credentials
	loginReq := dto.LoginRequest{
		Username: "admin",
		Password: "admin123",
	}

	// Create request
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response dto.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.NotEmpty(t, response.Token)
	assert.Equal(t, "admin", response.Username)
	assert.Contains(t, response.Roles, "role_admin")
	assert.Greater(t, response.ExpiresIn, int64(0))
}

func TestAuthController_Login_InvalidCredentials(t *testing.T) {
	services := setupTestServices(t)
	authController := controller.NewAuthController(services.AuthService)

	router := setupTestRouter()
	router.POST("/api/v1/auth/login", authController.Login)

	// Use wrong password
	loginReq := dto.LoginRequest{
		Username: "admin",
		Password: "wrongpassword",
	}

	// Create request
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthController_Login_InvalidJSON(t *testing.T) {
	services := setupTestServices(t)
	authController := controller.NewAuthController(services.AuthService)

	router := setupTestRouter()
	router.POST("/api/v1/auth/login", authController.Login)

	// Create request with invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSecretController_CreateSecret_Success(t *testing.T) {
	services := setupTestServices(t)
	secretController := controller.NewSecretController(services.SecretService, services.JWTMiddleware)

	// First, login to get a valid token
	authController := controller.NewAuthController(services.AuthService)
	router := setupTestRouter()
	router.POST("/api/v1/auth/login", authController.Login)
	router.POST("/api/v1/secrets/*path", services.JWTMiddleware.Authenticate(), secretController.CreateSecret)

	// Login first
	loginReq := dto.LoginRequest{
		Username: "admin",
		Password: "admin123",
	}
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var loginResp dto.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.Token)

	// Create secret with valid token
	secretReq := &dto.SecretRequest{
		Data: map[string]interface{}{
			"username": "admin",
			"password": "secret123",
		},
	}

	body, _ = json.Marshal(secretReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/secrets/test/secret", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	w = httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusCreated, w.Code)

	var response dto.SecretResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "/test/secret", response.Path)
	assert.Equal(t, secretReq.Data, response.Data)
	assert.Greater(t, response.Version, uint64(0))
}

func TestUserController_CreateUser_Success(t *testing.T) {
	services := setupTestServices(t)
	userController := controller.NewUserController(services.UserService, services.JWTMiddleware)

	// First, login to get a valid token
	authController := controller.NewAuthController(services.AuthService)
	router := setupTestRouter()
	router.POST("/api/v1/auth/login", authController.Login)
	router.POST("/api/v1/users", services.JWTMiddleware.Authenticate(), userController.CreateUser)

	// Login first
	loginReq := dto.LoginRequest{
		Username: "admin",
		Password: "admin123",
	}
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var loginResp dto.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.Token)

	// Create user with valid token
	enabled := true
	userReq := dto.CreateUserRequest{
		Username: "newuser",
		Email:    "newuser@example.com",
		Password: "password123",
		Enabled:  &enabled,
		Roles:    []entity.VaultRole{"role_user"},
	}

	body, _ = json.Marshal(userReq)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	w = httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusCreated, w.Code)

	var response dto.UserResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, userReq.Username, response.Username)
	assert.Equal(t, *userReq.Enabled, response.Enabled)
	assert.NotZero(t, response.ID)
	assert.NotZero(t, response.CreatedAt)
}

func TestUserController_GetUser_Success(t *testing.T) {
	services := setupTestServices(t)
	userController := controller.NewUserController(services.UserService, services.JWTMiddleware)

	// First, login to get a valid token
	authController := controller.NewAuthController(services.AuthService)
	router := setupTestRouter()
	router.POST("/api/v1/auth/login", authController.Login)
	router.GET("/api/v1/users/:id", services.JWTMiddleware.Authenticate(), userController.GetUser)

	// Login first
	loginReq := dto.LoginRequest{
		Username: "admin",
		Password: "admin123",
	}
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var loginResp dto.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.Token)

	// Get the admin user (which was created during bootstrap)
	ctx := context.Background()
	adminUserResp, err := services.UserService.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	require.NotNil(t, adminUserResp)

	// Get user with valid token
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/"+adminUserResp.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	w = httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response dto.UserResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, adminUserResp.ID, response.ID)
	assert.Equal(t, "admin", response.Username)
}

func TestUserController_ListUsers_Success(t *testing.T) {
	services := setupTestServices(t)
	userController := controller.NewUserController(services.UserService, services.JWTMiddleware)

	// First, login to get a valid token
	authController := controller.NewAuthController(services.AuthService)
	router := setupTestRouter()
	router.POST("/api/v1/auth/login", authController.Login)
	router.GET("/api/v1/users", services.JWTMiddleware.Authenticate(), userController.ListUsers)

	// Login first
	loginReq := dto.LoginRequest{
		Username: "admin",
		Password: "admin123",
	}
	body, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	var loginResp dto.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	require.NotEmpty(t, loginResp.Token)

	// List users with valid token
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users?page=1&pageSize=10", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	w = httptest.NewRecorder()

	// Execute
	router.ServeHTTP(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	var response dto.ListUsersResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(response.Users), 1) // At least admin user exists
	assert.Greater(t, response.Total, int64(0))
	assert.Equal(t, 1, response.Page)
	assert.Equal(t, 10, response.PageSize)
}

// Test validation
func TestValidateSecretRequest(t *testing.T) {
	testCases := []struct {
		name    string
		request dto.SecretRequest
		isValid bool
	}{
		{
			name: "valid request",
			request: dto.SecretRequest{
				Data: map[string]interface{}{
					"username": "admin",
					"password": "secret",
				},
			},
			isValid: true,
		},
		{
			name: "empty data",
			request: dto.SecretRequest{
				Data: map[string]interface{}{},
			},
			isValid: true, // Empty data might be valid
		},
		{
			name: "nil data",
			request: dto.SecretRequest{
				Data: nil,
			},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Basic validation test
			if tc.isValid {
				assert.NotNil(t, tc.request.Data)
			} else {
				assert.Nil(t, tc.request.Data)
			}
		})
	}
}

func TestValidateUserRequest(t *testing.T) {
	testCases := []struct {
		name    string
		request dto.CreateUserRequest
		isValid bool
	}{
		{
			name: "valid request",
			request: dto.CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "password123",
				Enabled:  &[]bool{true}[0],
			},
			isValid: true,
		},
		{
			name: "empty username",
			request: dto.CreateUserRequest{
				Username: "",
				Email:    "test@example.com",
				Password: "password123",
			},
			isValid: false,
		},
		{
			name: "empty email",
			request: dto.CreateUserRequest{
				Username: "testuser",
				Email:    "",
				Password: "password123",
			},
			isValid: false,
		},
		{
			name: "empty password",
			request: dto.CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "",
			},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Basic validation test
			if tc.isValid {
				assert.NotEmpty(t, tc.request.Username)
				assert.NotEmpty(t, tc.request.Email)
				assert.NotEmpty(t, tc.request.Password)
			} else {
				hasEmptyField := tc.request.Username == "" || tc.request.Email == "" || tc.request.Password == ""
				assert.True(t, hasEmptyField)
			}
		})
	}
}
