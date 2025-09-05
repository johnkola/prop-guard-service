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

type TeamTestServices struct {
	BadgerClient   *repository.BadgerClient
	Config         *config.Config
	TeamService    service.TeamService
	TeamController *controller.TeamController
	JWTMiddleware  *security.JWTMiddleware
	AuthService    service.AuthService
	UserService    service.UserService
	TestUser       *entity.VaultUser
}

func setupTeamTestServices(t *testing.T) *TeamTestServices {
	// Create unique temporary directory for this test
	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("propguard_team_test_%d_%s", time.Now().UnixNano(), t.Name()))
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
	teamRepo := repository.NewBadgerTeamRepository(badgerClient)
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)

	// Initialize services
	auditService := service.NewAuditService(auditRepo)
	authService := service.NewAuthService(userRepo, auditService, testConfig.JWT.Secret, testConfig.JWT.ExpiryHours)
	userService := service.NewUserService(userRepo, auditService)
	teamService := service.NewTeamService(teamRepo, auditService)

	// Initialize middleware
	jwtMiddleware := security.NewJWTMiddleware(authService)

	// Initialize team controller
	teamController := controller.NewTeamController(teamService, jwtMiddleware)

	// Create a test user
	ctx := context.Background()
	hashedPassword, err := service.HashPassword("testpass123")
	require.NoError(t, err)

	testUser := entity.NewVaultUser("teamtest", "teamtest@example.com", hashedPassword)
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

	return &TeamTestServices{
		BadgerClient:   badgerClient,
		Config:         testConfig,
		TeamService:    teamService,
		TeamController: teamController,
		JWTMiddleware:  jwtMiddleware,
		AuthService:    authService,
		UserService:    userService,
		TestUser:       testUser,
	}
}

func generateTestJWT(services *TeamTestServices) string {
	token, _ := services.AuthService.GenerateToken(services.TestUser.ID.String(), services.TestUser.Username)
	return token
}

func TestTeamController_CreateTeam_Success(t *testing.T) {
	services := setupTeamTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Create team request
	createRequest := dto.CreateTeamRequest{
		Name:        "Test Team",
		Description: "A test team for unit testing",
		Settings: map[string]interface{}{
			"timezone": "UTC",
			"theme":    "dark",
		},
	}

	jsonData, err := json.Marshal(createRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/teams", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Test Team", response["name"])
	assert.Equal(t, "A test team for unit testing", response["description"])
	assert.Contains(t, response, "id")
	assert.Contains(t, response, "created_at")
	assert.Equal(t, services.TestUser.ID.String(), response["created_by"])
}

func TestTeamController_GetTeam_Success(t *testing.T) {
	services := setupTeamTestServices(t)

	// Create a test team first
	ctx := context.Background()
	team := &entity.Team{
		ID:          entity.GenerateUUID(),
		Name:        "Get Test Team",
		Description: "Team for get test",
		CreatedBy:   services.TestUser.ID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Settings: map[string]interface{}{
			"timezone": "PST",
		},
	}

	err := services.TeamService.CreateTeam(ctx, team, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/teams/"+team.ID.String(), nil)
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Get Test Team", response["name"])
	assert.Equal(t, "Team for get test", response["description"])
	assert.Equal(t, team.ID.String(), response["id"])
}

func TestTeamController_UpdateTeam_Success(t *testing.T) {
	services := setupTeamTestServices(t)

	// Create a test team first
	ctx := context.Background()
	team := &entity.Team{
		ID:          entity.GenerateUUID(),
		Name:        "Update Test Team",
		Description: "Team for update test",
		CreatedBy:   services.TestUser.ID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := services.TeamService.CreateTeam(ctx, team, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Update team request
	updateRequest := dto.UpdateTeamRequest{
		Name:        "Updated Team Name",
		Description: "Updated description",
		Settings: map[string]interface{}{
			"timezone": "EST",
			"theme":    "light",
		},
	}

	jsonData, err := json.Marshal(updateRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("PUT", "/api/v1/teams/"+team.ID.String(), bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Updated Team Name", response["name"])
	assert.Equal(t, "Updated description", response["description"])
	assert.Equal(t, team.ID.String(), response["id"])
}

func TestTeamController_ListTeams_Success(t *testing.T) {
	services := setupTeamTestServices(t)

	// Create multiple test teams
	ctx := context.Background()
	teams := []*entity.Team{
		{
			ID:          entity.GenerateUUID(),
			Name:        "Team Alpha",
			Description: "First test team",
			CreatedBy:   services.TestUser.ID,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          entity.GenerateUUID(),
			Name:        "Team Beta",
			Description: "Second test team",
			CreatedBy:   services.TestUser.ID,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, team := range teams {
		err := services.TeamService.CreateTeam(ctx, team, services.TestUser.ID.String())
		require.NoError(t, err)
	}

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/teams?limit=10&offset=0", nil)
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "teams")
	assert.Contains(t, response, "total")
	assert.Contains(t, response, "limit")
	assert.Contains(t, response, "offset")

	teams_data := response["teams"].([]interface{})
	assert.GreaterOrEqual(t, len(teams_data), 2)
}

func TestTeamController_DeleteTeam_Success(t *testing.T) {
	services := setupTeamTestServices(t)

	// Create a test team first
	ctx := context.Background()
	team := &entity.Team{
		ID:          entity.GenerateUUID(),
		Name:        "Delete Test Team",
		Description: "Team for delete test",
		CreatedBy:   services.TestUser.ID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := services.TeamService.CreateTeam(ctx, team, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("DELETE", "/api/v1/teams/"+team.ID.String(), nil)
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Team deleted successfully", response["message"])
}

func TestTeamController_AddMember_Success(t *testing.T) {
	services := setupTeamTestServices(t)

	// Create a test team first
	ctx := context.Background()
	team := &entity.Team{
		ID:          entity.GenerateUUID(),
		Name:        "Member Test Team",
		Description: "Team for member test",
		CreatedBy:   services.TestUser.ID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := services.TeamService.CreateTeam(ctx, team, services.TestUser.ID.String())
	require.NoError(t, err)

	// Create another test user to add as member
	hashedPassword, err := service.HashPassword("memberpass123")
	require.NoError(t, err)

	memberUser := entity.NewVaultUser("membertest", "member@example.com", hashedPassword)
	userRepo := repository.NewBadgerUserRepository(services.BadgerClient)
	err = userRepo.Create(ctx, memberUser)
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Add member request
	addMemberRequest := dto.AddTeamMemberRequest{
		UserID: memberUser.ID.String(),
		Role:   "member",
	}

	jsonData, err := json.Marshal(addMemberRequest)
	require.NoError(t, err)

	// Make request with JWT token
	req, err := http.NewRequest("POST", "/api/v1/teams/"+team.ID.String()+"/members", bytes.NewBuffer(jsonData))
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Member added successfully", response["message"])
}

func TestTeamController_ListMembers_Success(t *testing.T) {
	services := setupTeamTestServices(t)

	// Create a test team first
	ctx := context.Background()
	team := &entity.Team{
		ID:          entity.GenerateUUID(),
		Name:        "List Members Team",
		Description: "Team for list members test",
		CreatedBy:   services.TestUser.ID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := services.TeamService.CreateTeam(ctx, team, services.TestUser.ID.String())
	require.NoError(t, err)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with JWT token
	req, err := http.NewRequest("GET", "/api/v1/teams/"+team.ID.String()+"/members", nil)
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Contains(t, response, "members")

	members := response["members"].([]interface{})
	// Should at least have the team creator as owner
	assert.GreaterOrEqual(t, len(members), 1)
}

func TestTeamController_CreateTeam_InvalidJSON(t *testing.T) {
	services := setupTeamTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Make request with invalid JSON
	req, err := http.NewRequest("POST", "/api/v1/teams", bytes.NewBufferString(`{"invalid json`))
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTeamController_GetTeam_NotFound(t *testing.T) {
	services := setupTeamTestServices(t)

	// Setup Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register team routes
	services.TeamController.RegisterRoutes(router.Group("/api/v1"))

	// Make request for non-existent team
	nonExistentID := entity.GenerateUUID().String()
	req, err := http.NewRequest("GET", "/api/v1/teams/"+nonExistentID, nil)
	require.NoError(t, err)

	token := generateTestJWT(services)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusNotFound, w.Code)
}
