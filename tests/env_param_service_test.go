package tests

import (
	"context"
	"fmt"
	"testing"

	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
	"PropGuard/internal/service"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvParamService_CreateEnvParam(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	envParamRepo := repository.NewBadgerEnvParamRepository(badgerClient)
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)
	encryptionService := service.NewEncryptionService("12345678901234567890123456789012") // 32 bytes key
	auditService := service.NewAuditService(auditRepo)
	envParamService := service.NewEnvParamService(envParamRepo, encryptionService, auditService)

	ctx := context.Background()

	t.Run("Create valid environment parameter", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "TEST_KEY",
			Value:       "test_value",
			Environment: "development",
			ParamType:   entity.ParamTypeString,
			IsSecret:    false,
			CreatedBy:   uuid.New(),
		}

		err := envParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)

		// Verify parameter was created
		retrieved, err := envParamService.GetEnvParam(ctx, "TEST_KEY", "development")
		require.NoError(t, err)
		assert.Equal(t, param.Key, retrieved.Key)
		assert.Equal(t, param.Value, retrieved.Value)
		assert.Equal(t, param.Environment, retrieved.Environment)
	})

	t.Run("Create encrypted environment parameter", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "SECRET_KEY",
			Value:       "secret_value",
			Environment: "production",
			ParamType:   entity.ParamTypeString,
			IsSecret:    true,
			CreatedBy:   uuid.New(),
		}

		err := envParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)

		// Verify parameter was created and can be decrypted
		retrieved, err := envParamService.GetEnvParam(ctx, "SECRET_KEY", "production")
		require.NoError(t, err)
		assert.Equal(t, param.Key, retrieved.Key)
		assert.Equal(t, "secret_value", retrieved.Value) // Should be decrypted
		assert.Equal(t, param.Environment, retrieved.Environment)
	})

	t.Run("Fail to create duplicate parameter", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "DUPLICATE_KEY",
			Value:       "value1",
			Environment: "staging",
			ParamType:   entity.ParamTypeString,
			CreatedBy:   uuid.New(),
		}

		// Create first parameter
		err := envParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)

		// Try to create duplicate
		duplicateParam := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "DUPLICATE_KEY",
			Value:       "value2",
			Environment: "staging",
			ParamType:   entity.ParamTypeString,
			CreatedBy:   uuid.New(),
		}

		err = envParamService.CreateEnvParam(ctx, duplicateParam)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}

func TestEnvParamService_UpdateEnvParam(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	envParamRepo := repository.NewBadgerEnvParamRepository(badgerClient)
	encryptionService := service.NewEncryptionService("12345678901234567890123456789012")
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)
	auditService := service.NewAuditService(auditRepo)
	envParamService := service.NewEnvParamService(envParamRepo, encryptionService, auditService)

	ctx := context.Background()

	// Create a parameter to update
	param := &entity.EnvParam{
		ID:          uuid.New(),
		Key:         "UPDATE_TEST",
		Value:       "original_value",
		Environment: "development",
		ParamType:   entity.ParamTypeString,
		CreatedBy:   uuid.New(),
	}

	err := envParamService.CreateEnvParam(ctx, param)
	require.NoError(t, err)

	t.Run("Update parameter value", func(t *testing.T) {
		newValue := "updated_value"
		err := envParamService.UpdateEnvParam(ctx, "UPDATE_TEST", "development", newValue)
		require.NoError(t, err)

		// Verify update
		retrieved, err := envParamService.GetEnvParam(ctx, "UPDATE_TEST", "development")
		require.NoError(t, err)
		assert.Equal(t, newValue, retrieved.Value)
	})

	t.Run("Update non-existent parameter", func(t *testing.T) {
		err := envParamService.UpdateEnvParam(ctx, "NON_EXISTENT", "development", "value")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestEnvParamService_ListEnvParams(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	envParamRepo := repository.NewBadgerEnvParamRepository(badgerClient)
	encryptionService := service.NewEncryptionService("12345678901234567890123456789012")
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)
	auditService := service.NewAuditService(auditRepo)
	envParamService := service.NewEnvParamService(envParamRepo, encryptionService, auditService)

	ctx := context.Background()

	// Create test parameters
	environment := "test"
	for i := 1; i <= 5; i++ {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         fmt.Sprintf("TEST_KEY_%d", i),
			Value:       fmt.Sprintf("test_value_%d", i),
			Environment: environment,
			ParamType:   entity.ParamTypeString,
			CreatedBy:   uuid.New(),
		}
		err := envParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)
	}

	t.Run("List parameters with pagination", func(t *testing.T) {
		// Get first page
		params, err := envParamService.ListEnvParams(ctx, environment, 3, 0)
		require.NoError(t, err)
		assert.Len(t, params, 3)

		// Get second page
		params, err = envParamService.ListEnvParams(ctx, environment, 3, 3)
		require.NoError(t, err)
		assert.Len(t, params, 2)
	})

	t.Run("Count parameters", func(t *testing.T) {
		count, err := envParamService.CountEnvParams(ctx, environment)
		require.NoError(t, err)
		assert.Equal(t, 5, count)
	})
}

func TestEnvParamService_GetEnvironments(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	envParamRepo := repository.NewBadgerEnvParamRepository(badgerClient)
	encryptionService := service.NewEncryptionService("12345678901234567890123456789012")
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)
	auditService := service.NewAuditService(auditRepo)
	envParamService := service.NewEnvParamService(envParamRepo, encryptionService, auditService)

	ctx := context.Background()

	// Create parameters in different environments
	environments := []string{"development", "staging", "production"}
	for _, env := range environments {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "TEST_KEY",
			Value:       "test_value",
			Environment: env,
			ParamType:   entity.ParamTypeString,
			CreatedBy:   uuid.New(),
		}
		err := envParamService.CreateEnvParam(ctx, param)
		require.NoError(t, err)
	}

	t.Run("Get all environments", func(t *testing.T) {
		envs, err := envParamService.GetEnvironments(ctx)
		require.NoError(t, err)
		assert.Len(t, envs, 3)

		// Check that all environments are present
		envMap := make(map[string]bool)
		for _, env := range envs {
			envMap[env] = true
		}
		for _, expectedEnv := range environments {
			assert.True(t, envMap[expectedEnv], "Environment %s should be present", expectedEnv)
		}
	})
}

func TestEnvParamService_DeleteEnvParam(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	envParamRepo := repository.NewBadgerEnvParamRepository(badgerClient)
	encryptionService := service.NewEncryptionService("12345678901234567890123456789012")
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)
	auditService := service.NewAuditService(auditRepo)
	envParamService := service.NewEnvParamService(envParamRepo, encryptionService, auditService)

	ctx := context.Background()

	// Create a parameter to delete
	param := &entity.EnvParam{
		ID:          uuid.New(),
		Key:         "DELETE_TEST",
		Value:       "test_value",
		Environment: "development",
		ParamType:   entity.ParamTypeString,
		CreatedBy:   uuid.New(),
	}

	err := envParamService.CreateEnvParam(ctx, param)
	require.NoError(t, err)

	t.Run("Delete existing parameter", func(t *testing.T) {
		err := envParamService.DeleteEnvParam(ctx, "DELETE_TEST", "development")
		require.NoError(t, err)

		// Verify deletion
		_, err = envParamService.GetEnvParam(ctx, "DELETE_TEST", "development")
		assert.Error(t, err) // Should not be found
	})

	t.Run("Delete non-existent parameter", func(t *testing.T) {
		err := envParamService.DeleteEnvParam(ctx, "NON_EXISTENT", "development")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestEnvParamService_ValidateEnvParam(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	envParamRepo := repository.NewBadgerEnvParamRepository(badgerClient)
	encryptionService := service.NewEncryptionService("12345678901234567890123456789012")
	auditRepo := repository.NewBadgerAuditRepository(badgerClient, 30)
	auditService := service.NewAuditService(auditRepo)
	envParamService := service.NewEnvParamService(envParamRepo, encryptionService, auditService)

	t.Run("Validate valid parameter", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "VALID_KEY",
			Value:       "valid_value",
			Environment: "development",
			ParamType:   entity.ParamTypeString,
			CreatedBy:   uuid.New(),
		}

		err := envParamService.ValidateEnvParam(param)
		assert.NoError(t, err)
	})

	t.Run("Validate parameter with empty key", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "",
			Value:       "valid_value",
			Environment: "development",
			ParamType:   entity.ParamTypeString,
			CreatedBy:   uuid.New(),
		}

		err := envParamService.ValidateEnvParam(param)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key cannot be empty")
	})

	t.Run("Validate parameter with empty environment", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "VALID_KEY",
			Value:       "valid_value",
			Environment: "",
			ParamType:   entity.ParamTypeString,
			CreatedBy:   uuid.New(),
		}

		err := envParamService.ValidateEnvParam(param)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "environment cannot be empty")
	})

	t.Run("Validate parameter with empty value", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "VALID_KEY",
			Value:       "",
			Environment: "development",
			ParamType:   entity.ParamTypeString,
			CreatedBy:   uuid.New(),
		}

		err := envParamService.ValidateEnvParam(param)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "value cannot be empty")
	})

	t.Run("Validate email parameter with invalid format", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "EMAIL_KEY",
			Value:       "invalid-email",
			Environment: "development",
			ParamType:   entity.ParamTypeEmail,
			CreatedBy:   uuid.New(),
		}

		err := envParamService.ValidateEnvParam(param)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid email format")
	})

	t.Run("Validate URL parameter with invalid format", func(t *testing.T) {
		param := &entity.EnvParam{
			ID:          uuid.New(),
			Key:         "URL_KEY",
			Value:       "invalid-url",
			Environment: "development",
			ParamType:   entity.ParamTypeURL,
			CreatedBy:   uuid.New(),
		}

		err := envParamService.ValidateEnvParam(param)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid URL format")
	})
}
