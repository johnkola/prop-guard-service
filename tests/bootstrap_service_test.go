package tests

import (
	"context"
	"testing"

	"PropGuard/internal/config"
	"PropGuard/internal/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrapService_IsFirstRun(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			AdminUsername: "admin",
			AdminPassword: "admin123",
			AdminEmail:    "admin@test.com",
		},
		Vault: config.VaultConfig{
			MasterKey: "12345678901234567890123456789012",
		},
	}

	bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)
	ctx := context.Background()

	t.Run("First run detection on empty database", func(t *testing.T) {
		isFirstRun, err := bootstrapService.IsFirstRun(ctx)
		require.NoError(t, err)
		assert.True(t, isFirstRun, "Should detect first run on empty database")
	})

	t.Run("Not first run after bootstrap", func(t *testing.T) {
		// Run bootstrap
		err := bootstrapService.RunBootstrap(ctx)
		require.NoError(t, err)

		// Check if it's still first run
		isFirstRun, err := bootstrapService.IsFirstRun(ctx)
		require.NoError(t, err)
		assert.False(t, isFirstRun, "Should not be first run after bootstrap")
	})
}

func TestBootstrapService_RunBootstrap(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			AdminUsername: "testadmin",
			AdminPassword: "testpass123",
			AdminEmail:    "testadmin@test.com",
		},
		Vault: config.VaultConfig{
			MasterKey: "12345678901234567890123456789012",
		},
	}

	bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)
	ctx := context.Background()

	t.Run("Successful bootstrap", func(t *testing.T) {
		isFirstRun, err := bootstrapService.IsFirstRun(ctx)
		require.NoError(t, err)
		require.True(t, isFirstRun)

		// Run bootstrap
		err = bootstrapService.RunBootstrap(ctx)
		require.NoError(t, err)

		// Verify bootstrap completed
		isFirstRun, err = bootstrapService.IsFirstRun(ctx)
		require.NoError(t, err)
		assert.False(t, isFirstRun)

		// Verify bootstrap status
		status, err := bootstrapService.GetBootstrapStatus(ctx)
		require.NoError(t, err)
		assert.True(t, status["bootstrapped"].(bool))
		assert.NotEmpty(t, status["bootstrap_date"])
		assert.NotEmpty(t, status["bootstrap_version"])
		assert.Greater(t, status["system_roles_count"].(int), 0)
		assert.Greater(t, status["users_count"].(int), 0)
		assert.Greater(t, status["teams_count"].(int), 0)
	})

	t.Run("Prevent duplicate bootstrap", func(t *testing.T) {
		// Try to bootstrap again
		err := bootstrapService.RunBootstrap(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already bootstrapped")
	})
}

func TestBootstrapService_GetBootstrapStatus(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			AdminUsername: "admin",
			AdminPassword: "admin123",
			AdminEmail:    "admin@test.com",
		},
		Vault: config.VaultConfig{
			MasterKey: "12345678901234567890123456789012",
		},
	}

	bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)
	ctx := context.Background()

	t.Run("Status before bootstrap", func(t *testing.T) {
		status, err := bootstrapService.GetBootstrapStatus(ctx)
		require.NoError(t, err)
		assert.False(t, status["bootstrapped"].(bool))
	})

	t.Run("Status after bootstrap", func(t *testing.T) {
		// Run bootstrap
		err := bootstrapService.RunBootstrap(ctx)
		require.NoError(t, err)

		// Check status
		status, err := bootstrapService.GetBootstrapStatus(ctx)
		require.NoError(t, err)

		assert.True(t, status["bootstrapped"].(bool))
		assert.NotEmpty(t, status["bootstrap_date"])
		assert.Equal(t, "1.0.0", status["bootstrap_version"])

		// Verify system components were created
		systemRolesCount, ok := status["system_roles_count"].(int)
		assert.True(t, ok)
		assert.Greater(t, systemRolesCount, 0, "Should have created system roles")

		usersCount, ok := status["users_count"].(int)
		assert.True(t, ok)
		assert.Greater(t, usersCount, 0, "Should have created admin user")

		teamsCount, ok := status["teams_count"].(int)
		assert.True(t, ok)
		assert.Greater(t, teamsCount, 0, "Should have created default team")
	})
}

func TestBootstrapService_ConfigValidation(t *testing.T) {
	t.Run("Bootstrap with empty admin username", func(t *testing.T) {
		badgerClient := setupTestBadgerClient(t)
		defer badgerClient.Close()
		cfg := &config.Config{
			Bootstrap: config.BootstrapConfig{
				AdminUsername: "", // Empty username
				AdminPassword: "admin123",
				AdminEmail:    "admin@test.com",
			},
			Vault: config.VaultConfig{
				MasterKey: "12345678901234567890123456789012",
			},
		}

		bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)
		ctx := context.Background()

		err := bootstrapService.RunBootstrap(ctx)
		// Bootstrap should still work with defaults
		require.NoError(t, err)
	})

	t.Run("Bootstrap with custom configuration", func(t *testing.T) {
		badgerClient := setupTestBadgerClient(t)
		defer badgerClient.Close()
		cfg := &config.Config{
			Bootstrap: config.BootstrapConfig{
				AdminUsername: "customadmin",
				AdminPassword: "custompass123",
				AdminEmail:    "customadmin@test.com",
			},
			Vault: config.VaultConfig{
				MasterKey: "12345678901234567890123456789012",
			},
		}

		bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)
		ctx := context.Background()

		err := bootstrapService.RunBootstrap(ctx)
		require.NoError(t, err)

		// Verify custom configuration was used
		status, err := bootstrapService.GetBootstrapStatus(ctx)
		require.NoError(t, err)
		assert.True(t, status["bootstrapped"].(bool))
	})
}

func TestBootstrapService_SystemIntegrity(t *testing.T) {
	// Setup
	badgerClient := setupTestBadgerClient(t)
	defer badgerClient.Close()

	cfg := &config.Config{
		Bootstrap: config.BootstrapConfig{
			AdminUsername: "admin",
			AdminPassword: "admin123",
			AdminEmail:    "admin@test.com",
		},
		Vault: config.VaultConfig{
			MasterKey: "12345678901234567890123456789012",
		},
	}

	bootstrapService := service.NewBootstrapServiceBadger(badgerClient, cfg)
	ctx := context.Background()

	t.Run("Verify system consistency after bootstrap", func(t *testing.T) {
		// Run bootstrap
		err := bootstrapService.RunBootstrap(ctx)
		require.NoError(t, err)

		// Verify bootstrap flag is set
		exists, err := badgerClient.Exists(ctx, "system:bootstrapped")
		require.NoError(t, err)
		assert.True(t, exists)

		// Verify bootstrap date is set
		exists, err = badgerClient.Exists(ctx, "system:bootstrap_date")
		require.NoError(t, err)
		assert.True(t, exists)

		// Verify bootstrap version is set
		exists, err = badgerClient.Exists(ctx, "system:bootstrap_version")
		require.NoError(t, err)
		assert.True(t, exists)

		// Verify system roles exist
		exists, err = badgerClient.Exists(ctx, "roles:index")
		require.NoError(t, err)
		assert.True(t, exists)

		// Verify users index exists
		exists, err = badgerClient.Exists(ctx, "users:index")
		require.NoError(t, err)
		assert.True(t, exists)

		// Verify teams index exists
		exists, err = badgerClient.Exists(ctx, "teams:index")
		require.NoError(t, err)
		assert.True(t, exists)

		// Verify default team ID is set
		exists, err = badgerClient.Exists(ctx, "system:default_team_id")
		require.NoError(t, err)
		assert.True(t, exists)
	})
}
