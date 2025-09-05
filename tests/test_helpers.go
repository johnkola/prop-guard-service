package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"PropGuard/internal/entity"
	"PropGuard/internal/repository"

	"github.com/stretchr/testify/require"
)

// setupTestBadgerClient creates a test BadgerDB client
func setupTestBadgerClient(t *testing.T) *repository.BadgerClient {
	// Create a temporary directory for test database
	tempDir := t.TempDir()

	config := repository.BadgerConfig{
		Dir:                tempDir,
		ValueLogFileSize:   1 << 26, // 64MB
		MemTableSize:       1 << 20, // 1MB - increased for larger BaseTableSize
		BlockCacheSize:     1 << 20, // 1MB
		IndexCacheSize:     1 << 19, // 512KB
		NumVersionsToKeep:  1,
		NumLevelZeroTables: 1,
		Compression:        false,    // Disable compression for faster tests
		BaseTableSize:      8 << 20,  // 8MB - much larger to avoid batch size issues
		ValueThreshold:     32 << 10, // 32KB - much smaller than batch size
	}

	client, err := repository.NewBadgerClient(config)
	require.NoError(t, err)

	// Test connection
	err = client.Ping()
	require.NoError(t, err)

	return client
}

// mockAuditService is a mock implementation of AuditService for testing
type mockAuditService struct{}

func (m *mockAuditService) LogAction(ctx context.Context, username, action, path string, success bool, details string) {
	// Mock implementation - do nothing
}

func (m *mockAuditService) LogUserOperation(ctx context.Context, username, action, targetUser string, success bool, details string) {
	// Mock implementation - do nothing
}

func (m *mockAuditService) LogSecretOperation(ctx context.Context, userID, operation, secretName string, success bool, details string) {
	// Mock implementation - do nothing
}

func (m *mockAuditService) LogAPIKeyOperation(ctx context.Context, userID, operation, resource string, success bool, details string) {
	// Mock implementation - do nothing
}

func (m *mockAuditService) LogServiceOperation(ctx context.Context, serviceID, operation, resource string, success bool, details string) {
	// Mock implementation - do nothing
}

func (m *mockAuditService) LogAdminOperation(ctx context.Context, adminID, operation, resource string, success bool, details string) {
	// Mock implementation - do nothing
}

func (m *mockAuditService) LogSystemOperation(ctx context.Context, systemID, operation, resource string, success bool, details string) {
	// Mock implementation - do nothing
}

func (m *mockAuditService) GetUserAuditLogs(ctx context.Context, username string, limit, offset int) ([]*entity.AuditLog, error) {
	return nil, nil
}

func (m *mockAuditService) GetPathAuditLogs(ctx context.Context, path string, limit, offset int) ([]*entity.AuditLog, error) {
	return nil, nil
}

func (m *mockAuditService) GetAuditLogsByDateRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*entity.AuditLog, error) {
	return nil, nil
}

func (m *mockAuditService) CleanupOldLogs(ctx context.Context, days int) (int64, error) {
	return 0, nil
}

// Additional test environment setup
func init() {
	// Ensure we're running in test mode
	os.Setenv("GIN_MODE", "test")

	// Set a test JWT secret
	os.Setenv("JWT_SECRET", "test-jwt-secret-key-exactly-32b")

	// Set a test vault master key
	os.Setenv("VAULT_MASTER_KEY", "12345678901234567890123456789012")
}
