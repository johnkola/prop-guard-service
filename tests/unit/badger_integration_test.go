package unit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"PropGuard/internal/config"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
)

func TestBadgerIntegration(t *testing.T) {
	fmt.Println("🧪 Testing BadgerDB Integration...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize BadgerDB with test directory
	badgerConfig := repository.BadgerConfig{
		Dir:                "/tmp/badger_test",
		ValueLogFileSize:   1 << 28,   // 256MB
		MemTableSize:       64 << 20,  // 64MB
		BlockCacheSize:     256 << 20, // 256MB
		IndexCacheSize:     100 << 20, // 100MB
		NumVersionsToKeep:  1,
		NumLevelZeroTables: 5,
		Compression:        false,
	}

	// Add encryption if configured
	if cfg.Badger.EncryptionEnabled {
		badgerConfig.EncryptionKey = []byte(cfg.Vault.MasterKey)
	}

	badgerClient, err := repository.NewBadgerClient(badgerConfig)
	if err != nil {
		t.Fatalf("Failed to connect to BadgerDB: %v", err)
	}
	defer func() {
		if err := badgerClient.Close(); err != nil {
			t.Logf("Error closing BadgerDB: %v", err)
		}
	}()

	fmt.Println("✅ BadgerDB client initialized")

	// Test basic operations
	ctx := context.Background()

	// Test 1: Basic key-value operations
	fmt.Println("🔧 Testing basic key-value operations...")
	testKey := "test:key"
	testValue := []byte("Hello BadgerDB!")

	if err := badgerClient.Set(ctx, testKey, testValue); err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	retrievedValue, err := badgerClient.Get(ctx, testKey)
	if err != nil {
		t.Fatalf("Failed to get key: %v", err)
	}

	if string(retrievedValue) != string(testValue) {
		t.Fatalf("Value mismatch: expected %s, got %s", testValue, retrievedValue)
	}
	fmt.Printf("✅ Basic operations work: %s\n", retrievedValue)

	// Test 2: JSON operations
	fmt.Println("🔧 Testing JSON operations...")
	testRole := &entity.Role{
		ID:          "test_role_123",
		Name:        "Test Role",
		Description: "A test role for BadgerDB testing",
		Permissions: []string{"test:read", "test:write"},
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   "test_user",
	}

	if err := badgerClient.SetJSON(ctx, "role:test", testRole); err != nil {
		t.Fatalf("Failed to set JSON: %v", err)
	}

	var retrievedRole entity.Role
	if err := badgerClient.GetJSON(ctx, "role:test", &retrievedRole); err != nil {
		t.Fatalf("Failed to get JSON: %v", err)
	}

	if retrievedRole.Name != testRole.Name {
		t.Fatalf("Role name mismatch: expected %s, got %s", testRole.Name, retrievedRole.Name)
	}
	fmt.Printf("✅ JSON operations work: %s\n", retrievedRole.Name)

	// Test 3: Repository operations
	fmt.Println("🔧 Testing repository operations...")
	roleRepo := repository.NewBadgerRoleRepository(badgerClient)

	if err := roleRepo.Create(ctx, testRole); err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	retrievedRoleFromRepo, err := roleRepo.GetByID(ctx, testRole.ID)
	if err != nil {
		t.Fatalf("Failed to get role by ID: %v", err)
	}

	if retrievedRoleFromRepo.Name != testRole.Name {
		t.Fatalf("Repository role mismatch: expected %s, got %s", testRole.Name, retrievedRoleFromRepo.Name)
	}
	fmt.Printf("✅ Repository operations work: %s\n", retrievedRoleFromRepo.Name)

	// Test 4: List operations
	fmt.Println("🔧 Testing list operations...")
	roles, err := roleRepo.List(ctx, 10, 0)
	if err != nil {
		t.Fatalf("Failed to list roles: %v", err)
	}

	if len(roles) == 0 {
		t.Fatalf("No roles found in list")
	}
	fmt.Printf("✅ List operations work: found %d roles\n", len(roles))

	// Test 5: Database stats
	fmt.Println("🔧 Testing database statistics...")
	stats := badgerClient.GetStats()
	fmt.Printf("✅ Database stats: LSM size: %v, VLog size: %v, Tables: %v\n",
		stats["lsm_size"], stats["vlog_size"], stats["num_tables"])

	// Cleanup test data
	fmt.Println("🧹 Cleaning up test data...")
	badgerClient.Delete(ctx, testKey)
	badgerClient.Delete(ctx, "role:test")
	roleRepo.Delete(ctx, testRole.ID)

	// Clean up test directory
	defer func() {
		if err := os.RemoveAll("/tmp/badger_test"); err != nil {
			t.Logf("Warning: Failed to clean up test directory: %v", err)
		}
	}()

	fmt.Println("🎉 All BadgerDB tests passed! Phase 2 BadgerDB integration is working correctly.")
}
