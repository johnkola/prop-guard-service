package tests

import (
	"os"
	"testing"
	"time"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
	"PropGuard/internal/service"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests for PropGuard services
// These tests use in-memory implementations to avoid external dependencies

func TestEncryptionService_Integration(t *testing.T) {
	// Test the actual encryption service
	testKey := "test-master-key-32-bytes-long!!"
	encService := service.NewEncryptionService(testKey)

	testCases := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple string",
			plaintext: "hello world",
		},
		{
			name:      "json data",
			plaintext: `{"username":"admin","password":"secret123"}`,
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "special characters",
			plaintext: "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test encryption
			encrypted, err := encService.Encrypt(tc.plaintext)
			require.NoError(t, err, "encryption should not fail")
			assert.NotEmpty(t, encrypted, "encrypted text should not be empty")
			assert.NotEqual(t, tc.plaintext, encrypted, "encrypted text should differ from plaintext")

			// Test decryption
			decrypted, err := encService.Decrypt(encrypted)
			require.NoError(t, err, "decryption should not fail")
			assert.Equal(t, tc.plaintext, decrypted, "decrypted text should match original")

			// Test hash generation
			hash := encService.GenerateHash(tc.plaintext)
			assert.NotEmpty(t, hash, "hash should not be empty")

			// Same input should generate same hash
			hash2 := encService.GenerateHash(tc.plaintext)
			assert.Equal(t, hash, hash2, "same input should generate same hash")
		})
	}
}

func TestEncryptionService_InvalidDecryption(t *testing.T) {
	testKey := "test-master-key-32-bytes-long!!"
	encService := service.NewEncryptionService(testKey)

	testCases := []struct {
		name        string
		invalidData string
	}{
		{
			name:        "empty string",
			invalidData: "",
		},
		{
			name:        "invalid base64",
			invalidData: "not-base64-data!!!",
		},
		{
			name:        "too short data",
			invalidData: "dGVzdA==", // base64 for "test" - too short for nonce
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := encService.Decrypt(tc.invalidData)
			assert.Error(t, err, "decryption of invalid data should fail")
		})
	}
}

func TestAuthService_TokenGeneration(t *testing.T) {
	// Skip if not in integration test mode
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test - set INTEGRATION_TEST=1 to run")
	}

	// Create mock dependencies
	userRepo := repository.NewBadgerUserRepository(nil) // Will need proper badger client
	auditService := service.NewAuditService(nil)        // Will need proper audit repo
	jwtSecret := "test-jwt-secret-key-for-testing"
	jwtExpiryHours := 24
	authService := service.NewAuthService(userRepo, auditService, jwtSecret, jwtExpiryHours)

	// Create test user (variable not used in this test)
	_ = &entity.VaultUser{
		ID:                    entity.GenerateUUIDv7(),
		Username:              "testuser",
		Email:                 "test@example.com",
		Roles:                 []entity.VaultRole{entity.VaultRole("role_user")},
		Enabled:               true,
		AccountNonExpired:     true,
		AccountNonLocked:      true,
		CredentialsNonExpired: true,
	}

	// Test token generation (we can't test private method directly, but we can test validation)
	// This would require exposing a public method or testing through login flow
	t.Log("Auth service created successfully")
	assert.NotNil(t, authService)
}

func TestEntity_SecretCreation(t *testing.T) {
	path := "/test/secret"
	encryptedData := "encrypted-test-data"
	namespace := "test-namespace"
	userUUID := uuid.New()

	secret := entity.NewSecret(path, encryptedData, namespace, userUUID)

	assert.NotNil(t, secret)
	assert.NotEqual(t, uuid.Nil, secret.ID)
	assert.Equal(t, path, secret.Path)
	assert.Equal(t, encryptedData, secret.EncryptedData)
	assert.Equal(t, namespace, secret.NetworkNamespace)
	assert.Equal(t, userUUID, secret.CreatedBy)
	assert.Equal(t, userUUID, secret.UpdatedBy)
	assert.False(t, secret.CreatedAt.IsZero())
	assert.False(t, secret.UpdatedAt.IsZero())
	assert.Equal(t, int64(1), secret.Version)
	assert.Nil(t, secret.ExpiresAt)
}

func TestEntity_SecretTTL(t *testing.T) {
	secret := entity.NewSecret("/test", "data", "default", uuid.New())

	// Test setting TTL
	ttlSeconds := int64(300) // 5 minutes
	secret.SetTTL(ttlSeconds)

	assert.NotNil(t, secret.ExpiresAt)
	assert.True(t, secret.ExpiresAt.After(time.Now()))
	assert.False(t, secret.IsExpired())

	// Test expired secret
	secret.ExpiresAt = &[]time.Time{time.Now().Add(-time.Hour)}[0]
	assert.True(t, secret.IsExpired())
}

func TestEntity_UserCreation(t *testing.T) {
	username := "testuser"
	email := "test@example.com"
	hashedPassword := "hashed-password-123"

	user := entity.NewVaultUser(username, email, hashedPassword)

	assert.NotNil(t, user)
	assert.NotEqual(t, uuid.Nil, user.ID)
	assert.Equal(t, username, user.Username)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, hashedPassword, user.PasswordHash)
	assert.True(t, user.Enabled)
	assert.True(t, user.AccountNonExpired)
	assert.True(t, user.AccountNonLocked)
	assert.True(t, user.CredentialsNonExpired)
	assert.False(t, user.CreatedAt.IsZero())
	assert.False(t, user.UpdatedAt.IsZero())
	assert.Empty(t, user.Roles)
}

func TestEntity_AuditLogCreation(t *testing.T) {
	username := "testuser"
	action := "CREATE_SECRET"
	path := "/test/secret"
	success := true

	auditLog := entity.NewAuditLog(username, action, path, success)

	assert.NotNil(t, auditLog)
	assert.NotEqual(t, uuid.Nil, auditLog.ID)
	assert.Equal(t, username, auditLog.Username)
	assert.Equal(t, action, auditLog.Action)
	assert.Equal(t, path, auditLog.SecretPath)
	assert.Equal(t, success, auditLog.Success)
	assert.False(t, auditLog.Timestamp.IsZero())
	assert.Empty(t, auditLog.Details)
	assert.Empty(t, auditLog.ErrorMessage)
	assert.Empty(t, auditLog.ClientIP)
	assert.Empty(t, auditLog.UserAgent)
}

func TestDTO_SecretRequest(t *testing.T) {
	data := map[string]interface{}{
		"username": "admin",
		"password": "secret123",
		"port":     8080,
		"enabled":  true,
	}
	ttl := int64(3600)

	request := &dto.SecretRequest{
		Data:       data,
		TTLSeconds: &ttl,
	}

	assert.Equal(t, data, request.Data)
	assert.Equal(t, ttl, *request.TTLSeconds)
}

func TestDTO_UserRequest(t *testing.T) {
	req := dto.CreateUserRequest{
		Username: "newuser",
		Email:    "newuser@example.com",
		Password: "password123",
		Roles:    []entity.VaultRole{entity.VaultRole("role_user")},
		Enabled:  &[]bool{true}[0],
	}

	assert.Equal(t, "newuser", req.Username)
	assert.Equal(t, "newuser@example.com", req.Email)
	assert.Equal(t, "password123", req.Password)
	assert.True(t, *req.Enabled)
	assert.Len(t, req.Roles, 1)
	assert.Equal(t, entity.VaultRole("role_user"), req.Roles[0])
}

func TestPasswordHashing(t *testing.T) {
	password := "testPassword123!"

	// Test hashing
	hashedPassword, err := service.HashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hashedPassword)
	assert.NotEqual(t, password, hashedPassword)

	// Test that the same password produces different hashes
	hashedPassword2, err := service.HashPassword(password)
	require.NoError(t, err)
	assert.NotEqual(t, hashedPassword, hashedPassword2)
}

// Benchmark tests
func BenchmarkEncryption(b *testing.B) {
	testKey := "test-master-key-32-bytes-long!!"
	encService := service.NewEncryptionService(testKey)
	plaintext := "benchmark test data for encryption performance"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := encService.Encrypt(plaintext)
		if err != nil {
			b.Fatal(err)
		}
		_, err = encService.Decrypt(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashGeneration(b *testing.B) {
	testKey := "test-master-key-32-bytes-long!!"
	encService := service.NewEncryptionService(testKey)
	data := "benchmark test data for hash generation performance"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encService.GenerateHash(data)
	}
}
