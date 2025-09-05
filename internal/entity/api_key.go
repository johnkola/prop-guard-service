package entity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	KeyHash     string            `json:"-"`                      // Store hash, never the actual key
	KeyPrefix   string            `json:"key_prefix"`             // First 8 chars for identification
	UserID      string            `json:"user_id,omitempty"`      // Optional: for user API keys
	TeamID      string            `json:"team_id,omitempty"`      // Optional: for team API keys
	ServiceName string            `json:"service_name,omitempty"` // For service accounts
	Permissions []string          `json:"permissions"`            // Specific permissions for this key
	RoleID      string            `json:"role_id,omitempty"`      // Optional: inherit role permissions
	Scopes      []string          `json:"scopes"`                 // Resource scopes (e.g., "secrets:read:/prod/*")
	IPWhitelist []string          `json:"ip_whitelist,omitempty"` // Optional IP restrictions
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time        `json:"last_used_at,omitempty"`
	LastUsedIP  string            `json:"last_used_ip,omitempty"`
	UsageCount  int64             `json:"usage_count"`
	IsActive    bool              `json:"is_active"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by"`
	RevokedAt   *time.Time        `json:"revoked_at,omitempty"`
	RevokedBy   string            `json:"revoked_by,omitempty"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// APIKeyResponse is returned when creating a new API key (includes the actual key only once)
type APIKeyResponse struct {
	*APIKey
	Key string `json:"key"` // Only returned on creation
}

// APIKeyScope defines resource access patterns
type APIKeyScope struct {
	Resource    string   `json:"resource"`     // e.g., "secrets", "users", "teams"
	Actions     []string `json:"actions"`      // e.g., ["read", "write", "delete"]
	PathPattern string   `json:"path_pattern"` // e.g., "/prod/*", "/team/123/*"
}

// APIKeyUsageStats tracks API key usage statistics
type APIKeyUsageStats struct {
	KeyID              string           `json:"key_id"`
	TotalRequests      int64            `json:"total_requests"`
	SuccessfulRequests int64            `json:"successful_requests"`
	FailedRequests     int64            `json:"failed_requests"`
	LastHourRequests   int64            `json:"last_hour_requests"`
	LastDayRequests    int64            `json:"last_day_requests"`
	UniqueIPs          []string         `json:"unique_ips"`
	TopEndpoints       map[string]int64 `json:"top_endpoints"`
	LastUpdated        time.Time        `json:"last_updated"`
}

const (
	// API Key prefixes for different types
	APIKeyPrefixUser    = "pgu_" // PropGuard User key
	APIKeyPrefixService = "pgs_" // PropGuard Service key
	APIKeyPrefixTeam    = "pgt_" // PropGuard Team key
	APIKeyPrefixTemp    = "pgt_" // PropGuard Temporary key

	// API Key lengths
	APIKeyLength       = 32 // Random bytes
	APIKeyPrefixLength = 8  // Visible prefix length
)

// GenerateAPIKey creates a new secure API key
func GenerateAPIKey(keyType string) (string, string, error) {
	// Generate random bytes5cou
	randomBytes := make([]byte, APIKeyLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random key: %w", err)
	}

	// Create the key
	keyData := base64.URLEncoding.EncodeToString(randomBytes)
	key := fmt.Sprintf("%s%s", keyType, keyData)

	// Create hash for storage
	hash := sha256.Sum256([]byte(key))
	hashString := hex.EncodeToString(hash[:])

	return key, hashString, nil
}

// NewAPIKey creates a new API key entity
func NewAPIKey(name, userID, teamID, createdBy string) (*APIKey, string, error) {
	// Determine key type
	var keyType string
	switch {
	case userID != "":
		keyType = APIKeyPrefixUser
	case teamID != "":
		keyType = APIKeyPrefixTeam
	default:
		keyType = APIKeyPrefixService
	}

	// Generate the key
	key, keyHash, err := GenerateAPIKey(keyType)
	if err != nil {
		return nil, "", err
	}

	// Extract prefix for display
	keyPrefix := key[:APIKeyPrefixLength] + "..."

	apiKey := &APIKey{
		ID:          GenerateUUID(),
		Name:        name,
		KeyHash:     keyHash,
		KeyPrefix:   keyPrefix,
		UserID:      userID,
		TeamID:      teamID,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   createdBy,
		UsageCount:  0,
		Permissions: []string{},
		Scopes:      []string{},
		Metadata:    make(map[string]string),
	}

	return apiKey, key, nil
}

// HashAPIKey creates a hash from an API key for comparison
func HashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// ValidateAPIKey checks if a provided key matches the stored hash
func (a *APIKey) ValidateAPIKey(providedKey string) bool {
	providedHash := HashAPIKey(providedKey)
	return providedHash == a.KeyHash
}

// IsExpired checks if the API key has expired
func (a *APIKey) IsExpired() bool {
	if a.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*a.ExpiresAt)
}

// IsValid checks if the API key is valid for use
func (a *APIKey) IsValid() bool {
	return a.IsActive && !a.IsExpired() && a.RevokedAt == nil
}

// CanAccessIP checks if the provided IP is allowed
func (a *APIKey) CanAccessIP(ip string) bool {
	// If no whitelist, allow all
	if len(a.IPWhitelist) == 0 {
		return true
	}

	// Check if IP is in whitelist
	for _, allowedIP := range a.IPWhitelist {
		if allowedIP == ip {
			return true
		}
		// Support CIDR notation (simplified check)
		if strings.Contains(allowedIP, "/") {
			// TODO: Implement proper CIDR matching
			continue
		}
	}
	return false
}

// HasPermission checks if the API key has a specific permission
func (a *APIKey) HasPermission(permission string) bool {
	for _, p := range a.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasScope checks if the API key has access to a specific scope
func (a *APIKey) HasScope(resource, action, path string) bool {
	scopePattern := fmt.Sprintf("%s:%s:%s", resource, action, path)

	for _, scope := range a.Scopes {
		// Exact match
		if scope == scopePattern {
			return true
		}

		// Wildcard match
		if strings.HasSuffix(scope, "*") {
			prefix := strings.TrimSuffix(scope, "*")
			if strings.HasPrefix(scopePattern, prefix) {
				return true
			}
		}
	}
	return false
}

// RecordUsage updates the usage statistics
func (a *APIKey) RecordUsage(ip string) {
	now := time.Now()
	a.LastUsedAt = &now
	a.LastUsedIP = ip
	a.UsageCount++
	a.UpdatedAt = now
}

// Revoke marks the API key as revoked
func (a *APIKey) Revoke(revokedBy string) {
	now := time.Now()
	a.RevokedAt = &now
	a.RevokedBy = revokedBy
	a.IsActive = false
	a.UpdatedAt = now
}

// SetExpiry sets the expiration time for the API key
func (a *APIKey) SetExpiry(duration time.Duration) {
	expiryTime := time.Now().Add(duration)
	a.ExpiresAt = &expiryTime
	a.UpdatedAt = time.Now()
}

// ToJSON converts API key to JSON
func (a *APIKey) ToJSON() ([]byte, error) {
	return json.Marshal(a)
}

// FromJSON creates API key from JSON
func (a *APIKey) FromJSON(data []byte) error {
	return json.Unmarshal(data, a)
}

// SanitizedCopy returns a copy without sensitive data for client response
func (a *APIKey) SanitizedCopy() *APIKey {
	sanitized := *a
	sanitized.KeyHash = ""
	return &sanitized
}
