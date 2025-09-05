package dto

import (
	"time"

	"PropGuard/internal/entity"
)

// CreateAPIKeyRequest represents a request to create an API key
type CreateAPIKeyRequest struct {
	Name             string     `json:"name" binding:"required,max=100"`
	Description      string     `json:"description,omitempty"`
	Permissions      []string   `json:"permissions,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RateLimitPerHour int        `json:"rate_limit_per_hour,omitempty"`
}

// UpdateAPIKeyRequest represents a request to update an API key
type UpdateAPIKeyRequest struct {
	Name             string     `json:"name,omitempty"`
	Description      string     `json:"description,omitempty"`
	Permissions      []string   `json:"permissions,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	IsActive         *bool      `json:"is_active,omitempty"`
	RateLimitPerHour *int       `json:"rate_limit_per_hour,omitempty"`
}

// APIKeyResponse represents an API key in responses (without the actual key value)
type APIKeyResponse struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	KeyPrefix        string            `json:"key_prefix"`
	UserID           string            `json:"user_id,omitempty"`
	TeamID           string            `json:"team_id,omitempty"`
	ServiceName      string            `json:"service_name,omitempty"`
	Permissions      []string          `json:"permissions"`
	Scopes           []string          `json:"scopes"`
	IPWhitelist      []string          `json:"ip_whitelist,omitempty"`
	ExpiresAt        *time.Time        `json:"expires_at,omitempty"`
	LastUsedAt       *time.Time        `json:"last_used_at,omitempty"`
	LastUsedIP       string            `json:"last_used_ip,omitempty"`
	UsageCount       int64             `json:"usage_count"`
	IsActive         bool              `json:"is_active"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
	CreatedBy        string            `json:"created_by"`
	RevokedAt        *time.Time        `json:"revoked_at,omitempty"`
	RevokedBy        string            `json:"revoked_by,omitempty"`
	Description      string            `json:"description,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	RateLimitPerHour int               `json:"rate_limit_per_hour"`
}

// CreateAPIKeyResponse represents the response when creating an API key (includes the actual key)
type CreateAPIKeyResponse struct {
	APIKey    APIKeyResponse `json:"api_key"`
	ActualKey string         `json:"actual_key"` // Only returned once during creation
	Warning   string         `json:"warning"`    // Security warning about key storage
}

// ListAPIKeysResponse represents a paginated list of API keys
type ListAPIKeysResponse struct {
	APIKeys    []APIKeyResponse `json:"api_keys"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

// APIKeyUsageStatsResponse represents usage statistics for an API key
type APIKeyUsageStatsResponse struct {
	KeyID              string           `json:"key_id"`
	TotalRequests      int64            `json:"total_requests"`
	SuccessfulRequests int64            `json:"successful_requests"`
	FailedRequests     int64            `json:"failed_requests"`
	LastHourRequests   int64            `json:"last_hour_requests"`
	LastDayRequests    int64            `json:"last_day_requests"`
	UniqueIPs          []string         `json:"unique_ips"`
	TopEndpoints       map[string]int64 `json:"top_endpoints"`
	UsageByDay         map[string]int64 `json:"usage_by_day"`
	UsageByHour        map[string]int64 `json:"usage_by_hour"`
	LastUpdated        time.Time        `json:"last_updated"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string            `json:"error"`
	Code    string            `json:"code,omitempty"`
	Details map[string]string `json:"details,omitempty"`
	Message string            `json:"message,omitempty"`
}

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ToAPIKeyResponse converts entity.APIKey to dto.APIKeyResponse
func ToAPIKeyResponse(apiKey *entity.APIKey) APIKeyResponse {
	userID := ""
	if apiKey.UserID != "" {
		userID = apiKey.UserID
	}

	return APIKeyResponse{
		ID:               apiKey.ID,
		Name:             apiKey.Name,
		KeyPrefix:        apiKey.KeyPrefix,
		UserID:           userID,
		Permissions:      apiKey.Permissions,
		Scopes:           apiKey.Scopes,
		IPWhitelist:      apiKey.IPWhitelist,
		ExpiresAt:        apiKey.ExpiresAt,
		RevokedAt:        apiKey.RevokedAt,
		LastUsedAt:       apiKey.LastUsedAt,
		LastUsedIP:       apiKey.LastUsedIP,
		UsageCount:       apiKey.UsageCount,
		RateLimitPerHour: 1000, // Default value - should be added to entity
		IsActive:         apiKey.IsActive,
		CreatedAt:        apiKey.CreatedAt,
		UpdatedAt:        apiKey.UpdatedAt,
		CreatedBy:        apiKey.CreatedBy,
		Description:      apiKey.Description,
		Metadata:         apiKey.Metadata,
	}
}

// ToCreateAPIKeyResponse converts entity.APIKeyResponse to dto.CreateAPIKeyResponse
func ToCreateAPIKeyResponse(apiKey *entity.APIKey, key string) CreateAPIKeyResponse {
	return CreateAPIKeyResponse{
		APIKey:    ToAPIKeyResponse(apiKey),
		ActualKey: key,
		Warning:   "Store this API key securely. It will not be shown again.",
	}
}

// ToAPIKeyUsageStatsResponse converts entity.APIKeyUsageStats to dto.APIKeyUsageStatsResponse
func ToAPIKeyUsageStatsResponse(stats *entity.APIKeyUsageStats) APIKeyUsageStatsResponse {
	return APIKeyUsageStatsResponse{
		KeyID:              stats.KeyID,
		TotalRequests:      stats.TotalRequests,
		SuccessfulRequests: stats.SuccessfulRequests,
		FailedRequests:     stats.FailedRequests,
		LastHourRequests:   stats.LastHourRequests,
		LastDayRequests:    stats.LastDayRequests,
		UniqueIPs:          stats.UniqueIPs,
		TopEndpoints:       stats.TopEndpoints,
		LastUpdated:        stats.LastUpdated,
		UsageByDay:         make(map[string]int64),
		UsageByHour:        make(map[string]int64),
	}
}

// NewErrorResponse creates a new error response
func NewErrorResponse(err error) ErrorResponse {
	return ErrorResponse{
		Error:   err.Error(),
		Message: "An error occurred while processing your request",
	}
}

// NewErrorResponseWithCode creates a new error response with error code
func NewErrorResponseWithCode(err error, code string) ErrorResponse {
	return ErrorResponse{
		Error:   err.Error(),
		Code:    code,
		Message: "An error occurred while processing your request",
	}
}

// NewSuccessResponse creates a new success response
func NewSuccessResponse(message string, data interface{}) SuccessResponse {
	return SuccessResponse{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// PaginatedAPIKeysResponse represents paginated API keys response
type PaginatedAPIKeysResponse struct {
	Data     []APIKeyResponse `json:"data"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"pageSize"`
	HasNext  bool             `json:"hasNext"`
	HasPrev  bool             `json:"hasPrev"`
}

// RegenerateAPIKeyResponse represents response for API key regeneration
type RegenerateAPIKeyResponse struct {
	NewKey  string `json:"new_key"`
	Warning string `json:"warning"`
}

// APIKeyUsageResponse represents API key usage statistics
type APIKeyUsageResponse struct {
	KeyID            string     `json:"key_id"`
	UsageCount       int64      `json:"usage_count"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	RateLimitPerHour int        `json:"rate_limit_per_hour"`
	IsActive         bool       `json:"is_active"`
	CreatedAt        time.Time  `json:"created_at"`
}
