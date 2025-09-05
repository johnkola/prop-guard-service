package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"

	"github.com/google/uuid"
)

type APIKeyService interface {
	// API Key management
	CreateAPIKey(ctx context.Context, req *dto.CreateAPIKeyRequest, userID string) (*dto.CreateAPIKeyResponse, error)
	GetAPIKey(ctx context.Context, keyID, userID string) (*dto.APIKeyResponse, error)
	UpdateAPIKey(ctx context.Context, keyID string, req *dto.UpdateAPIKeyRequest, userID string) (*dto.APIKeyResponse, error)
	DeleteAPIKey(ctx context.Context, keyID, userID string) error
	ListAPIKeys(ctx context.Context, userID string, page, pageSize int) (*dto.ListAPIKeysResponse, error)

	// API Key authentication and validation
	ValidateAPIKey(ctx context.Context, apiKey string) (*entity.APIKey, error)
	AuthenticateAPIKey(ctx context.Context, apiKey, ipAddress string) (*entity.APIKey, error)

	// API Key operations
	RevokeAPIKey(ctx context.Context, keyID, userID string) error
	RegenerateAPIKey(ctx context.Context, keyID, userID string) (*dto.RegenerateAPIKeyResponse, error)

	// Usage and stats
	RecordUsage(ctx context.Context, keyID, ipAddress, endpoint string, success bool) error
	GetUsageStats(ctx context.Context, keyID, userID string) (*dto.APIKeyUsageStatsResponse, error)

	// Permission checks
	HasPermission(ctx context.Context, keyID, permission string) (bool, error)
	HasScope(ctx context.Context, keyID, resource, action, path string) (bool, error)

	// Team API keys (if user has team context)
	CreateTeamAPIKey(ctx context.Context, req *dto.CreateAPIKeyRequest, userID, teamID string) (*dto.CreateAPIKeyResponse, error)
	ListTeamAPIKeys(ctx context.Context, teamID, userID string, page, pageSize int) (*dto.ListAPIKeysResponse, error)
}

type apiKeyService struct {
	apiKeyRepo   *repository.BadgerAPIKeyRepository
	userRepo     *repository.BadgerUserRepository
	auditService AuditService
}

func NewAPIKeyService(
	apiKeyRepo *repository.BadgerAPIKeyRepository,
	userRepo *repository.BadgerUserRepository,
	auditService AuditService,
) APIKeyService {
	return &apiKeyService{
		apiKeyRepo:   apiKeyRepo,
		userRepo:     userRepo,
		auditService: auditService,
	}
}

// CreateAPIKey creates a new API key for the user
func (s *apiKeyService) CreateAPIKey(ctx context.Context, req *dto.CreateAPIKeyRequest, userID string) (*dto.CreateAPIKeyResponse, error) {
	// Validate request
	if err := s.validateCreateRequest(req); err != nil {
		return nil, err
	}

	// Check user exists and get user limits (if any)
	if err := s.checkUserLimits(ctx, userID); err != nil {
		return nil, err
	}

	// Create API key entity
	apiKey, actualKey, err := entity.NewAPIKey(req.Name, userID, "", userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	// Set optional fields
	apiKey.Description = req.Description
	if len(req.Permissions) > 0 {
		apiKey.Permissions = req.Permissions
	}
	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = req.ExpiresAt
	}

	// Store API key in repository
	if err := s.apiKeyRepo.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	// Log creation
	s.auditService.LogAction(ctx, userID, "API_KEY_CREATE", apiKey.ID, true,
		fmt.Sprintf("Created API key: %s", apiKey.Name))

	// Return response with actual key (only shown once)
	response := dto.ToCreateAPIKeyResponse(apiKey, actualKey)
	return &response, nil
}

// GetAPIKey retrieves an API key by ID
func (s *apiKeyService) GetAPIKey(ctx context.Context, keyID, userID string) (*dto.APIKeyResponse, error) {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid API key ID: %w", err)
	}

	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Check ownership
	if apiKey.UserID != userID {
		return nil, fmt.Errorf("access denied: API key belongs to different user")
	}

	response := dto.ToAPIKeyResponse(apiKey)
	return &response, nil
}

// UpdateAPIKey updates an existing API key
func (s *apiKeyService) UpdateAPIKey(ctx context.Context, keyID string, req *dto.UpdateAPIKeyRequest, userID string) (*dto.APIKeyResponse, error) {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid API key ID: %w", err)
	}

	// Get existing API key
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Check ownership
	if apiKey.UserID != userID {
		return nil, fmt.Errorf("access denied: API key belongs to different user")
	}

	// Update fields
	if req.Name != "" {
		apiKey.Name = req.Name
	}
	if req.Description != "" {
		apiKey.Description = req.Description
	}
	if len(req.Permissions) > 0 {
		apiKey.Permissions = req.Permissions
	}
	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = req.ExpiresAt
	}
	if req.IsActive != nil {
		apiKey.IsActive = *req.IsActive
	}

	apiKey.UpdatedAt = time.Now()

	// Update in repository
	if err := s.apiKeyRepo.Update(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("failed to update API key: %w", err)
	}

	// Log update
	s.auditService.LogAction(ctx, userID, "API_KEY_UPDATE", keyID, true,
		fmt.Sprintf("Updated API key: %s", apiKey.Name))

	response := dto.ToAPIKeyResponse(apiKey)
	return &response, nil
}

// DeleteAPIKey deletes an API key
func (s *apiKeyService) DeleteAPIKey(ctx context.Context, keyID, userID string) error {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return fmt.Errorf("invalid API key ID: %w", err)
	}

	// Get existing API key
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return fmt.Errorf("API key not found: %w", err)
	}

	// Check ownership
	if apiKey.UserID != userID {
		return fmt.Errorf("access denied: API key belongs to different user")
	}

	// Delete from repository
	if err := s.apiKeyRepo.Delete(ctx, keyUUID); err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}

	// Log deletion
	s.auditService.LogAction(ctx, userID, "API_KEY_DELETE", keyID, true,
		fmt.Sprintf("Deleted API key: %s", apiKey.Name))

	return nil
}

// ListAPIKeys lists all API keys for a user
func (s *apiKeyService) ListAPIKeys(ctx context.Context, userID string, page, pageSize int) (*dto.ListAPIKeysResponse, error) {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	// Get API keys from repository (simplified - get all for user)
	apiKeys, err := s.apiKeyRepo.GetByUserID(ctx, userUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to get API keys: %w", err)
	}

	// Apply pagination manually
	total := len(apiKeys)
	offset := (page - 1) * pageSize
	end := offset + pageSize

	if offset >= total {
		apiKeys = []*entity.APIKey{}
	} else {
		if end > total {
			end = total
		}
		apiKeys = apiKeys[offset:end]
	}

	// Convert to response DTOs
	var apiKeyResponses []dto.APIKeyResponse
	for _, apiKey := range apiKeys {
		response := dto.ToAPIKeyResponse(apiKey)
		apiKeyResponses = append(apiKeyResponses, response)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &dto.ListAPIKeysResponse{
		APIKeys:    apiKeyResponses,
		Total:      int64(total),
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ValidateAPIKey validates an API key format and checks if it exists
func (s *apiKeyService) ValidateAPIKey(ctx context.Context, apiKeyString string) (*entity.APIKey, error) {
	if apiKeyString == "" {
		return nil, fmt.Errorf("API key is required")
	}

	// Check format
	if !strings.HasPrefix(apiKeyString, entity.APIKeyPrefixUser) &&
		!strings.HasPrefix(apiKeyString, entity.APIKeyPrefixService) &&
		!strings.HasPrefix(apiKeyString, entity.APIKeyPrefixTeam) {
		return nil, fmt.Errorf("invalid API key format")
	}

	// Hash the key and look it up
	keyHash := entity.HashAPIKey(apiKeyString)
	apiKey, err := s.apiKeyRepo.GetByHash(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid API key")
	}

	return apiKey, nil
}

// AuthenticateAPIKey authenticates an API key and checks validity
func (s *apiKeyService) AuthenticateAPIKey(ctx context.Context, apiKeyString, ipAddress string) (*entity.APIKey, error) {
	// Validate key format and existence
	apiKey, err := s.ValidateAPIKey(ctx, apiKeyString)
	if err != nil {
		return nil, err
	}

	// Check if key is valid (active, not expired, not revoked)
	if !apiKey.IsValid() {
		return nil, fmt.Errorf("API key is not valid")
	}

	// Check IP whitelist if configured
	if !apiKey.CanAccessIP(ipAddress) {
		return nil, fmt.Errorf("access denied: IP not whitelisted")
	}

	// Record usage
	apiKey.RecordUsage(ipAddress)
	s.apiKeyRepo.Update(ctx, apiKey)

	// Log usage
	s.auditService.LogAction(ctx, apiKey.UserID, "API_KEY_USED", apiKey.ID, true,
		fmt.Sprintf("API key used: %s from %s", apiKey.Name, ipAddress))

	return apiKey, nil
}

// RevokeAPIKey revokes an API key
func (s *apiKeyService) RevokeAPIKey(ctx context.Context, keyID, userID string) error {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return fmt.Errorf("invalid API key ID: %w", err)
	}

	// Get existing API key
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return fmt.Errorf("API key not found: %w", err)
	}

	// Check ownership
	if apiKey.UserID != userID {
		return fmt.Errorf("access denied: API key belongs to different user")
	}

	// Revoke the key
	apiKey.Revoke(userID)

	// Update in repository
	if err := s.apiKeyRepo.Update(ctx, apiKey); err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	// Log revocation
	s.auditService.LogAction(ctx, userID, "API_KEY_REVOKE", keyID, true,
		fmt.Sprintf("Revoked API key: %s", apiKey.Name))

	return nil
}

// RegenerateAPIKey generates a new key for an existing API key entry
func (s *apiKeyService) RegenerateAPIKey(ctx context.Context, keyID, userID string) (*dto.RegenerateAPIKeyResponse, error) {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid API key ID: %w", err)
	}

	// Get existing API key
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Check ownership
	if apiKey.UserID != userID {
		return nil, fmt.Errorf("access denied: API key belongs to different user")
	}

	// Determine key type based on existing key
	var keyType string
	if apiKey.UserID != "" {
		keyType = entity.APIKeyPrefixUser
	} else if apiKey.TeamID != "" {
		keyType = entity.APIKeyPrefixTeam
	} else {
		keyType = entity.APIKeyPrefixService
	}

	// Generate new key
	newKey, newKeyHash, err := entity.GenerateAPIKey(keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key: %w", err)
	}

	// Update API key with new hash and prefix
	apiKey.KeyHash = newKeyHash
	apiKey.KeyPrefix = newKey[:entity.APIKeyPrefixLength] + "..."
	apiKey.UpdatedAt = time.Now()
	apiKey.IsActive = true
	apiKey.RevokedAt = nil
	apiKey.RevokedBy = ""

	// Update in repository
	if err := s.apiKeyRepo.Update(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("failed to update API key: %w", err)
	}

	// Log regeneration
	s.auditService.LogAction(ctx, userID, "API_KEY_REGENERATE", keyID, true,
		fmt.Sprintf("Regenerated API key: %s", apiKey.Name))

	return &dto.RegenerateAPIKeyResponse{
		NewKey:  newKey,
		Warning: "Store this new API key securely. The old key is now invalid.",
	}, nil
}

// RecordUsage records API key usage statistics
func (s *apiKeyService) RecordUsage(ctx context.Context, keyID, ipAddress, endpoint string, success bool) error {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return fmt.Errorf("invalid API key ID: %w", err)
	}

	// For now, we'll just update the basic usage tracking in the API key
	// A full implementation might have separate usage stats tracking
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return err
	}

	apiKey.RecordUsage(ipAddress)
	return s.apiKeyRepo.Update(ctx, apiKey)
}

// GetUsageStats gets usage statistics for an API key
func (s *apiKeyService) GetUsageStats(ctx context.Context, keyID, userID string) (*dto.APIKeyUsageStatsResponse, error) {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid API key ID: %w", err)
	}

	// Get API key
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return nil, fmt.Errorf("API key not found: %w", err)
	}

	// Check ownership
	if apiKey.UserID != userID {
		return nil, fmt.Errorf("access denied: API key belongs to different user")
	}

	// Create basic stats response (in a full implementation, this would query a separate stats store)
	stats := &dto.APIKeyUsageStatsResponse{
		KeyID:              keyID,
		TotalRequests:      apiKey.UsageCount,
		SuccessfulRequests: apiKey.UsageCount, // Simplified
		FailedRequests:     0,                 // Would track separately
		LastHourRequests:   0,                 // Would require time-series data
		LastDayRequests:    0,                 // Would require time-series data
		UniqueIPs:          []string{},        // Would track separately
		TopEndpoints:       make(map[string]int64),
		UsageByDay:         make(map[string]int64),
		UsageByHour:        make(map[string]int64),
		LastUpdated:        time.Now(),
	}

	return stats, nil
}

// HasPermission checks if API key has a specific permission
func (s *apiKeyService) HasPermission(ctx context.Context, keyID, permission string) (bool, error) {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return false, fmt.Errorf("invalid API key ID: %w", err)
	}

	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return false, err
	}

	return apiKey.HasPermission(permission), nil
}

// HasScope checks if API key has access to a specific scope
func (s *apiKeyService) HasScope(ctx context.Context, keyID, resource, action, path string) (bool, error) {
	keyUUID, err := uuid.Parse(keyID)
	if err != nil {
		return false, fmt.Errorf("invalid API key ID: %w", err)
	}

	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyUUID)
	if err != nil {
		return false, err
	}

	return apiKey.HasScope(resource, action, path), nil
}

// CreateTeamAPIKey creates an API key for a team
func (s *apiKeyService) CreateTeamAPIKey(ctx context.Context, req *dto.CreateAPIKeyRequest, userID, teamID string) (*dto.CreateAPIKeyResponse, error) {
	// TODO: Add team permission check here

	// Create API key entity for team
	apiKey, actualKey, err := entity.NewAPIKey(req.Name, "", teamID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate team API key: %w", err)
	}

	// Set optional fields
	apiKey.Description = req.Description
	if len(req.Permissions) > 0 {
		apiKey.Permissions = req.Permissions
	}
	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = req.ExpiresAt
	}

	// Store API key in repository
	if err := s.apiKeyRepo.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("failed to create team API key: %w", err)
	}

	// Log creation
	s.auditService.LogAction(ctx, userID, "TEAM_API_KEY_CREATE", apiKey.ID, true,
		fmt.Sprintf("Created team API key: %s for team: %s", apiKey.Name, teamID))

	// Return response with actual key (only shown once)
	response := dto.ToCreateAPIKeyResponse(apiKey, actualKey)
	return &response, nil
}

// ListTeamAPIKeys lists API keys for a team
func (s *apiKeyService) ListTeamAPIKeys(ctx context.Context, teamID, userID string, page, pageSize int) (*dto.ListAPIKeysResponse, error) {
	// TODO: Add team permission check here - verify user has access to team

	// Get team API keys from repository
	apiKeys, err := s.apiKeyRepo.GetByTeamID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team API keys: %w", err)
	}

	// Apply pagination manually
	total := len(apiKeys)
	offset := (page - 1) * pageSize
	end := offset + pageSize

	if offset >= total {
		apiKeys = []*entity.APIKey{}
	} else {
		if end > total {
			end = total
		}
		apiKeys = apiKeys[offset:end]
	}

	// Convert to response DTOs
	var apiKeyResponses []dto.APIKeyResponse
	for _, apiKey := range apiKeys {
		response := dto.ToAPIKeyResponse(apiKey)
		apiKeyResponses = append(apiKeyResponses, response)
	}

	totalPages := (total + pageSize - 1) / pageSize

	return &dto.ListAPIKeysResponse{
		APIKeys:    apiKeyResponses,
		Total:      int64(total),
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// Helper methods

func (s *apiKeyService) validateCreateRequest(req *dto.CreateAPIKeyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("API key name is required")
	}

	if len(req.Name) > 100 {
		return fmt.Errorf("API key name too long")
	}

	// Validate expiration date
	if req.ExpiresAt != nil && req.ExpiresAt.Before(time.Now()) {
		return fmt.Errorf("expiration date must be in the future")
	}

	return nil
}

func (s *apiKeyService) checkUserLimits(ctx context.Context, userID string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %w", err)
	}

	// Get user's existing API keys to check limits
	existingKeys, err := s.apiKeyRepo.GetByUserID(ctx, userUUID)
	if err != nil {
		return fmt.Errorf("failed to check existing API keys: %w", err)
	}

	total := int64(len(existingKeys))

	// Basic limit check (could be made configurable)
	const maxAPIKeysPerUser = 10
	if total >= maxAPIKeysPerUser {
		return fmt.Errorf("maximum number of API keys reached (%d)", maxAPIKeysPerUser)
	}

	// Count active keys
	activeCount := 0
	for _, key := range existingKeys {
		if key.IsValid() {
			activeCount++
		}
	}

	const maxActiveKeysPerUser = 5
	if activeCount >= maxActiveKeysPerUser {
		return fmt.Errorf("maximum number of active API keys reached (%d)", maxActiveKeysPerUser)
	}

	return nil
}
