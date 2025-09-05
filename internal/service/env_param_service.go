package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
)

// EnvParamService handles environment parameter operations
type EnvParamService interface {
	GetEnvParam(ctx context.Context, key, environment string) (*entity.EnvParam, error)
	GetEnvParams(ctx context.Context, keys []string, environment string) (map[string]*entity.EnvParam, error)
	CreateEnvParam(ctx context.Context, param *entity.EnvParam) error
	UpdateEnvParam(ctx context.Context, key, environment string, value string) error
	DeleteEnvParam(ctx context.Context, key, environment string) error
	ListEnvParams(ctx context.Context, environment string, limit, offset int) ([]*entity.EnvParam, error)
	ListAllEnvParams(ctx context.Context, limit, offset int) ([]*entity.EnvParam, error)
	CountEnvParams(ctx context.Context, environment string) (int, error)
	CountAllEnvParams(ctx context.Context) (int, error)
	GetEnvironments(ctx context.Context) ([]string, error)
	BulkCreateEnvParams(ctx context.Context, params []*entity.EnvParam) error
	ValidateEnvParam(param *entity.EnvParam) error
}

// envParamService is the full implementation using BadgerDB
type envParamService struct {
	repo              *repository.BadgerEnvParamRepository
	encryptionService EncryptionService
	auditService      AuditService
}

// NewEnvParamService creates a new environment parameter service
func NewEnvParamService(repo *repository.BadgerEnvParamRepository, encryptionService EncryptionService, auditService AuditService) EnvParamService {
	return &envParamService{
		repo:              repo,
		encryptionService: encryptionService,
		auditService:      auditService,
	}
}

func (s *envParamService) GetEnvParam(ctx context.Context, key, environment string) (*entity.EnvParam, error) {
	param, err := s.repo.GetByKey(ctx, key, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to get environment parameter: %w", err)
	}

	// Decrypt value if it's encrypted
	if param != nil && param.IsSecret {
		decryptedValue, err := s.encryptionService.Decrypt(param.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt parameter value: %w", err)
		}
		param.Value = decryptedValue
	}

	return param, nil
}

func (s *envParamService) GetEnvParams(ctx context.Context, keys []string, environment string) (map[string]*entity.EnvParam, error) {
	results, err := s.repo.GetMultiple(ctx, keys, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to get environment parameters: %w", err)
	}

	// Decrypt values if they're encrypted
	for key, param := range results {
		if param != nil && param.IsSecret {
			decryptedValue, err := s.encryptionService.Decrypt(param.Value)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt parameter value for key %s: %w", key, err)
			}
			param.Value = decryptedValue
		}
	}

	return results, nil
}

func (s *envParamService) CreateEnvParam(ctx context.Context, param *entity.EnvParam) error {
	if err := s.ValidateEnvParam(param); err != nil {
		return fmt.Errorf("parameter validation failed: %w", err)
	}

	// Check if parameter already exists
	existing, _ := s.repo.GetByKey(ctx, param.Key, param.Environment)
	if existing != nil {
		return fmt.Errorf("environment parameter with key '%s' already exists in environment '%s'", param.Key, param.Environment)
	}

	// Set metadata
	now := time.Now()
	param.CreatedAt = now
	param.UpdatedAt = now

	// Encrypt value if marked as sensitive
	if param.IsSecret {
		encryptedValue, err := s.encryptionService.Encrypt(param.Value)
		if err != nil {
			return fmt.Errorf("failed to encrypt parameter value: %w", err)
		}
		param.Value = encryptedValue
	}

	if err := s.repo.Create(ctx, param); err != nil {
		return fmt.Errorf("failed to create environment parameter: %w", err)
	}

	// Audit log
	s.auditService.LogAction(ctx, param.CreatedBy.String(), "create", fmt.Sprintf("env_param:%s:%s", param.Environment, param.Key), true, fmt.Sprintf("Created environment parameter: %s:%s", param.Environment, param.Key))

	return nil
}

func (s *envParamService) UpdateEnvParam(ctx context.Context, key, environment string, value string) error {
	param, err := s.repo.GetByKey(ctx, key, environment)
	if err != nil {
		return fmt.Errorf("failed to get environment parameter: %w", err)
	}
	if param == nil {
		return fmt.Errorf("environment parameter with key '%s' not found in environment '%s'", key, environment)
	}

	// Store original value for audit
	originalValue := param.Value
	if param.IsSecret && originalValue != "" {
		// Decrypt original for comparison
		decOriginal, err := s.encryptionService.Decrypt(originalValue)
		if err == nil {
			originalValue = decOriginal
		}
	}

	// Update value
	param.Value = value
	param.UpdatedAt = time.Now()

	// Encrypt new value if marked as sensitive
	if param.IsSecret {
		encryptedValue, err := s.encryptionService.Encrypt(value)
		if err != nil {
			return fmt.Errorf("failed to encrypt parameter value: %w", err)
		}
		param.Value = encryptedValue
	}

	if err := s.repo.Update(ctx, param); err != nil {
		return fmt.Errorf("failed to update environment parameter: %w", err)
	}

	// Audit log
	s.auditService.LogAction(ctx, "system", "update", fmt.Sprintf("env_param:%s:%s", environment, key), true, fmt.Sprintf("Value changed from '%s' to '%s'", originalValue, value))

	return nil
}

func (s *envParamService) DeleteEnvParam(ctx context.Context, key, environment string) error {
	param, err := s.repo.GetByKey(ctx, key, environment)
	if err != nil {
		return fmt.Errorf("failed to get environment parameter: %w", err)
	}
	if param == nil {
		return fmt.Errorf("environment parameter with key '%s' not found in environment '%s'", key, environment)
	}

	if err := s.repo.Delete(ctx, key, environment); err != nil {
		return fmt.Errorf("failed to delete environment parameter: %w", err)
	}

	// Audit log
	s.auditService.LogAction(ctx, "system", "delete", fmt.Sprintf("env_param:%s:%s", environment, key), true, fmt.Sprintf("Deleted environment parameter: %s:%s", environment, key))

	return nil
}

func (s *envParamService) ListEnvParams(ctx context.Context, environment string, limit, offset int) ([]*entity.EnvParam, error) {
	params, err := s.repo.List(ctx, environment, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list environment parameters: %w", err)
	}

	// Decrypt values if they're encrypted (for listing, we might want to mask instead)
	for _, param := range params {
		if param.IsSecret {
			// For security, don't decrypt in list operations - just mark as encrypted
			param.Value = "[ENCRYPTED]"
		}
	}

	return params, nil
}

func (s *envParamService) ListAllEnvParams(ctx context.Context, limit, offset int) ([]*entity.EnvParam, error) {
	params, err := s.repo.ListAll(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list all environment parameters: %w", err)
	}

	// Decrypt values if they're encrypted (for listing, we might want to mask instead)
	for _, param := range params {
		if param.IsSecret {
			// For security, don't decrypt in list operations - just mark as encrypted
			param.Value = "[ENCRYPTED]"
		}
	}

	return params, nil
}

func (s *envParamService) CountEnvParams(ctx context.Context, environment string) (int, error) {
	count, err := s.repo.Count(ctx, environment)
	if err != nil {
		return 0, fmt.Errorf("failed to count environment parameters: %w", err)
	}
	return count, nil
}

func (s *envParamService) CountAllEnvParams(ctx context.Context) (int, error) {
	count, err := s.repo.CountAll(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count all environment parameters: %w", err)
	}
	return count, nil
}

func (s *envParamService) GetEnvironments(ctx context.Context) ([]string, error) {
	environments, err := s.repo.GetEnvironments(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get environments: %w", err)
	}
	return environments, nil
}

func (s *envParamService) BulkCreateEnvParams(ctx context.Context, params []*entity.EnvParam) error {
	for _, param := range params {
		if err := s.CreateEnvParam(ctx, param); err != nil {
			return fmt.Errorf("failed to create parameter %s:%s: %w", param.Environment, param.Key, err)
		}
	}
	return nil
}

func (s *envParamService) ValidateEnvParam(param *entity.EnvParam) error {
	if param == nil {
		return fmt.Errorf("parameter cannot be nil")
	}

	if param.Key == "" {
		return fmt.Errorf("parameter key cannot be empty")
	}

	if param.Environment == "" {
		return fmt.Errorf("parameter environment cannot be empty")
	}

	if param.Value == "" {
		return fmt.Errorf("parameter value cannot be empty")
	}

	// Validate parameter type-specific constraints
	switch param.ParamType {
	case entity.ParamTypeEmail:
		// Simple email validation
		if !strings.Contains(param.Value, "@") {
			return fmt.Errorf("invalid email format")
		}
	case entity.ParamTypeURL:
		// Simple URL validation
		if !strings.HasPrefix(param.Value, "http://") && !strings.HasPrefix(param.Value, "https://") {
			return fmt.Errorf("invalid URL format")
		}
	}

	return nil
}
