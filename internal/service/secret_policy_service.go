package service

import (
	"context"
	"fmt"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"

	"github.com/google/uuid"
)

// SecretPolicyService handles secret policy management and enforcement
type SecretPolicyService interface {
	// Policy CRUD operations
	CreatePolicy(ctx context.Context, req *dto.CreateSecretPolicyRequest, createdBy string) (*dto.SecretPolicyResponse, error)
	GetPolicy(ctx context.Context, id uuid.UUID) (*dto.SecretPolicyResponse, error)
	UpdatePolicy(ctx context.Context, id uuid.UUID, req *dto.UpdateSecretPolicyRequest, updatedBy string) (*dto.SecretPolicyResponse, error)
	DeletePolicy(ctx context.Context, id uuid.UUID, deletedBy string) error
	ListPolicies(ctx context.Context, page, pageSize int) (*dto.ListSecretPoliciesResponse, error)

	// Policy enforcement
	GetPolicyForPath(ctx context.Context, path string) (*entity.SecretPolicy, error)
	ValidateSecretAgainstPolicy(ctx context.Context, path string, secretValue string) error
	EnforceSecretPolicy(ctx context.Context, path string, secret *entity.Secret) error

	// Secret generation based on policy
	GenerateSecretForPath(ctx context.Context, path string) (map[string]interface{}, error)

	// Policy analysis
	GetPoliciesByType(ctx context.Context, secretType entity.SecretType) ([]*entity.SecretPolicy, error)
	GetExpiredSecrets(ctx context.Context) ([]*entity.Secret, error)
	GetSecretsNeedingRotation(ctx context.Context) ([]*entity.Secret, error)
}

type secretPolicyService struct {
	policyRepo    *repository.BadgerSecretPolicyRepository
	secretRepo    *repository.BadgerSecretRepository
	generationSvc SecretGenerationService
	auditService  AuditService
}

func NewSecretPolicyService(
	policyRepo *repository.BadgerSecretPolicyRepository,
	secretRepo *repository.BadgerSecretRepository,
	generationSvc SecretGenerationService,
	auditService AuditService,
) SecretPolicyService {
	return &secretPolicyService{
		policyRepo:    policyRepo,
		secretRepo:    secretRepo,
		generationSvc: generationSvc,
		auditService:  auditService,
	}
}

func (s *secretPolicyService) CreatePolicy(ctx context.Context, req *dto.CreateSecretPolicyRequest, createdBy string) (*dto.SecretPolicyResponse, error) {
	// Validate request
	if err := s.validateCreateRequest(req); err != nil {
		return nil, err
	}

	// Create policy entity
	policy := entity.NewSecretPolicy(req.Name, req.PathPattern, req.SecretType)
	policy.Description = req.Description
	if req.RotationIntervalDays != nil {
		policy.RotationIntervalDays = req.RotationIntervalDays
	}
	if req.MaxAgeDays != nil {
		policy.MaxAgeDays = req.MaxAgeDays
	}
	policy.RequireApproval = req.RequireApproval
	policy.AutoRegenerate = req.AutoRegenerate
	policy.RegenerationRules = req.RegenerationRules

	// Create in repository
	if err := s.policyRepo.Create(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create secret policy: %w", err)
	}

	// Audit log
	s.auditService.LogAction(ctx, createdBy, "SECRET_POLICY_CREATE", policy.ID.String(), true,
		fmt.Sprintf("Created secret policy: %s", policy.Name))

	// Convert to response
	response := s.policyToResponse(policy)
	return &response, nil
}

func (s *secretPolicyService) GetPolicy(ctx context.Context, id uuid.UUID) (*dto.SecretPolicyResponse, error) {
	policy, err := s.policyRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret policy: %w", err)
	}

	response := s.policyToResponse(policy)
	return &response, nil
}

func (s *secretPolicyService) UpdatePolicy(ctx context.Context, id uuid.UUID, req *dto.UpdateSecretPolicyRequest, updatedBy string) (*dto.SecretPolicyResponse, error) {
	// Get existing policy
	policy, err := s.policyRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret policy: %w", err)
	}

	// Update fields
	if req.Name != "" {
		policy.Name = req.Name
	}
	if req.Description != "" {
		policy.Description = req.Description
	}
	if req.PathPattern != "" {
		policy.PathPattern = req.PathPattern
	}
	if req.RotationIntervalDays != nil {
		policy.RotationIntervalDays = req.RotationIntervalDays
	}
	if req.MaxAgeDays != nil {
		policy.MaxAgeDays = req.MaxAgeDays
	}
	if req.RequireApproval != nil {
		policy.RequireApproval = *req.RequireApproval
	}
	if req.AutoRegenerate != nil {
		policy.AutoRegenerate = *req.AutoRegenerate
	}
	if req.RegenerationRules != "" {
		policy.RegenerationRules = req.RegenerationRules
	}
	if req.Enabled != nil {
		policy.Enabled = *req.Enabled
	}

	// Update in repository
	if err := s.policyRepo.Update(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to update secret policy: %w", err)
	}

	// Audit log
	s.auditService.LogAction(ctx, updatedBy, "SECRET_POLICY_UPDATE", policy.ID.String(), true,
		fmt.Sprintf("Updated secret policy: %s", policy.Name))

	response := s.policyToResponse(policy)
	return &response, nil
}

func (s *secretPolicyService) DeletePolicy(ctx context.Context, id uuid.UUID, deletedBy string) error {
	// Check if policy exists
	policy, err := s.policyRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get secret policy: %w", err)
	}

	// Delete from repository
	if err := s.policyRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete secret policy: %w", err)
	}

	// Audit log
	s.auditService.LogAction(ctx, deletedBy, "SECRET_POLICY_DELETE", id.String(), true,
		fmt.Sprintf("Deleted secret policy: %s", policy.Name))

	return nil
}

func (s *secretPolicyService) ListPolicies(ctx context.Context, page, pageSize int) (*dto.ListSecretPoliciesResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	policies, err := s.policyRepo.List(ctx, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list secret policies: %w", err)
	}

	total, err := s.policyRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count secret policies: %w", err)
	}

	var policyResponses []dto.SecretPolicyResponse
	for _, policy := range policies {
		policyResponses = append(policyResponses, s.policyToResponse(policy))
	}

	totalPages := (int(total) + pageSize - 1) / pageSize

	return &dto.ListSecretPoliciesResponse{
		Policies:   policyResponses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}, nil
}

func (s *secretPolicyService) GetPolicyForPath(ctx context.Context, path string) (*entity.SecretPolicy, error) {
	policy, err := s.policyRepo.GetPolicyByPath(ctx, path)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

func (s *secretPolicyService) ValidateSecretAgainstPolicy(ctx context.Context, path string, secretValue string) error {
	policy, err := s.GetPolicyForPath(ctx, path)
	if err != nil {
		// If no policy found, allow the secret (no policy enforcement)
		return nil
	}

	return s.generationSvc.ValidateSecretFormat(policy, secretValue)
}

func (s *secretPolicyService) EnforceSecretPolicy(ctx context.Context, path string, secret *entity.Secret) error {
	policy, err := s.GetPolicyForPath(ctx, path)
	if err != nil {
		// If no policy found, no enforcement needed
		return nil
	}

	// Set secret type based on policy
	secret.Metadata = make(map[string]string)
	secret.Metadata["secret_type"] = string(policy.SecretType)
	secret.Metadata["policy_id"] = policy.ID.String()
	secret.Metadata["policy_name"] = policy.Name

	// Store policy information in metadata (auto-generation would be handled at a higher level)
	// The secret value itself is already encrypted and stored in EncryptedData

	return nil
}

func (s *secretPolicyService) GenerateSecretForPath(ctx context.Context, path string) (map[string]interface{}, error) {
	policy, err := s.GetPolicyForPath(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("no policy found for path %s: %w", path, err)
	}

	generated, err := s.generationSvc.GenerateSecret(policy, policy.RegenerationRules)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Add policy information to result
	generated["policy_id"] = policy.ID.String()
	generated["policy_name"] = policy.Name
	generated["secret_type"] = string(policy.SecretType)

	return generated, nil
}

func (s *secretPolicyService) GetPoliciesByType(ctx context.Context, secretType entity.SecretType) ([]*entity.SecretPolicy, error) {
	return s.policyRepo.GetPoliciesByType(ctx, secretType)
}

func (s *secretPolicyService) GetExpiredSecrets(ctx context.Context) ([]*entity.Secret, error) {
	// Get all enabled policies
	enabledPolicies, err := s.policyRepo.GetEnabledPolicies(ctx)
	if err != nil {
		return nil, err
	}

	var expiredSecrets []*entity.Secret

	for _, policy := range enabledPolicies {
		if policy.MaxAgeDays == nil || *policy.MaxAgeDays <= 0 {
			continue
		}

		// This is a simplified implementation
		// In a real system, you'd query secrets by path pattern and check expiration
		// For now, we'll return an empty slice as the secret repository doesn't have
		// the necessary query methods
	}

	return expiredSecrets, nil
}

func (s *secretPolicyService) GetSecretsNeedingRotation(ctx context.Context) ([]*entity.Secret, error) {
	// Similar to GetExpiredSecrets, this would need additional repository methods
	// to query secrets by path patterns and check rotation schedules
	return []*entity.Secret{}, nil
}

// Helper methods

func (s *secretPolicyService) validateCreateRequest(req *dto.CreateSecretPolicyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if req.PathPattern == "" {
		return fmt.Errorf("path pattern is required")
	}

	// Validate regeneration rules if provided
	if req.RegenerationRules != "" {
		_, err := s.generationSvc.ParseGenerationRules(req.RegenerationRules)
		if err != nil {
			return fmt.Errorf("invalid regeneration rules: %w", err)
		}
	}

	return nil
}

func (s *secretPolicyService) policyToResponse(policy *entity.SecretPolicy) dto.SecretPolicyResponse {
	return dto.SecretPolicyResponse{
		ID:                   policy.ID,
		Name:                 policy.Name,
		Description:          policy.Description,
		PathPattern:          policy.PathPattern,
		RotationIntervalDays: policy.RotationIntervalDays,
		MaxAgeDays:           policy.MaxAgeDays,
		RequireApproval:      policy.RequireApproval,
		AutoRegenerate:       policy.AutoRegenerate,
		SecretType:           policy.SecretType,
		RegenerationRules:    policy.RegenerationRules,
		Enabled:              policy.Enabled,
		CreatedAt:            policy.CreatedAt,
		UpdatedAt:            policy.UpdatedAt,
		Version:              policy.Version,
	}
}

func (s *secretPolicyService) extractPrimaryValue(generated map[string]interface{}, secretType entity.SecretType) string {
	key := s.getPrimaryValueKey(secretType)
	if value, ok := generated[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return ""
}

func (s *secretPolicyService) getPrimaryValueKey(secretType entity.SecretType) string {
	switch secretType {
	case entity.SecretTypePassword:
		return "password"
	case entity.SecretTypeAPIKey:
		return "api_key"
	case entity.SecretTypeJWTSecret:
		return "secret"
	case entity.SecretTypeAESKey, entity.SecretTypeHMACKey:
		return "key"
	default:
		return "value"
	}
}
