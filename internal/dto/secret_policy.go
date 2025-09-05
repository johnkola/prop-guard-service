package dto

import (
	"time"

	"PropGuard/internal/entity"

	"github.com/google/uuid"
)

// CreateSecretPolicyRequest represents a request to create a secret policy
type CreateSecretPolicyRequest struct {
	Name                 string            `json:"name" binding:"required,max=100"`
	Description          string            `json:"description,omitempty"`
	PathPattern          string            `json:"path_pattern" binding:"required"`
	RotationIntervalDays *int              `json:"rotation_interval_days,omitempty"`
	MaxAgeDays           *int              `json:"max_age_days,omitempty"`
	RequireApproval      bool              `json:"require_approval"`
	AutoRegenerate       bool              `json:"auto_regenerate"`
	SecretType           entity.SecretType `json:"secret_type" binding:"required"`
	RegenerationRules    string            `json:"regeneration_rules,omitempty"`
}

// UpdateSecretPolicyRequest represents a request to update a secret policy
type UpdateSecretPolicyRequest struct {
	Name                 string `json:"name,omitempty"`
	Description          string `json:"description,omitempty"`
	PathPattern          string `json:"path_pattern,omitempty"`
	RotationIntervalDays *int   `json:"rotation_interval_days,omitempty"`
	MaxAgeDays           *int   `json:"max_age_days,omitempty"`
	RequireApproval      *bool  `json:"require_approval,omitempty"`
	AutoRegenerate       *bool  `json:"auto_regenerate,omitempty"`
	RegenerationRules    string `json:"regeneration_rules,omitempty"`
	Enabled              *bool  `json:"enabled,omitempty"`
}

// SecretPolicyResponse represents a secret policy in responses
type SecretPolicyResponse struct {
	ID                   uuid.UUID         `json:"id"`
	Name                 string            `json:"name"`
	Description          string            `json:"description"`
	PathPattern          string            `json:"path_pattern"`
	RotationIntervalDays *int              `json:"rotation_interval_days,omitempty"`
	MaxAgeDays           *int              `json:"max_age_days,omitempty"`
	RequireApproval      bool              `json:"require_approval"`
	AutoRegenerate       bool              `json:"auto_regenerate"`
	SecretType           entity.SecretType `json:"secret_type"`
	RegenerationRules    string            `json:"regeneration_rules,omitempty"`
	Enabled              bool              `json:"enabled"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
	Version              int64             `json:"version"`
}

// ListSecretPoliciesResponse represents a paginated list of secret policies
type ListSecretPoliciesResponse struct {
	Policies   []SecretPolicyResponse `json:"policies"`
	Total      int64                  `json:"total"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"page_size"`
	TotalPages int                    `json:"total_pages"`
	HasNext    bool                   `json:"has_next"`
	HasPrev    bool                   `json:"has_prev"`
}

// GenerateSecretRequest represents a request to generate a secret based on policy
type GenerateSecretRequest struct {
	Path  string `json:"path" binding:"required"`
	Force bool   `json:"force"` // Force regeneration even if policy doesn't allow auto-generation
}

// GenerateSecretResponse represents the result of secret generation
type GenerateSecretResponse struct {
	Generated  map[string]interface{} `json:"generated"`
	PolicyID   string                 `json:"policy_id"`
	PolicyName string                 `json:"policy_name"`
	SecretType entity.SecretType      `json:"secret_type"`
	Message    string                 `json:"message,omitempty"`
}

// ValidateSecretRequest represents a request to validate a secret against policy
type ValidateSecretRequest struct {
	Path  string `json:"path" binding:"required"`
	Value string `json:"value" binding:"required"`
}

// ValidateSecretResponse represents the result of secret validation
type ValidateSecretResponse struct {
	Valid      bool              `json:"valid"`
	PolicyID   string            `json:"policy_id,omitempty"`
	PolicyName string            `json:"policy_name,omitempty"`
	SecretType entity.SecretType `json:"secret_type,omitempty"`
	Errors     []string          `json:"errors,omitempty"`
	Warnings   []string          `json:"warnings,omitempty"`
}

// SecretPolicyStatusResponse represents the status of policy enforcement
type SecretPolicyStatusResponse struct {
	TotalPolicies   int                       `json:"total_policies"`
	EnabledPolicies int                       `json:"enabled_policies"`
	PoliciesByType  map[entity.SecretType]int `json:"policies_by_type"`
	ExpiredSecrets  int                       `json:"expired_secrets"`
	RotationNeeded  int                       `json:"rotation_needed"`
	LastUpdated     time.Time                 `json:"last_updated"`
}

// SecretTypeInfo provides information about supported secret types
type SecretTypeInfo struct {
	Type        entity.SecretType `json:"type"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Examples    []string          `json:"examples,omitempty"`
	Rules       []string          `json:"rules,omitempty"`
}

// GetSecretTypesResponse lists all supported secret types
type GetSecretTypesResponse struct {
	SecretTypes []SecretTypeInfo `json:"secret_types"`
}

// SecretGenerationPreviewRequest represents a request to preview secret generation
type SecretGenerationPreviewRequest struct {
	SecretType        entity.SecretType `json:"secret_type" binding:"required"`
	RegenerationRules string            `json:"regeneration_rules,omitempty"`
}

// SecretGenerationPreviewResponse represents a preview of what would be generated
type SecretGenerationPreviewResponse struct {
	Preview    map[string]interface{} `json:"preview"`
	Rules      map[string]interface{} `json:"rules"`
	SecretType entity.SecretType      `json:"secret_type"`
	Message    string                 `json:"message,omitempty"`
}
