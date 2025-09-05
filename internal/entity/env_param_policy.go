package entity

import (
	"time"

	"github.com/google/uuid"
)

type EnvParamPolicy struct {
	ID                 uuid.UUID    `bson:"_id,omitempty" json:"id"`
	Name               string       `bson:"name" json:"name" binding:"required"`
	Description        string       `bson:"description" json:"description"`
	Environment        string       `bson:"environment" json:"environment" binding:"required"`
	ApplicationPattern string       `bson:"applicationPattern" json:"applicationPattern"`
	KeyPattern         string       `bson:"keyPattern" json:"keyPattern" binding:"required"`
	ParamType          ParamType    `bson:"paramType,omitempty" json:"paramType,omitempty"`
	ParamSubtype       ParamSubtype `bson:"paramSubtype,omitempty" json:"paramSubtype,omitempty"`

	// Rotation and lifecycle policies
	RotationIntervalDays *int `bson:"rotationIntervalDays,omitempty" json:"rotationIntervalDays,omitempty"`
	MaxAgeDays           *int `bson:"maxAgeDays,omitempty" json:"maxAgeDays,omitempty"`
	AutoRotate           bool `bson:"autoRotate" json:"autoRotate"`
	RequireApproval      bool `bson:"requireApproval" json:"requireApproval"`

	// Validation rules
	ValidationRegex string   `bson:"validationRegex,omitempty" json:"validationRegex,omitempty"`
	AllowedValues   []string `bson:"allowedValues,omitempty" json:"allowedValues,omitempty"`
	MinLength       *int     `bson:"minLength,omitempty" json:"minLength,omitempty"`
	MaxLength       *int     `bson:"maxLength,omitempty" json:"maxLength,omitempty"`
	IsRequired      bool     `bson:"isRequired" json:"isRequired"`

	// Security policies
	EncryptionRequired bool `bson:"encryptionRequired" json:"encryptionRequired"`
	AuditChanges       bool `bson:"auditChanges" json:"auditChanges"`

	Enabled   bool      `bson:"enabled" json:"enabled"`
	CreatedAt time.Time `bson:"createdAt" json:"createdAt"`
	UpdatedAt time.Time `bson:"updatedAt" json:"updatedAt"`
	Version   int64     `bson:"version" json:"version"`
}

func NewEnvParamPolicy(name, environment, keyPattern string, paramType ParamType, paramSubtype ParamSubtype) *EnvParamPolicy {
	return &EnvParamPolicy{
		ID:                 GenerateUUIDv7(),
		Name:               name,
		Environment:        environment,
		KeyPattern:         keyPattern,
		ParamType:          paramType,
		ParamSubtype:       paramSubtype,
		IsRequired:         true,
		EncryptionRequired: paramSubtype != ParamSubtypeGeneric,
		AuditChanges:       paramSubtype != ParamSubtypeGeneric,
		RequireApproval:    paramSubtype != ParamSubtypeGeneric,
		AutoRotate:         false, // Default to manual rotation
		Enabled:            true,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Version:            1,
	}
}

func (p *EnvParamPolicy) NeedsRotation(lastRotated time.Time) bool {
	if p.RotationIntervalDays == nil || *p.RotationIntervalDays <= 0 {
		return false
	}

	rotationDuration := time.Duration(*p.RotationIntervalDays) * 24 * time.Hour
	return time.Since(lastRotated) > rotationDuration
}

func (p *EnvParamPolicy) IsExpired(createdAt time.Time) bool {
	if p.MaxAgeDays == nil || *p.MaxAgeDays <= 0 {
		return false
	}

	maxAgeDuration := time.Duration(*p.MaxAgeDays) * 24 * time.Hour
	return time.Since(createdAt) > maxAgeDuration
}

func (p *EnvParamPolicy) IsSecretParam() bool {
	return p.ParamSubtype != ParamSubtypeGeneric
}

func (p *EnvParamPolicy) ShouldEncrypt() bool {
	return p.EncryptionRequired || p.IsSecretParam()
}

// Helper functions for common policy types

func NewSecretEnvParamPolicy(name, environment, keyPattern string, paramSubtype ParamSubtype) *EnvParamPolicy {
	policy := NewEnvParamPolicy(name, environment, keyPattern, ParamTypeString, paramSubtype)
	policy.RequireApproval = true
	policy.AuditChanges = true
	policy.EncryptionRequired = true

	// Set default rotation based on subtype
	switch paramSubtype {
	case ParamSubtypePassword, ParamSubtypeAPIKey:
		rotationDays := 90
		policy.RotationIntervalDays = &rotationDays
	case ParamSubtypeJWTSecret, ParamSubtypeEncryption:
		rotationDays := 30
		policy.RotationIntervalDays = &rotationDays
	case ParamSubtypeDBString:
		rotationDays := 180
		policy.RotationIntervalDays = &rotationDays
	}

	return policy
}

func NewGenericEnvParamPolicy(name, environment, keyPattern string, paramType ParamType) *EnvParamPolicy {
	policy := NewEnvParamPolicy(name, environment, keyPattern, paramType, ParamSubtypeGeneric)
	policy.RequireApproval = false
	policy.AuditChanges = false
	policy.EncryptionRequired = false
	return policy
}
