package dto

import (
	"time"

	"PropGuard/internal/entity"

	"github.com/google/uuid"
)

type CreateEnvParamRequest struct {
	Key              string              `json:"key" binding:"required,max=200"`
	Value            string              `json:"value" binding:"required"`
	Description      string              `json:"description"`
	ParamType        entity.ParamType    `json:"paramType" binding:"required"`
	ParamSubtype     entity.ParamSubtype `json:"paramSubtype" binding:"required"`
	Environment      string              `json:"environment" binding:"required,max=100"`
	ApplicationName  string              `json:"applicationName"`
	NetworkNamespace string              `json:"networkNamespace"`
	IsRequired       bool                `json:"isRequired"`
	DefaultValue     string              `json:"defaultValue"`
	ValidationRegex  string              `json:"validationRegex"`
	TTLSeconds       *int64              `json:"ttlSeconds"`
}

type UpdateEnvParamRequest struct {
	Value           string `json:"value"`
	Description     string `json:"description"`
	IsRequired      bool   `json:"isRequired"`
	DefaultValue    string `json:"defaultValue"`
	ValidationRegex string `json:"validationRegex"`
	TTLSeconds      *int64 `json:"ttlSeconds"`
}

type EnvParamResponse struct {
	ID               uuid.UUID           `json:"id"`
	Key              string              `json:"key"`
	Value            string              `json:"value"` // Will be masked if secret
	Description      string              `json:"description"`
	ParamType        entity.ParamType    `json:"paramType"`
	ParamSubtype     entity.ParamSubtype `json:"paramSubtype"`
	Environment      string              `json:"environment"`
	ApplicationName  string              `json:"applicationName"`
	NetworkNamespace string              `json:"networkNamespace"`
	IsSecret         bool                `json:"isSecret"`
	IsRequired       bool                `json:"isRequired"`
	DefaultValue     string              `json:"defaultValue"`
	ValidationRegex  string              `json:"validationRegex"`
	CreatedBy        uuid.UUID           `json:"createdBy"`
	UpdatedBy        uuid.UUID           `json:"updatedBy"`
	CreatedAt        time.Time           `json:"createdAt"`
	UpdatedAt        time.Time           `json:"updatedAt"`
	Version          int64               `json:"version"`
	TTLSeconds       *int64              `json:"ttlSeconds"`
	ExpiresAt        *time.Time          `json:"expiresAt"`
	LastRotatedAt    *time.Time          `json:"lastRotatedAt"`
}

type EnvParamListResponse struct {
	Params     []EnvParamResponse `json:"params"`
	TotalCount int                `json:"totalCount"`
	Page       int                `json:"page"`
	PageSize   int                `json:"pageSize"`
}

type CreateEnvParamPolicyRequest struct {
	Name                 string              `json:"name" binding:"required"`
	Description          string              `json:"description"`
	Environment          string              `json:"environment" binding:"required"`
	ApplicationPattern   string              `json:"applicationPattern"`
	KeyPattern           string              `json:"keyPattern" binding:"required"`
	ParamType            entity.ParamType    `json:"paramType"`
	ParamSubtype         entity.ParamSubtype `json:"paramSubtype"`
	RotationIntervalDays *int                `json:"rotationIntervalDays"`
	MaxAgeDays           *int                `json:"maxAgeDays"`
	AutoRotate           bool                `json:"autoRotate"`
	RequireApproval      bool                `json:"requireApproval"`
	ValidationRegex      string              `json:"validationRegex"`
	AllowedValues        []string            `json:"allowedValues"`
	MinLength            *int                `json:"minLength"`
	MaxLength            *int                `json:"maxLength"`
	IsRequired           bool                `json:"isRequired"`
	EncryptionRequired   bool                `json:"encryptionRequired"`
	AuditChanges         bool                `json:"auditChanges"`
}

type EnvParamPolicyResponse struct {
	ID                   uuid.UUID           `json:"id"`
	Name                 string              `json:"name"`
	Description          string              `json:"description"`
	Environment          string              `json:"environment"`
	ApplicationPattern   string              `json:"applicationPattern"`
	KeyPattern           string              `json:"keyPattern"`
	ParamType            entity.ParamType    `json:"paramType"`
	ParamSubtype         entity.ParamSubtype `json:"paramSubtype"`
	RotationIntervalDays *int                `json:"rotationIntervalDays"`
	MaxAgeDays           *int                `json:"maxAgeDays"`
	AutoRotate           bool                `json:"autoRotate"`
	RequireApproval      bool                `json:"requireApproval"`
	ValidationRegex      string              `json:"validationRegex"`
	AllowedValues        []string            `json:"allowedValues"`
	MinLength            *int                `json:"minLength"`
	MaxLength            *int                `json:"maxLength"`
	IsRequired           bool                `json:"isRequired"`
	EncryptionRequired   bool                `json:"encryptionRequired"`
	AuditChanges         bool                `json:"auditChanges"`
	Enabled              bool                `json:"enabled"`
	CreatedAt            time.Time           `json:"createdAt"`
	UpdatedAt            time.Time           `json:"updatedAt"`
	Version              int64               `json:"version"`
}

type RotateEnvParamRequest struct {
	NewValue string `json:"newValue" binding:"required"`
	Reason   string `json:"reason"`
}

type PaginatedEnvParamsResponse struct {
	Data     []*entity.EnvParam `json:"data"`
	Total    int                `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"pageSize"`
	HasNext  bool               `json:"hasNext"`
	HasPrev  bool               `json:"hasPrev"`
}

// Helper functions to convert between entity and DTO

func (r *CreateEnvParamRequest) ToEntity(createdBy uuid.UUID) *entity.EnvParam {
	param := entity.NewEnvParam(r.Key, r.Value, r.Environment, r.ParamType, r.ParamSubtype, createdBy)
	param.Description = r.Description
	param.ApplicationName = r.ApplicationName
	param.NetworkNamespace = r.NetworkNamespace
	param.IsRequired = r.IsRequired
	param.DefaultValue = r.DefaultValue
	param.ValidationRegex = r.ValidationRegex

	if r.TTLSeconds != nil {
		param.SetTTL(*r.TTLSeconds)
	}

	return param
}

func EnvParamToResponse(param *entity.EnvParam) *EnvParamResponse {
	return &EnvParamResponse{
		ID:               param.ID,
		Key:              param.Key,
		Value:            param.GetDisplayValue(), // Masks secrets
		Description:      param.Description,
		ParamType:        param.ParamType,
		ParamSubtype:     param.ParamSubtype,
		Environment:      param.Environment,
		ApplicationName:  param.ApplicationName,
		NetworkNamespace: param.NetworkNamespace,
		IsSecret:         param.IsSecret,
		IsRequired:       param.IsRequired,
		DefaultValue:     param.DefaultValue,
		ValidationRegex:  param.ValidationRegex,
		CreatedBy:        param.CreatedBy,
		UpdatedBy:        param.UpdatedBy,
		CreatedAt:        param.CreatedAt,
		UpdatedAt:        param.UpdatedAt,
		Version:          param.Version,
		TTLSeconds:       param.TTLSeconds,
		ExpiresAt:        param.ExpiresAt,
		LastRotatedAt:    param.LastRotatedAt,
	}
}
