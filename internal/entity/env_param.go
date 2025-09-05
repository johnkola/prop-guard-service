package entity

import (
	"time"

	"github.com/google/uuid"
)

type ParamType string
type ParamSubtype string

const (
	ParamTypeString  ParamType = "STRING"
	ParamTypeNumber  ParamType = "NUMBER"
	ParamTypeBoolean ParamType = "BOOLEAN"
	ParamTypeJSON    ParamType = "JSON"
	ParamTypeURL     ParamType = "URL"
	ParamTypeEmail   ParamType = "EMAIL"
)

const (
	ParamSubtypeGeneric    ParamSubtype = "GENERIC"
	ParamSubtypeSecret     ParamSubtype = "SECRET"
	ParamSubtypePassword   ParamSubtype = "PASSWORD"
	ParamSubtypeAPIKey     ParamSubtype = "API_KEY"
	ParamSubtypeDBString   ParamSubtype = "DATABASE_URL"
	ParamSubtypeJWTSecret  ParamSubtype = "JWT_SECRET"
	ParamSubtypeEncryption ParamSubtype = "ENCRYPTION_KEY"
)

type EnvParam struct {
	ID               uuid.UUID    `bson:"_id,omitempty" json:"id"`
	Key              string       `bson:"key" json:"key" binding:"required,max=200"`
	Value            string       `bson:"value" json:"value,omitempty"`
	EncryptedValue   string       `bson:"encryptedValue" json:"-"`
	Description      string       `bson:"description" json:"description"`
	ParamType        ParamType    `bson:"paramType" json:"paramType"`
	ParamSubtype     ParamSubtype `bson:"paramSubtype" json:"paramSubtype"`
	Environment      string       `bson:"environment" json:"environment" binding:"required"`
	ApplicationName  string       `bson:"applicationName" json:"applicationName"`
	NetworkNamespace string       `bson:"networkNamespace" json:"networkNamespace"`
	IsSecret         bool         `bson:"isSecret" json:"isSecret"`
	IsRequired       bool         `bson:"isRequired" json:"isRequired"`
	DefaultValue     string       `bson:"defaultValue,omitempty" json:"defaultValue,omitempty"`
	ValidationRegex  string       `bson:"validationRegex,omitempty" json:"validationRegex,omitempty"`
	CreatedBy        uuid.UUID    `bson:"createdBy" json:"createdBy" ref:"vault_users"`
	UpdatedBy        uuid.UUID    `bson:"updatedBy" json:"updatedBy" ref:"vault_users"`
	CreatedAt        time.Time    `bson:"createdAt" json:"createdAt"`
	UpdatedAt        time.Time    `bson:"updatedAt" json:"updatedAt"`
	Version          int64        `bson:"version" json:"version"`
	TTLSeconds       *int64       `bson:"ttlSeconds,omitempty" json:"ttlSeconds,omitempty"`
	ExpiresAt        *time.Time   `bson:"expiresAt,omitempty" json:"expiresAt,omitempty"`
	LastRotatedAt    *time.Time   `bson:"lastRotatedAt,omitempty" json:"lastRotatedAt,omitempty"`
}

func NewEnvParam(key, value, environment string, paramType ParamType, paramSubtype ParamSubtype, createdBy uuid.UUID) *EnvParam {
	isSecret := paramSubtype != ParamSubtypeGeneric

	return &EnvParam{
		ID:           GenerateUUIDv7(),
		Key:          key,
		Value:        value,
		ParamType:    paramType,
		ParamSubtype: paramSubtype,
		Environment:  environment,
		IsSecret:     isSecret,
		IsRequired:   true,
		CreatedBy:    createdBy,
		UpdatedBy:    createdBy,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Version:      1,
	}
}

func (e *EnvParam) SetTTL(ttlSeconds int64) {
	e.TTLSeconds = &ttlSeconds
	if ttlSeconds > 0 {
		expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
		e.ExpiresAt = &expiresAt
	}
}

func (e *EnvParam) IsExpired() bool {
	if e.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*e.ExpiresAt)
}

func (e *EnvParam) NeedsEncryption() bool {
	return e.IsSecret || e.ParamSubtype != ParamSubtypeGeneric
}

func (e *EnvParam) GetDisplayValue() string {
	if e.IsSecret {
		return "***HIDDEN***"
	}
	return e.Value
}

func (e *EnvParam) MarkRotated() {
	now := time.Now()
	e.LastRotatedAt = &now
	e.UpdatedAt = now
	e.Version++
}
