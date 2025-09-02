package entity

import (
	"time"

	"github.com/google/uuid"
)

type SecretType string

const (
	SecretTypeGeneric          SecretType = "GENERIC"
	SecretTypePassword         SecretType = "PASSWORD"
	SecretTypeAPIKey           SecretType = "API_KEY"
	SecretTypeJWTSecret        SecretType = "JWT_SECRET"
	SecretTypeRSAKeyPair       SecretType = "RSA_KEY_PAIR"
	SecretTypeECKeyPair        SecretType = "EC_KEY_PAIR"
	SecretTypeAESKey           SecretType = "AES_KEY"
	SecretTypeHMACKey          SecretType = "HMAC_KEY"
	SecretTypeDatabaseCred     SecretType = "DATABASE_CREDENTIAL"
	SecretTypeTLSCertificate   SecretType = "TLS_CERTIFICATE"
	SecretTypeSSHKey           SecretType = "SSH_KEY"
	SecretTypeOAuthCredentials SecretType = "OAUTH_CREDENTIALS"
)

type SecretPolicy struct {
	ID                   uuid.UUID  `bson:"_id,omitempty" json:"id"`
	Name                 string     `bson:"name" json:"name" binding:"required"`
	Description          string     `bson:"description" json:"description"`
	PathPattern          string     `bson:"pathPattern" json:"pathPattern" binding:"required"`
	RotationIntervalDays *int       `bson:"rotationIntervalDays,omitempty" json:"rotationIntervalDays,omitempty"`
	MaxAgeDays           *int       `bson:"maxAgeDays,omitempty" json:"maxAgeDays,omitempty"`
	RequireApproval      bool       `bson:"requireApproval" json:"requireApproval"`
	AutoRegenerate       bool       `bson:"autoRegenerate" json:"autoRegenerate"`
	SecretType           SecretType `bson:"secretType" json:"secretType"`
	RegenerationRules    string     `bson:"regenerationRules" json:"regenerationRules"`
	Enabled              bool       `bson:"enabled" json:"enabled"`
	CreatedAt            time.Time  `bson:"createdAt" json:"createdAt"`
	UpdatedAt            time.Time  `bson:"updatedAt" json:"updatedAt"`
	Version              int64      `bson:"version" json:"version"`
}

func NewSecretPolicy(name, pathPattern string, secretType SecretType) *SecretPolicy {
	return &SecretPolicy{
		ID:          GenerateUUIDv7(),
		Name:        name,
		PathPattern: pathPattern,
		SecretType:  secretType,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func (p *SecretPolicy) NeedsRotation(lastRotated time.Time) bool {
	if p.RotationIntervalDays == nil || *p.RotationIntervalDays <= 0 {
		return false
	}

	rotationDuration := time.Duration(*p.RotationIntervalDays) * 24 * time.Hour
	return time.Since(lastRotated) > rotationDuration
}

func (p *SecretPolicy) IsExpired(createdAt time.Time) bool {
	if p.MaxAgeDays == nil || *p.MaxAgeDays <= 0 {
		return false
	}

	maxAgeDuration := time.Duration(*p.MaxAgeDays) * 24 * time.Hour
	return time.Since(createdAt) > maxAgeDuration
}
