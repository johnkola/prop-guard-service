package entity

import (
	"time"

	"github.com/google/uuid"
)

type Secret struct {
	ID               uuid.UUID         `bson:"_id,omitempty" json:"id"`
	Path             string            `bson:"path" json:"path" binding:"required,max=500"`
	NetworkNamespace string            `bson:"networkNamespace" json:"networkNamespace" binding:"required,max=100"`
	NetworkSegment   string            `bson:"networkSegment" json:"networkSegment"`
	EncryptedData    string            `bson:"encryptedData" json:"-"`
	DataHash         string            `bson:"dataHash" json:"dataHash"`
	EncryptionKeyID  string            `bson:"encryptionKeyId" json:"encryptionKeyId"`
	CreatedBy        uuid.UUID         `bson:"createdBy" json:"createdBy" ref:"vault_users"`
	UpdatedBy        uuid.UUID         `bson:"updatedBy" json:"updatedBy" ref:"vault_users"`
	CreatedAt        time.Time         `bson:"createdAt" json:"createdAt"`
	UpdatedAt        time.Time         `bson:"updatedAt" json:"updatedAt"`
	Version          int64             `bson:"version" json:"version"`
	TTLSeconds       *int64            `bson:"ttlSeconds,omitempty" json:"ttlSeconds,omitempty"`
	ExpiresAt        *time.Time        `bson:"expiresAt,omitempty" json:"expiresAt,omitempty"`
	Metadata         map[string]string `bson:"metadata,omitempty" json:"metadata,omitempty"`
}

func NewSecret(path, encryptedData, networkNamespace string, createdBy uuid.UUID) *Secret {
	return &Secret{
		ID:               GenerateUUIDv7(),
		Path:             path,
		EncryptedData:    encryptedData,
		CreatedBy:        createdBy,
		UpdatedBy:        createdBy,
		NetworkNamespace: networkNamespace,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		Version:          1,
	}
}

func (s *Secret) SetTTL(ttlSeconds int64) {
	s.TTLSeconds = &ttlSeconds
	if ttlSeconds > 0 {
		expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
		s.ExpiresAt = &expiresAt
	}
}

func (s *Secret) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}
