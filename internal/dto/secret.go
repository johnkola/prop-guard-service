package dto

import (
	"time"

	"github.com/google/uuid"
)

type SecretRequest struct {
	Data       map[string]interface{} `json:"data" binding:"required"`
	TTLSeconds *int64                 `json:"ttlSeconds,omitempty"`
}

type SecretResponse struct {
	Path      string                 `json:"path"`
	Data      map[string]interface{} `json:"data"`
	CreatedAt time.Time              `json:"createdAt"`
	UpdatedAt time.Time              `json:"updatedAt"`
	CreatedBy uuid.UUID              `json:"createdBy"`
	UpdatedBy uuid.UUID              `json:"updatedBy"`
	Version   int64                  `json:"version"`
	ExpiresAt *time.Time             `json:"expiresAt,omitempty"`
}
