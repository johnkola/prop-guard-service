package entity

import (
	"time"

	"github.com/google/uuid"
)

type RotationStatus string

const (
	RotationStatusInitiated  RotationStatus = "INITIATED"
	RotationStatusInProgress RotationStatus = "IN_PROGRESS"
	RotationStatusCompleted  RotationStatus = "COMPLETED"
	RotationStatusFailed     RotationStatus = "FAILED"
	RotationStatusRolledBack RotationStatus = "ROLLED_BACK"
)

type SecretRotationHistory struct {
	ID                uuid.UUID      `bson:"_id,omitempty" json:"id"`
	SecretPath        string         `bson:"secretPath" json:"secretPath"`
	PolicyName        string         `bson:"policyName" json:"policyName"`
	RotationReason    string         `bson:"rotationReason" json:"rotationReason"`
	Status            RotationStatus `bson:"status" json:"status"`
	OldVersion        *int64         `bson:"oldVersion,omitempty" json:"oldVersion,omitempty"`
	NewVersion        *int64         `bson:"newVersion,omitempty" json:"newVersion,omitempty"`
	InitiatedBy       uuid.UUID      `bson:"initiatedBy" json:"initiatedBy" ref:"vault_users"`
	ErrorMessage      string         `bson:"errorMessage,omitempty" json:"errorMessage,omitempty"`
	RotationTimestamp time.Time      `bson:"rotationTimestamp" json:"rotationTimestamp"`
	CompletedAt       *time.Time     `bson:"completedAt,omitempty" json:"completedAt,omitempty"`
}

func NewSecretRotationHistory(secretPath, policyName, rotationReason string, initiatedBy uuid.UUID) *SecretRotationHistory {
	return &SecretRotationHistory{
		ID:                GenerateUUIDv7(),
		SecretPath:        secretPath,
		PolicyName:        policyName,
		RotationReason:    rotationReason,
		InitiatedBy:       initiatedBy,
		Status:            RotationStatusInitiated,
		RotationTimestamp: time.Now(),
	}
}

func (r *SecretRotationHistory) MarkInProgress() {
	r.Status = RotationStatusInProgress
}

func (r *SecretRotationHistory) MarkCompleted(newVersion int64) {
	r.Status = RotationStatusCompleted
	r.NewVersion = &newVersion
	now := time.Now()
	r.CompletedAt = &now
}

func (r *SecretRotationHistory) MarkFailed(errorMsg string) {
	r.Status = RotationStatusFailed
	r.ErrorMessage = errorMsg
	now := time.Now()
	r.CompletedAt = &now
}

func (r *SecretRotationHistory) MarkRolledBack(errorMsg string) {
	r.Status = RotationStatusRolledBack
	r.ErrorMessage = errorMsg
	now := time.Now()
	r.CompletedAt = &now
}
