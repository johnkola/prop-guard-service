package entity

import (
	"time"

	"github.com/google/uuid"
)

type AuditLog struct {
	ID           uuid.UUID `bson:"_id,omitempty" json:"id"`
	Username     string    `bson:"username" json:"username"`
	Action       string    `bson:"action" json:"action"`
	SecretPath   string    `bson:"secretPath" json:"secretPath"`
	ClientIP     string    `bson:"clientIp" json:"clientIp"`
	UserAgent    string    `bson:"userAgent" json:"userAgent"`
	Details      string    `bson:"details" json:"details"`
	Success      bool      `bson:"success" json:"success"`
	ErrorMessage string    `bson:"errorMessage,omitempty" json:"errorMessage,omitempty"`
	Timestamp    time.Time `bson:"timestamp" json:"timestamp"`
}

func NewAuditLog(username, action, secretPath string, success bool) *AuditLog {
	return &AuditLog{
		ID:         GenerateUUIDv7(),
		Username:   username,
		Action:     action,
		SecretPath: secretPath,
		Success:    success,
		Timestamp:  time.Now(),
	}
}

func (a *AuditLog) SetError(errMsg string) {
	a.Success = false
	a.ErrorMessage = errMsg
}

func (a *AuditLog) SetClientInfo(ip, userAgent string) {
	a.ClientIP = ip
	a.UserAgent = userAgent
}
