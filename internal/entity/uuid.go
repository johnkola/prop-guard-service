package entity

import (
	"github.com/google/uuid"
)

// GenerateUUIDv7 generates a UUIDv7 using the Google UUID library
func GenerateUUIDv7() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}

// GenerateUUID generates a UUID string for compatibility
func GenerateUUID() string {
	return uuid.New().String()
}
