package entity

import (
	"time"

	"github.com/google/uuid"
)

type VaultRole string

const (
	RoleAdmin    VaultRole = "ADMIN"
	RoleUser     VaultRole = "USER"
	RoleReadOnly VaultRole = "READ_ONLY"
	RoleRoot     VaultRole = "ROOT"
)

type VaultUser struct {
	ID                    uuid.UUID   `bson:"_id,omitempty" json:"id"`
	VaultID               uuid.UUID   `bson:"vaultId" json:"vaultId"`
	Username              string      `bson:"username" json:"username" binding:"required,max=100"`
	PasswordHash          string      `bson:"passwordHash" json:"-" binding:"required,max=255"`
	Enabled               bool        `bson:"enabled" json:"enabled"`
	AccountNonExpired     bool        `bson:"accountNonExpired" json:"accountNonExpired"`
	AccountNonLocked      bool        `bson:"accountNonLocked" json:"accountNonLocked"`
	CredentialsNonExpired bool        `bson:"credentialsNonExpired" json:"credentialsNonExpired"`
	Roles                 []VaultRole `bson:"roles" json:"roles"`
	Policies              []string    `bson:"policies" json:"policies"`
	CreatedAt             time.Time   `bson:"createdAt" json:"createdAt"`
	UpdatedAt             time.Time   `bson:"updatedAt" json:"updatedAt"`
	Version               int64       `bson:"version" json:"version"`
}

func NewVaultUser(username, passwordHash string) *VaultUser {
	return &VaultUser{
		ID:                    GenerateUUIDv7(),
		VaultID:               GenerateUUIDv7(),
		Username:              username,
		PasswordHash:          passwordHash,
		Enabled:               true,
		AccountNonExpired:     true,
		AccountNonLocked:      true,
		CredentialsNonExpired: true,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}
}

func (u *VaultUser) IsActive() bool {
	return u.Enabled && u.AccountNonExpired && u.AccountNonLocked && u.CredentialsNonExpired
}

func (u *VaultUser) HasRole(role VaultRole) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (u *VaultUser) HasPolicy(policy string) bool {
	for _, p := range u.Policies {
		if p == policy {
			return true
		}
	}
	return false
}

func (u *VaultUser) IsSystemUser() bool {
	return u.HasRole(RoleRoot) || u.Username == "system"
}
