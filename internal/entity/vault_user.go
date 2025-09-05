package entity

import (
	"time"

	"github.com/google/uuid"
)

type VaultRole string

// Legacy role constants - deprecated in favor of new RBAC system
const (
	LegacyRoleAdmin    VaultRole = "ADMIN"
	LegacyRoleUser     VaultRole = "USER"
	LegacyRoleReadOnly VaultRole = "READ_ONLY"
	LegacyRoleRoot     VaultRole = "ROOT"
)

type VaultUser struct {
	ID                    uuid.UUID              `bson:"_id,omitempty" json:"id"`
	VaultID               uuid.UUID              `bson:"vaultId" json:"vaultId"`
	Username              string                 `bson:"username" json:"username" binding:"required,max=100"`
	Email                 string                 `bson:"email" json:"email" binding:"required,email"`
	PasswordHash          string                 `bson:"passwordHash" json:"passwordHash,omitempty" binding:"required,max=255"`
	Enabled               bool                   `bson:"enabled" json:"enabled"`
	AccountNonExpired     bool                   `bson:"accountNonExpired" json:"accountNonExpired"`
	AccountNonLocked      bool                   `bson:"accountNonLocked" json:"accountNonLocked"`
	CredentialsNonExpired bool                   `bson:"credentialsNonExpired" json:"credentialsNonExpired"`
	Roles                 []VaultRole            `bson:"roles" json:"roles"`      // Legacy roles for backward compatibility
	RoleIDs               []string               `bson:"roleIds" json:"role_ids"` // New RBAC role IDs
	TeamIDs               []string               `bson:"teamIds" json:"team_ids"` // Teams the user belongs to
	DefaultTeamID         string                 `bson:"defaultTeamId" json:"default_team_id,omitempty"`
	Policies              []string               `bson:"policies" json:"policies"`
	Permissions           []string               `bson:"permissions" json:"permissions,omitempty"` // Direct permissions
	MFAEnabled            bool                   `bson:"mfaEnabled" json:"mfa_enabled"`
	MFASecret             string                 `bson:"mfaSecret" json:"-"`
	LastLoginAt           *time.Time             `bson:"lastLoginAt" json:"last_login_at,omitempty"`
	LastLoginIP           string                 `bson:"lastLoginIp" json:"last_login_ip,omitempty"`
	LoginAttempts         int                    `bson:"loginAttempts" json:"login_attempts"`
	LockedUntil           *time.Time             `bson:"lockedUntil" json:"locked_until,omitempty"`
	PasswordChangedAt     time.Time              `bson:"passwordChangedAt" json:"password_changed_at"`
	RequirePasswordChange bool                   `bson:"requirePasswordChange" json:"require_password_change"`
	Metadata              map[string]interface{} `bson:"metadata" json:"metadata,omitempty"`
	CreatedAt             time.Time              `bson:"createdAt" json:"createdAt"`
	UpdatedAt             time.Time              `bson:"updatedAt" json:"updatedAt"`
	Version               int64                  `bson:"version" json:"version"`
}

func NewVaultUser(username, email, passwordHash string) *VaultUser {
	now := time.Now()
	return &VaultUser{
		ID:                    GenerateUUIDv7(),
		VaultID:               GenerateUUIDv7(),
		Username:              username,
		Email:                 email,
		PasswordHash:          passwordHash,
		Enabled:               true,
		AccountNonExpired:     true,
		AccountNonLocked:      true,
		CredentialsNonExpired: true,
		RoleIDs:               []string{"role_user"}, // Default role
		TeamIDs:               []string{},
		Policies:              []string{},
		Permissions:           []string{},
		MFAEnabled:            false,
		LoginAttempts:         0,
		PasswordChangedAt:     now,
		RequirePasswordChange: false,
		Metadata:              make(map[string]interface{}),
		CreatedAt:             now,
		UpdatedAt:             now,
		Version:               1,
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
	return u.HasRole(LegacyRoleRoot) || u.Username == "system" || u.HasRoleID("role_admin")
}

// HasRoleID checks if user has a specific role ID (new RBAC system)
func (u *VaultUser) HasRoleID(roleID string) bool {
	for _, id := range u.RoleIDs {
		if id == roleID {
			return true
		}
	}
	return false
}

// HasPermission checks if user has a specific permission
func (u *VaultUser) HasPermission(permission string) bool {
	for _, p := range u.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// BelongsToTeam checks if user belongs to a specific team
func (u *VaultUser) BelongsToTeam(teamID string) bool {
	for _, id := range u.TeamIDs {
		if id == teamID {
			return true
		}
	}
	return false
}

// AddToTeam adds user to a team
func (u *VaultUser) AddToTeam(teamID string) {
	if !u.BelongsToTeam(teamID) {
		u.TeamIDs = append(u.TeamIDs, teamID)
		if u.DefaultTeamID == "" {
			u.DefaultTeamID = teamID
		}
		u.UpdatedAt = time.Now()
		u.Version++
	}
}

// RemoveFromTeam removes user from a team
func (u *VaultUser) RemoveFromTeam(teamID string) {
	newTeamIDs := []string{}
	for _, id := range u.TeamIDs {
		if id != teamID {
			newTeamIDs = append(newTeamIDs, id)
		}
	}
	u.TeamIDs = newTeamIDs

	// Update default team if necessary
	if u.DefaultTeamID == teamID {
		if len(u.TeamIDs) > 0 {
			u.DefaultTeamID = u.TeamIDs[0]
		} else {
			u.DefaultTeamID = ""
		}
	}

	u.UpdatedAt = time.Now()
	u.Version++
}

// AssignRole assigns a role to the user
func (u *VaultUser) AssignRole(roleID string) {
	if !u.HasRoleID(roleID) {
		u.RoleIDs = append(u.RoleIDs, roleID)
		u.UpdatedAt = time.Now()
		u.Version++
	}
}

// RemoveRole removes a role from the user
func (u *VaultUser) RemoveRole(roleID string) {
	newRoleIDs := []string{}
	for _, id := range u.RoleIDs {
		if id != roleID {
			newRoleIDs = append(newRoleIDs, id)
		}
	}
	u.RoleIDs = newRoleIDs
	u.UpdatedAt = time.Now()
	u.Version++
}

// IsLocked checks if the account is currently locked
func (u *VaultUser) IsLocked() bool {
	if !u.AccountNonLocked {
		return true
	}
	if u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
		return true
	}
	return false
}

// RecordLoginAttempt records a login attempt
func (u *VaultUser) RecordLoginAttempt(success bool, ip string) {
	if success {
		u.LoginAttempts = 0
		now := time.Now()
		u.LastLoginAt = &now
		u.LastLoginIP = ip
		u.LockedUntil = nil
	} else {
		u.LoginAttempts++
		// Lock account after 5 failed attempts for 15 minutes
		if u.LoginAttempts >= 5 {
			lockUntil := time.Now().Add(15 * time.Minute)
			u.LockedUntil = &lockUntil
		}
	}
	u.UpdatedAt = time.Now()
	u.Version++
}

// NeedsPasswordChange checks if user needs to change password
func (u *VaultUser) NeedsPasswordChange() bool {
	if u.RequirePasswordChange {
		return true
	}
	// Check if password is older than 90 days
	passwordAge := time.Since(u.PasswordChangedAt)
	return passwordAge > (90 * 24 * time.Hour)
}

// UpdatePassword updates the user's password
func (u *VaultUser) UpdatePassword(newPasswordHash string) {
	u.PasswordHash = newPasswordHash
	u.PasswordChangedAt = time.Now()
	u.RequirePasswordChange = false
	u.UpdatedAt = time.Now()
	u.Version++
}
