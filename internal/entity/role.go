package entity

import (
	"encoding/json"
	"time"
)

// Role represents a role in the system with associated permissions
type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	IsSystem    bool      `json:"is_system"` // System roles cannot be deleted
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedBy   string    `json:"created_by"`
}

// Permission constants for fine-grained access control
const (
	// Secret permissions
	PermissionSecretCreate = "secret:create"
	PermissionSecretRead   = "secret:read"
	PermissionSecretUpdate = "secret:update"
	PermissionSecretDelete = "secret:delete"
	PermissionSecretList   = "secret:list"
	PermissionSecretShare  = "secret:share"
	PermissionSecretRotate = "secret:rotate"

	// User permissions
	PermissionUserCreate = "user:create"
	PermissionUserRead   = "user:read"
	PermissionUserUpdate = "user:update"
	PermissionUserDelete = "user:delete"
	PermissionUserList   = "user:list"

	// Role permissions
	PermissionRoleCreate = "role:create"
	PermissionRoleRead   = "role:read"
	PermissionRoleUpdate = "role:update"
	PermissionRoleDelete = "role:delete"
	PermissionRoleList   = "role:list"
	PermissionRoleAssign = "role:assign"

	// Team permissions
	PermissionTeamCreate       = "team:create"
	PermissionTeamRead         = "team:read"
	PermissionTeamUpdate       = "team:update"
	PermissionTeamDelete       = "team:delete"
	PermissionTeamList         = "team:list"
	PermissionTeamMemberAdd    = "team:member:add"
	PermissionTeamMemberRemove = "team:member:remove"

	// API Key permissions
	PermissionAPIKeyCreate = "apikey:create"
	PermissionAPIKeyRead   = "apikey:read"
	PermissionAPIKeyRevoke = "apikey:revoke"
	PermissionAPIKeyList   = "apikey:list"

	// Audit permissions
	PermissionAuditRead   = "audit:read"
	PermissionAuditExport = "audit:export"
	PermissionAuditPurge  = "audit:purge"

	// Policy permissions
	PermissionPolicyCreate = "policy:create"
	PermissionPolicyRead   = "policy:read"
	PermissionPolicyUpdate = "policy:update"
	PermissionPolicyDelete = "policy:delete"
	PermissionPolicyList   = "policy:list"

	// System permissions
	PermissionSystemConfig = "system:config"
	PermissionSystemBackup = "system:backup"
	PermissionSystemHealth = "system:health"
	PermissionSystemStats  = "system:stats"
)

// Predefined system roles
var (
	// RoleAdmin has all permissions
	RoleAdmin = &Role{
		ID:          "role_admin",
		Name:        "Administrator",
		Description: "Full system access",
		Permissions: []string{
			PermissionSecretCreate, PermissionSecretRead, PermissionSecretUpdate, PermissionSecretDelete,
			PermissionSecretList, PermissionSecretShare, PermissionSecretRotate,
			PermissionUserCreate, PermissionUserRead, PermissionUserUpdate, PermissionUserDelete, PermissionUserList,
			PermissionRoleCreate, PermissionRoleRead, PermissionRoleUpdate, PermissionRoleDelete, PermissionRoleList, PermissionRoleAssign,
			PermissionTeamCreate, PermissionTeamRead, PermissionTeamUpdate, PermissionTeamDelete, PermissionTeamList,
			PermissionTeamMemberAdd, PermissionTeamMemberRemove,
			PermissionAPIKeyCreate, PermissionAPIKeyRead, PermissionAPIKeyRevoke, PermissionAPIKeyList,
			PermissionAuditRead, PermissionAuditExport, PermissionAuditPurge,
			PermissionPolicyCreate, PermissionPolicyRead, PermissionPolicyUpdate, PermissionPolicyDelete, PermissionPolicyList,
			PermissionSystemConfig, PermissionSystemBackup, PermissionSystemHealth, PermissionSystemStats,
		},
		IsSystem:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	// RoleManager can manage users and secrets but not system settings
	RoleManager = &Role{
		ID:          "role_manager",
		Name:        "Manager",
		Description: "Manage users and secrets",
		Permissions: []string{
			PermissionSecretCreate, PermissionSecretRead, PermissionSecretUpdate, PermissionSecretDelete,
			PermissionSecretList, PermissionSecretShare, PermissionSecretRotate,
			PermissionUserRead, PermissionUserUpdate, PermissionUserList,
			PermissionTeamRead, PermissionTeamUpdate, PermissionTeamList,
			PermissionTeamMemberAdd, PermissionTeamMemberRemove,
			PermissionAPIKeyCreate, PermissionAPIKeyRead, PermissionAPIKeyRevoke, PermissionAPIKeyList,
			PermissionAuditRead,
			PermissionPolicyRead, PermissionPolicyList,
			PermissionSystemHealth, PermissionSystemStats,
		},
		IsSystem:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	// RoleUser has basic read/write permissions for their own resources
	RoleUser = &Role{
		ID:          "role_user",
		Name:        "User",
		Description: "Standard user access",
		Permissions: []string{
			PermissionSecretCreate, PermissionSecretRead, PermissionSecretUpdate,
			PermissionSecretList,
			PermissionUserRead,
			PermissionTeamRead, PermissionTeamList,
			PermissionAPIKeyCreate, PermissionAPIKeyRead, PermissionAPIKeyList,
			PermissionAuditRead,
			PermissionSystemHealth,
		},
		IsSystem:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	// RoleReadOnly has read-only access
	RoleReadOnly = &Role{
		ID:          "role_readonly",
		Name:        "Read Only",
		Description: "Read-only access to resources",
		Permissions: []string{
			PermissionSecretRead, PermissionSecretList,
			PermissionUserRead, PermissionUserList,
			PermissionRoleRead, PermissionRoleList,
			PermissionTeamRead, PermissionTeamList,
			PermissionAPIKeyRead, PermissionAPIKeyList,
			PermissionAuditRead,
			PermissionPolicyRead, PermissionPolicyList,
			PermissionSystemHealth, PermissionSystemStats,
		},
		IsSystem:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	// RoleServiceAccount for API access
	RoleServiceAccount = &Role{
		ID:          "role_service",
		Name:        "Service Account",
		Description: "API service account access",
		Permissions: []string{
			PermissionSecretRead,
			PermissionSecretList,
			PermissionSystemHealth,
		},
		IsSystem:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}
)

// GetSystemRoles returns all predefined system roles
func GetSystemRoles() []*Role {
	return []*Role{
		RoleAdmin,
		RoleManager,
		RoleUser,
		RoleReadOnly,
		RoleServiceAccount,
	}
}

// HasPermission checks if the role has a specific permission
func (r *Role) HasPermission(permission string) bool {
	for _, p := range r.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// ToJSON converts role to JSON
func (r *Role) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}

// FromJSON creates role from JSON
func (r *Role) FromJSON(data []byte) error {
	return json.Unmarshal(data, r)
}
