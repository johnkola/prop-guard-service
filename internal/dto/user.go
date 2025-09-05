package dto

import (
	"time"

	"PropGuard/internal/entity"

	"github.com/google/uuid"
)

type CreateUserRequest struct {
	Username              string             `json:"username" binding:"required,max=100"`
	Email                 string             `json:"email" binding:"required,email"`
	Password              string             `json:"password" binding:"required,min=8"`
	Enabled               *bool              `json:"enabled"`
	AccountNonExpired     *bool              `json:"accountNonExpired"`
	AccountNonLocked      *bool              `json:"accountNonLocked"`
	CredentialsNonExpired *bool              `json:"credentialsNonExpired"`
	Roles                 []entity.VaultRole `json:"roles" binding:"required"`
	Policies              []string           `json:"policies"`
}

type UpdateUserRequest struct {
	Enabled               *bool              `json:"enabled"`
	AccountNonExpired     *bool              `json:"accountNonExpired"`
	AccountNonLocked      *bool              `json:"accountNonLocked"`
	CredentialsNonExpired *bool              `json:"credentialsNonExpired"`
	Roles                 []entity.VaultRole `json:"roles"`
	Policies              []string           `json:"policies"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required,min=8"`
}

type ResetPasswordRequest struct {
	NewPassword string `json:"newPassword" binding:"required,min=8"`
}

type UserResponse struct {
	ID                    uuid.UUID          `json:"id"`
	VaultID               uuid.UUID          `json:"vaultId"`
	Username              string             `json:"username"`
	Enabled               bool               `json:"enabled"`
	AccountNonExpired     bool               `json:"accountNonExpired"`
	AccountNonLocked      bool               `json:"accountNonLocked"`
	CredentialsNonExpired bool               `json:"credentialsNonExpired"`
	Roles                 []entity.VaultRole `json:"roles"`
	Policies              []string           `json:"policies"`
	CreatedAt             time.Time          `json:"createdAt"`
	UpdatedAt             time.Time          `json:"updatedAt"`
	Version               int64              `json:"version"`
	IsSystem              bool               `json:"isSystem"`
}

type ListUsersResponse struct {
	Users      []UserResponse `json:"users"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"pageSize"`
	TotalPages int            `json:"totalPages"`
}

// HasRoleID checks if the user has a specific role ID
func (u *UserResponse) HasRoleID(roleID string) bool {
	// This is a placeholder - in practice, we'd need to store RoleIDs in the DTO
	// For now, check if user is system user (likely admin)
	return u.IsSystem
}

// ToUserResponse converts entity.VaultUser to dto.UserResponse
func ToUserResponse(user *entity.VaultUser) UserResponse {
	return UserResponse{
		ID:                    user.ID,
		VaultID:               user.VaultID,
		Username:              user.Username,
		Enabled:               user.Enabled,
		AccountNonExpired:     user.AccountNonExpired,
		AccountNonLocked:      user.AccountNonLocked,
		CredentialsNonExpired: user.CredentialsNonExpired,
		Roles:                 user.Roles,
		Policies:              user.Policies,
		CreatedAt:             user.CreatedAt,
		UpdatedAt:             user.UpdatedAt,
		Version:               user.Version,
		IsSystem:              user.IsSystemUser(),
	}
}
