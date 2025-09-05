package dto

import (
	"time"

	"PropGuard/internal/entity"
)

// Team management DTOs
type CreateTeamRequest struct {
	Name        string `json:"name" binding:"required,max=100"`
	Description string `json:"description" binding:"max=500"`
}

type UpdateTeamRequest struct {
	Name        string               `json:"name" binding:"max=100"`
	Description string               `json:"description" binding:"max=500"`
	Settings    *entity.TeamSettings `json:"settings"`
	Metadata    map[string]string    `json:"metadata"`
}

type TeamResponse struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	OwnerID         string              `json:"owner_id"`
	Members         []entity.TeamMember `json:"members"`
	Settings        entity.TeamSettings `json:"settings"`
	Metadata        map[string]string   `json:"metadata"`
	SecretCount     int                 `json:"secret_count"`
	MemberCount     int                 `json:"member_count"`
	StorageUsed     int64               `json:"storage_used"`
	StorageLimit    int64               `json:"storage_limit"`
	SecretsLimit    int                 `json:"secrets_limit"`
	MembersLimit    int                 `json:"members_limit"`
	APIKeysLimit    int                 `json:"api_keys_limit"`
	BillingPlan     string              `json:"billing_plan"`
	SubscriptionID  string              `json:"subscription_id,omitempty"`
	TrialEndsAt     *time.Time          `json:"trial_ends_at,omitempty"`
	IsActive        bool                `json:"is_active"`
	IsSuspended     bool                `json:"is_suspended"`
	SuspendedReason string              `json:"suspended_reason,omitempty"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
	LastActivityAt  time.Time           `json:"last_activity_at"`
}

type ListTeamsResponse struct {
	Teams      []TeamResponse `json:"teams"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
	HasNext    bool           `json:"has_next"`
	HasPrev    bool           `json:"has_prev"`
}

// Team member management DTOs
type AddTeamMemberRequest struct {
	UserID string `json:"user_id" binding:"required"`
	RoleID string `json:"role_id" binding:"required"`
}

type UpdateTeamMemberRequest struct {
	RoleID      string   `json:"role_id" binding:"required"`
	Permissions []string `json:"permissions"`
}

type TeamMemberResponse struct {
	UserID           string     `json:"user_id"`
	TeamID           string     `json:"team_id"`
	RoleID           string     `json:"role_id"`
	JoinedAt         time.Time  `json:"joined_at"`
	InvitedBy        string     `json:"invited_by"`
	InviteAcceptedAt *time.Time `json:"invite_accepted_at,omitempty"`
	IsOwner          bool       `json:"is_owner"`
	Permissions      []string   `json:"permissions,omitempty"`
	LastActiveAt     *time.Time `json:"last_active_at,omitempty"`
}

// Team invitation DTOs
type CreateTeamInviteRequest struct {
	Email   string `json:"email" binding:"required,email"`
	RoleID  string `json:"role_id" binding:"required"`
	Message string `json:"message" binding:"max=500"`
}

type TeamInviteResponse struct {
	ID         string     `json:"id"`
	TeamID     string     `json:"team_id"`
	Email      string     `json:"email"`
	RoleID     string     `json:"role_id"`
	InvitedBy  string     `json:"invited_by"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	Message    string     `json:"message,omitempty"`
}

type AcceptInviteRequest struct {
	InviteToken string `json:"invite_token" binding:"required"`
	UserID      string `json:"user_id" binding:"required"`
}

// Team settings DTOs
type UpdateTeamSettingsRequest struct {
	RequireMFA               bool     `json:"require_mfa"`
	AllowAPIKeys             bool     `json:"allow_api_keys"`
	SecretRotationDays       int      `json:"secret_rotation_days"`
	SessionTimeoutMinutes    int      `json:"session_timeout_minutes"`
	IPWhitelist              []string `json:"ip_whitelist"`
	AllowedDomains           []string `json:"allowed_domains"`
	DefaultRoleID            string   `json:"default_role_id"`
	EnforceSecretNaming      bool     `json:"enforce_secret_naming"`
	SecretNamingPattern      string   `json:"secret_naming_pattern"`
	AuditRetentionDays       int      `json:"audit_retention_days"`
	RequireApprovalForDelete bool     `json:"require_approval_for_delete"`
	EnabledFeatures          []string `json:"enabled_features"`
	WebhookURL               string   `json:"webhook_url"`
	SlackWebhookURL          string   `json:"slack_webhook_url"`
	NotificationEmails       []string `json:"notification_emails"`
}

// Team stats DTOs
type TeamStatsResponse struct {
	TeamID               string    `json:"team_id"`
	TotalSecrets         int       `json:"total_secrets"`
	TotalMembers         int       `json:"total_members"`
	TotalAPIKeys         int       `json:"total_api_keys"`
	ActiveMembers30Days  int       `json:"active_members_30_days"`
	SecretsCreatedMonth  int       `json:"secrets_created_month"`
	SecretsAccessedMonth int       `json:"secrets_accessed_month"`
	StorageUsedBytes     int64     `json:"storage_used_bytes"`
	LastActivityAt       time.Time `json:"last_activity_at"`
	CalculatedAt         time.Time `json:"calculated_at"`
}

// Team activity DTOs
type TeamActivityResponse struct {
	ID           string            `json:"id"`
	TeamID       string            `json:"team_id"`
	UserID       string            `json:"user_id"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Details      map[string]string `json:"details,omitempty"`
	IPAddress    string            `json:"ip_address"`
	UserAgent    string            `json:"user_agent,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
}

type ListTeamActivitiesResponse struct {
	Activities []TeamActivityResponse `json:"activities"`
	Total      int                    `json:"total"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"page_size"`
	TotalPages int                    `json:"total_pages"`
	HasNext    bool                   `json:"has_next"`
	HasPrev    bool                   `json:"has_prev"`
}

// Team billing DTOs
type UpgradePlanRequest struct {
	PlanType string `json:"plan_type" binding:"required,oneof=free starter team enterprise"`
}

type TeamBillingResponse struct {
	TeamID         string     `json:"team_id"`
	BillingPlan    string     `json:"billing_plan"`
	SubscriptionID string     `json:"subscription_id,omitempty"`
	TrialEndsAt    *time.Time `json:"trial_ends_at,omitempty"`
	IsInTrial      bool       `json:"is_in_trial"`
	Limits         struct {
		Members   int `json:"members"`
		Secrets   int `json:"secrets"`
		APIKeys   int `json:"api_keys"`
		StorageGB int `json:"storage_gb"`
		AuditDays int `json:"audit_days"`
	} `json:"limits"`
	Usage struct {
		Members   int `json:"members"`
		Secrets   int `json:"secrets"`
		APIKeys   int `json:"api_keys"`
		StorageGB int `json:"storage_gb"`
	} `json:"usage"`
}

// Search DTOs
type SearchTeamsRequest struct {
	Query    string `json:"query" form:"query" binding:"max=100"`
	Page     int    `json:"page" form:"page,default=1"`
	PageSize int    `json:"page_size" form:"page_size,default=20"`
}

// Helper functions to convert entities to DTOs
func TeamToResponse(team *entity.Team) TeamResponse {
	return TeamResponse{
		ID:              team.ID,
		Name:            team.Name,
		Description:     team.Description,
		OwnerID:         team.OwnerID,
		Members:         team.Members,
		Settings:        team.Settings,
		Metadata:        team.Metadata,
		SecretCount:     team.SecretCount,
		MemberCount:     team.MemberCount,
		StorageUsed:     team.StorageUsed,
		StorageLimit:    team.StorageLimit,
		SecretsLimit:    team.SecretsLimit,
		MembersLimit:    team.MembersLimit,
		APIKeysLimit:    team.APIKeysLimit,
		BillingPlan:     team.BillingPlan,
		SubscriptionID:  team.SubscriptionID,
		TrialEndsAt:     team.TrialEndsAt,
		IsActive:        team.IsActive,
		IsSuspended:     team.IsSuspended,
		SuspendedReason: team.SuspendedReason,
		CreatedAt:       team.CreatedAt,
		UpdatedAt:       team.UpdatedAt,
		LastActivityAt:  team.LastActivityAt,
	}
}

func TeamInviteToResponse(invite *entity.TeamInvite) TeamInviteResponse {
	return TeamInviteResponse{
		ID:         invite.ID,
		TeamID:     invite.TeamID,
		Email:      invite.Email,
		RoleID:     invite.RoleID,
		InvitedBy:  invite.InvitedBy,
		ExpiresAt:  invite.ExpiresAt,
		AcceptedAt: invite.AcceptedAt,
		CreatedAt:  invite.CreatedAt,
		Message:    invite.Message,
	}
}

func TeamMemberToResponse(member *entity.TeamMember) TeamMemberResponse {
	return TeamMemberResponse{
		UserID:           member.UserID,
		TeamID:           member.TeamID,
		RoleID:           member.RoleID,
		JoinedAt:         member.JoinedAt,
		InvitedBy:        member.InvitedBy,
		InviteAcceptedAt: member.InviteAcceptedAt,
		IsOwner:          member.IsOwner,
		Permissions:      member.Permissions,
		LastActiveAt:     member.LastActiveAt,
	}
}

func TeamActivityToResponse(activity *entity.TeamActivity) TeamActivityResponse {
	return TeamActivityResponse{
		ID:           activity.ID,
		TeamID:       activity.TeamID,
		UserID:       activity.UserID,
		Action:       activity.Action,
		ResourceType: activity.ResourceType,
		ResourceID:   activity.ResourceID,
		Details:      activity.Details,
		IPAddress:    activity.IPAddress,
		UserAgent:    activity.UserAgent,
		Timestamp:    activity.Timestamp,
	}
}

func TeamStatsToResponse(stats *entity.TeamStats) TeamStatsResponse {
	return TeamStatsResponse{
		TeamID:               stats.TeamID,
		TotalSecrets:         stats.TotalSecrets,
		TotalMembers:         stats.TotalMembers,
		TotalAPIKeys:         stats.TotalAPIKeys,
		ActiveMembers30Days:  stats.ActiveMembers30Days,
		SecretsCreatedMonth:  stats.SecretsCreatedMonth,
		SecretsAccessedMonth: stats.SecretsAccessedMonth,
		StorageUsedBytes:     stats.StorageUsedBytes,
		LastActivityAt:       stats.LastActivityAt,
		CalculatedAt:         stats.CalculatedAt,
	}
}
