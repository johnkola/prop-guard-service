package entity

import (
	"encoding/json"
	"fmt"
	"time"
)

// Team represents a team/workspace for multi-tenancy
type Team struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Description     string            `json:"description,omitempty"`
	OwnerID         string            `json:"owner_id"`
	Members         []TeamMember      `json:"members"`
	Settings        TeamSettings      `json:"settings"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	SecretCount     int               `json:"secret_count"`
	MemberCount     int               `json:"member_count"`
	StorageUsed     int64             `json:"storage_used"`  // in bytes
	StorageLimit    int64             `json:"storage_limit"` // in bytes
	SecretsLimit    int               `json:"secrets_limit"`
	MembersLimit    int               `json:"members_limit"`
	APIKeysLimit    int               `json:"api_keys_limit"`
	BillingPlan     string            `json:"billing_plan"`
	SubscriptionID  string            `json:"subscription_id,omitempty"`
	TrialEndsAt     *time.Time        `json:"trial_ends_at,omitempty"`
	IsActive        bool              `json:"is_active"`
	IsSuspended     bool              `json:"is_suspended"`
	SuspendedReason string            `json:"suspended_reason,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
	LastActivityAt  time.Time         `json:"last_activity_at"`
}

// TeamMember represents a member of a team
type TeamMember struct {
	UserID           string     `json:"user_id"`
	TeamID           string     `json:"team_id"`
	RoleID           string     `json:"role_id"`
	JoinedAt         time.Time  `json:"joined_at"`
	InvitedBy        string     `json:"invited_by"`
	InviteAcceptedAt *time.Time `json:"invite_accepted_at,omitempty"`
	IsOwner          bool       `json:"is_owner"`
	Permissions      []string   `json:"permissions,omitempty"` // Override permissions
	LastActiveAt     *time.Time `json:"last_active_at,omitempty"`
}

// TeamSettings contains team-specific settings
type TeamSettings struct {
	RequireMFA               bool     `json:"require_mfa"`
	AllowAPIKeys             bool     `json:"allow_api_keys"`
	SecretRotationDays       int      `json:"secret_rotation_days"`
	SessionTimeoutMinutes    int      `json:"session_timeout_minutes"`
	IPWhitelist              []string `json:"ip_whitelist,omitempty"`
	AllowedDomains           []string `json:"allowed_domains,omitempty"` // Email domains for auto-join
	DefaultRoleID            string   `json:"default_role_id"`
	EnforceSecretNaming      bool     `json:"enforce_secret_naming"`
	SecretNamingPattern      string   `json:"secret_naming_pattern,omitempty"`
	AuditRetentionDays       int      `json:"audit_retention_days"`
	RequireApprovalForDelete bool     `json:"require_approval_for_delete"`
	EnabledFeatures          []string `json:"enabled_features"`
	WebhookURL               string   `json:"webhook_url,omitempty"`
	SlackWebhookURL          string   `json:"slack_webhook_url,omitempty"`
	NotificationEmails       []string `json:"notification_emails,omitempty"`
}

// TeamInvite represents an invitation to join a team
type TeamInvite struct {
	ID          string     `json:"id"`
	TeamID      string     `json:"team_id"`
	Email       string     `json:"email"`
	RoleID      string     `json:"role_id"`
	InvitedBy   string     `json:"invited_by"`
	InviteToken string     `json:"-"` // Not exposed in JSON
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	Message     string     `json:"message,omitempty"`
}

// TeamActivity tracks team activity for audit
type TeamActivity struct {
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

// TeamStats provides statistics about team usage
type TeamStats struct {
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

// Billing plans
const (
	PlanFree       = "free"
	PlanStarter    = "starter"
	PlanTeam       = "team"
	PlanEnterprise = "enterprise"
)

// Team activity actions
const (
	ActionTeamCreated       = "team.created"
	ActionTeamUpdated       = "team.updated"
	ActionTeamDeleted       = "team.deleted"
	ActionMemberAdded       = "team.member.added"
	ActionMemberRemoved     = "team.member.removed"
	ActionMemberRoleChanged = "team.member.role_changed"
	ActionSettingsUpdated   = "team.settings.updated"
	ActionPlanUpgraded      = "team.plan.upgraded"
	ActionPlanDowngraded    = "team.plan.downgraded"
)

// Default limits by plan
var PlanLimits = map[string]struct {
	Members   int
	Secrets   int
	APIKeys   int
	StorageGB int
	AuditDays int
}{
	PlanFree: {
		Members:   5,
		Secrets:   50,
		APIKeys:   2,
		StorageGB: 1,
		AuditDays: 7,
	},
	PlanStarter: {
		Members:   20,
		Secrets:   500,
		APIKeys:   10,
		StorageGB: 10,
		AuditDays: 30,
	},
	PlanTeam: {
		Members:   100,
		Secrets:   5000,
		APIKeys:   50,
		StorageGB: 100,
		AuditDays: 90,
	},
	PlanEnterprise: {
		Members:   -1, // Unlimited
		Secrets:   -1,
		APIKeys:   -1,
		StorageGB: -1,
		AuditDays: 365,
	},
}

// NewTeam creates a new team
func NewTeam(name, ownerID string) *Team {
	now := time.Now()
	trialEnd := now.AddDate(0, 0, 30) // 30-day trial

	return &Team{
		ID:             GenerateUUID(),
		Name:           name,
		OwnerID:        ownerID,
		Members:        []TeamMember{},
		Settings:       DefaultTeamSettings(),
		Metadata:       make(map[string]string),
		BillingPlan:    PlanFree,
		MembersLimit:   PlanLimits[PlanFree].Members,
		SecretsLimit:   PlanLimits[PlanFree].Secrets,
		APIKeysLimit:   PlanLimits[PlanFree].APIKeys,
		StorageLimit:   int64(PlanLimits[PlanFree].StorageGB) * 1024 * 1024 * 1024,
		IsActive:       true,
		TrialEndsAt:    &trialEnd,
		CreatedAt:      now,
		UpdatedAt:      now,
		LastActivityAt: now,
	}
}

// DefaultTeamSettings returns default team settings
func DefaultTeamSettings() TeamSettings {
	return TeamSettings{
		RequireMFA:               false,
		AllowAPIKeys:             true,
		SecretRotationDays:       90,
		SessionTimeoutMinutes:    60,
		DefaultRoleID:            "role_user",
		EnforceSecretNaming:      false,
		AuditRetentionDays:       30,
		RequireApprovalForDelete: false,
		EnabledFeatures:          []string{"secrets", "api_keys", "audit"},
		IPWhitelist:              []string{},
		AllowedDomains:           []string{},
		NotificationEmails:       []string{},
	}
}

// AddMember adds a member to the team
func (t *Team) AddMember(userID, roleID, invitedBy string) error {
	// Check member limit
	if t.MembersLimit > 0 && len(t.Members) >= t.MembersLimit {
		return fmt.Errorf("team member limit reached (%d)", t.MembersLimit)
	}

	// Check if already a member
	for _, m := range t.Members {
		if m.UserID == userID {
			return fmt.Errorf("user is already a team member")
		}
	}

	member := TeamMember{
		UserID:    userID,
		TeamID:    t.ID,
		RoleID:    roleID,
		JoinedAt:  time.Now(),
		InvitedBy: invitedBy,
		IsOwner:   false,
	}

	t.Members = append(t.Members, member)
	t.MemberCount = len(t.Members)
	t.UpdatedAt = time.Now()

	return nil
}

// RemoveMember removes a member from the team
func (t *Team) RemoveMember(userID string) error {
	// Cannot remove owner
	if userID == t.OwnerID {
		return fmt.Errorf("cannot remove team owner")
	}

	found := false
	newMembers := []TeamMember{}
	for _, m := range t.Members {
		if m.UserID != userID {
			newMembers = append(newMembers, m)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("user is not a team member")
	}

	t.Members = newMembers
	t.MemberCount = len(t.Members)
	t.UpdatedAt = time.Now()

	return nil
}

// GetMember retrieves a team member by user ID
func (t *Team) GetMember(userID string) (*TeamMember, error) {
	for _, m := range t.Members {
		if m.UserID == userID {
			return &m, nil
		}
	}
	return nil, fmt.Errorf("member not found")
}

// UpdateMemberRole updates a member's role
func (t *Team) UpdateMemberRole(userID, newRoleID string) error {
	for i, m := range t.Members {
		if m.UserID == userID {
			t.Members[i].RoleID = newRoleID
			t.UpdatedAt = time.Now()
			return nil
		}
	}
	return fmt.Errorf("member not found")
}

// IsOwner checks if a user is the team owner
func (t *Team) IsOwner(userID string) bool {
	return t.OwnerID == userID
}

// IsMember checks if a user is a team member
func (t *Team) IsMember(userID string) bool {
	if t.IsOwner(userID) {
		return true
	}
	for _, m := range t.Members {
		if m.UserID == userID {
			return true
		}
	}
	return false
}

// CanAddSecrets checks if the team can add more secrets
func (t *Team) CanAddSecrets(count int) bool {
	if t.SecretsLimit <= 0 {
		return true // Unlimited
	}
	return (t.SecretCount + count) <= t.SecretsLimit
}

// CanAddMembers checks if the team can add more members
func (t *Team) CanAddMembers(count int) bool {
	if t.MembersLimit <= 0 {
		return true // Unlimited
	}
	return (t.MemberCount + count) <= t.MembersLimit
}

// IsInTrial checks if the team is in trial period
func (t *Team) IsInTrial() bool {
	if t.TrialEndsAt == nil {
		return false
	}
	return time.Now().Before(*t.TrialEndsAt)
}

// UpgradePlan upgrades the team's billing plan
func (t *Team) UpgradePlan(newPlan string) error {
	limits, exists := PlanLimits[newPlan]
	if !exists {
		return fmt.Errorf("invalid plan: %s", newPlan)
	}

	t.BillingPlan = newPlan
	t.MembersLimit = limits.Members
	t.SecretsLimit = limits.Secrets
	t.APIKeysLimit = limits.APIKeys
	t.StorageLimit = int64(limits.StorageGB) * 1024 * 1024 * 1024
	t.Settings.AuditRetentionDays = limits.AuditDays
	t.UpdatedAt = time.Now()

	return nil
}

// ToJSON converts team to JSON
func (t *Team) ToJSON() ([]byte, error) {
	return json.Marshal(t)
}

// FromJSON creates team from JSON
func (t *Team) FromJSON(data []byte) error {
	return json.Unmarshal(data, t)
}
