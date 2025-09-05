package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
)

type TeamService interface {
	CreateTeam(ctx context.Context, req dto.CreateTeamRequest, ownerID string) (*dto.TeamResponse, error)
	GetTeam(ctx context.Context, id string) (*dto.TeamResponse, error)
	GetTeamByName(ctx context.Context, name string) (*dto.TeamResponse, error)
	UpdateTeam(ctx context.Context, id string, req dto.UpdateTeamRequest, updatedBy string) (*dto.TeamResponse, error)
	DeleteTeam(ctx context.Context, id string, deletedBy string) error
	ListTeams(ctx context.Context, page, pageSize int) (*dto.ListTeamsResponse, error)
	SearchTeams(ctx context.Context, req dto.SearchTeamsRequest) (*dto.ListTeamsResponse, error)

	// Team membership management
	AddTeamMember(ctx context.Context, teamID string, req dto.AddTeamMemberRequest, addedBy string) (*dto.TeamMemberResponse, error)
	RemoveTeamMember(ctx context.Context, teamID, userID string, removedBy string) error
	UpdateTeamMember(ctx context.Context, teamID, userID string, req dto.UpdateTeamMemberRequest, updatedBy string) (*dto.TeamMemberResponse, error)
	GetTeamMembers(ctx context.Context, teamID string) ([]dto.TeamMemberResponse, error)
	GetUserTeams(ctx context.Context, userID string) ([]dto.TeamResponse, error)

	// Team invitations
	CreateTeamInvite(ctx context.Context, teamID string, req dto.CreateTeamInviteRequest, invitedBy string) (*dto.TeamInviteResponse, error)
	AcceptTeamInvite(ctx context.Context, req dto.AcceptInviteRequest) (*dto.TeamMemberResponse, error)
	GetTeamInvites(ctx context.Context, teamID string) ([]dto.TeamInviteResponse, error)
	CancelTeamInvite(ctx context.Context, inviteID string, cancelledBy string) error

	// Team settings
	UpdateTeamSettings(ctx context.Context, teamID string, req dto.UpdateTeamSettingsRequest, updatedBy string) (*dto.TeamResponse, error)

	// Team stats and activity
	GetTeamStats(ctx context.Context, teamID string) (*dto.TeamStatsResponse, error)
	GetTeamActivities(ctx context.Context, teamID string, page, pageSize int) (*dto.ListTeamActivitiesResponse, error)

	// Team billing
	UpgradeTeamPlan(ctx context.Context, teamID string, req dto.UpgradePlanRequest, upgradedBy string) (*dto.TeamBillingResponse, error)
	GetTeamBilling(ctx context.Context, teamID string) (*dto.TeamBillingResponse, error)
}

type teamService struct {
	teamRepo     *repository.BadgerTeamRepository
	auditService AuditService
}

func NewTeamService(teamRepo *repository.BadgerTeamRepository, auditService AuditService) TeamService {
	return &teamService{
		teamRepo:     teamRepo,
		auditService: auditService,
	}
}

func (s *teamService) CreateTeam(ctx context.Context, req dto.CreateTeamRequest, ownerID string) (*dto.TeamResponse, error) {
	// Create team entity
	team := entity.NewTeam(req.Name, ownerID)
	if req.Description != "" {
		team.Description = req.Description
	}

	// Add owner as first member
	owner := &entity.TeamMember{
		UserID:    ownerID,
		TeamID:    team.ID,
		RoleID:    "role_admin", // Default admin role
		JoinedAt:  time.Now(),
		InvitedBy: ownerID,
		IsOwner:   true,
	}
	team.Members = []entity.TeamMember{*owner}
	team.MemberCount = 1

	// Create team in repository
	if err := s.teamRepo.Create(ctx, team); err != nil {
		s.auditService.LogUserOperation(ctx, ownerID, "CREATE_TEAM", req.Name, false, fmt.Sprintf("Team creation failed: %v", err))
		return nil, fmt.Errorf("failed to create team: %w", err)
	}

	// Log team creation activity
	activity := &entity.TeamActivity{
		ID:           entity.GenerateUUID(),
		TeamID:       team.ID,
		UserID:       ownerID,
		Action:       entity.ActionTeamCreated,
		ResourceType: "team",
		ResourceID:   team.ID,
		Details:      map[string]string{"team_name": req.Name},
		Timestamp:    time.Now(),
	}
	s.teamRepo.LogActivity(ctx, activity)

	s.auditService.LogUserOperation(ctx, ownerID, "CREATE_TEAM", req.Name, true, "Team created successfully")

	response := dto.TeamToResponse(team)
	return &response, nil
}

func (s *teamService) GetTeam(ctx context.Context, id string) (*dto.TeamResponse, error) {
	team, err := s.teamRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	response := dto.TeamToResponse(team)
	return &response, nil
}

func (s *teamService) GetTeamByName(ctx context.Context, name string) (*dto.TeamResponse, error) {
	team, err := s.teamRepo.GetByName(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get team by name: %w", err)
	}

	response := dto.TeamToResponse(team)
	return &response, nil
}

func (s *teamService) UpdateTeam(ctx context.Context, id string, req dto.UpdateTeamRequest, updatedBy string) (*dto.TeamResponse, error) {
	// Get existing team
	team, err := s.teamRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	// Check if user has permission to update team
	if !team.IsOwner(updatedBy) && !s.hasTeamPermission(team, updatedBy, "team:update") {
		s.auditService.LogUserOperation(ctx, updatedBy, "UPDATE_TEAM", team.Name, false, "Insufficient permissions")
		return nil, fmt.Errorf("insufficient permissions to update team")
	}

	// Update fields
	if req.Name != "" {
		team.Name = req.Name
	}
	if req.Description != "" {
		team.Description = req.Description
	}
	if req.Settings != nil {
		team.Settings = *req.Settings
	}
	if req.Metadata != nil {
		team.Metadata = req.Metadata
	}

	// Update team
	if err := s.teamRepo.Update(ctx, team); err != nil {
		s.auditService.LogUserOperation(ctx, updatedBy, "UPDATE_TEAM", team.Name, false, fmt.Sprintf("Team update failed: %v", err))
		return nil, fmt.Errorf("failed to update team: %w", err)
	}

	// Log activity
	activity := &entity.TeamActivity{
		ID:           entity.GenerateUUID(),
		TeamID:       team.ID,
		UserID:       updatedBy,
		Action:       entity.ActionTeamUpdated,
		ResourceType: "team",
		ResourceID:   team.ID,
		Details:      map[string]string{"updated_fields": "name,description,settings"},
		Timestamp:    time.Now(),
	}
	s.teamRepo.LogActivity(ctx, activity)

	s.auditService.LogUserOperation(ctx, updatedBy, "UPDATE_TEAM", team.Name, true, "Team updated successfully")

	response := dto.TeamToResponse(team)
	return &response, nil
}

func (s *teamService) DeleteTeam(ctx context.Context, id string, deletedBy string) error {
	// Get team to check permissions
	team, err := s.teamRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get team: %w", err)
	}

	// Only team owner can delete team
	if !team.IsOwner(deletedBy) {
		s.auditService.LogUserOperation(ctx, deletedBy, "DELETE_TEAM", team.Name, false, "Only team owner can delete team")
		return fmt.Errorf("only team owner can delete team")
	}

	// Delete team
	if err := s.teamRepo.Delete(ctx, id); err != nil {
		s.auditService.LogUserOperation(ctx, deletedBy, "DELETE_TEAM", team.Name, false, fmt.Sprintf("Team deletion failed: %v", err))
		return fmt.Errorf("failed to delete team: %w", err)
	}

	s.auditService.LogUserOperation(ctx, deletedBy, "DELETE_TEAM", team.Name, true, "Team deleted successfully")
	return nil
}

func (s *teamService) ListTeams(ctx context.Context, page, pageSize int) (*dto.ListTeamsResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	teams, err := s.teamRepo.List(ctx, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list teams: %w", err)
	}

	total, err := s.teamRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count teams: %w", err)
	}

	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))

	var teamResponses []dto.TeamResponse
	for _, team := range teams {
		teamResponses = append(teamResponses, dto.TeamToResponse(team))
	}

	return &dto.ListTeamsResponse{
		Teams:      teamResponses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}, nil
}

func (s *teamService) SearchTeams(ctx context.Context, req dto.SearchTeamsRequest) (*dto.ListTeamsResponse, error) {
	if req.Page < 1 {
		req.Page = 1
	}
	if req.PageSize < 1 || req.PageSize > 100 {
		req.PageSize = 20
	}

	offset := (req.Page - 1) * req.PageSize

	teams, err := s.teamRepo.SearchTeams(ctx, req.Query, req.PageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to search teams: %w", err)
	}

	// For simplicity, we'll assume the search count equals the returned results
	// In a real implementation, you might want a separate count method for search
	total := len(teams)
	totalPages := int(math.Ceil(float64(total) / float64(req.PageSize)))

	var teamResponses []dto.TeamResponse
	for _, team := range teams {
		teamResponses = append(teamResponses, dto.TeamToResponse(team))
	}

	return &dto.ListTeamsResponse{
		Teams:      teamResponses,
		Total:      total,
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
		HasNext:    req.Page < totalPages,
		HasPrev:    req.Page > 1,
	}, nil
}

func (s *teamService) AddTeamMember(ctx context.Context, teamID string, req dto.AddTeamMemberRequest, addedBy string) (*dto.TeamMemberResponse, error) {
	// Get team
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	// Check permissions
	if !team.IsOwner(addedBy) && !s.hasTeamPermission(team, addedBy, "team:members:add") {
		s.auditService.LogUserOperation(ctx, addedBy, "ADD_TEAM_MEMBER", team.Name, false, "Insufficient permissions")
		return nil, fmt.Errorf("insufficient permissions to add team member")
	}

	// Create member
	member := &entity.TeamMember{
		UserID:    req.UserID,
		TeamID:    teamID,
		RoleID:    req.RoleID,
		JoinedAt:  time.Now(),
		InvitedBy: addedBy,
		IsOwner:   false,
	}

	// Add member to team
	if err := s.teamRepo.AddMember(ctx, teamID, member); err != nil {
		s.auditService.LogUserOperation(ctx, addedBy, "ADD_TEAM_MEMBER", team.Name, false, fmt.Sprintf("Failed to add member: %v", err))
		return nil, fmt.Errorf("failed to add team member: %w", err)
	}

	// Log activity
	activity := &entity.TeamActivity{
		ID:           entity.GenerateUUID(),
		TeamID:       teamID,
		UserID:       addedBy,
		Action:       entity.ActionMemberAdded,
		ResourceType: "team_member",
		ResourceID:   req.UserID,
		Details:      map[string]string{"added_user": req.UserID, "role": req.RoleID},
		Timestamp:    time.Now(),
	}
	s.teamRepo.LogActivity(ctx, activity)

	s.auditService.LogUserOperation(ctx, addedBy, "ADD_TEAM_MEMBER", team.Name, true, fmt.Sprintf("Added member %s", req.UserID))

	response := dto.TeamMemberToResponse(member)
	return &response, nil
}

func (s *teamService) RemoveTeamMember(ctx context.Context, teamID, userID string, removedBy string) error {
	// Get team
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return fmt.Errorf("failed to get team: %w", err)
	}

	// Check permissions
	if !team.IsOwner(removedBy) && !s.hasTeamPermission(team, removedBy, "team:members:remove") {
		s.auditService.LogUserOperation(ctx, removedBy, "REMOVE_TEAM_MEMBER", team.Name, false, "Insufficient permissions")
		return fmt.Errorf("insufficient permissions to remove team member")
	}

	// Remove member
	if err := s.teamRepo.RemoveMember(ctx, teamID, userID); err != nil {
		s.auditService.LogUserOperation(ctx, removedBy, "REMOVE_TEAM_MEMBER", team.Name, false, fmt.Sprintf("Failed to remove member: %v", err))
		return fmt.Errorf("failed to remove team member: %w", err)
	}

	// Log activity
	activity := &entity.TeamActivity{
		ID:           entity.GenerateUUID(),
		TeamID:       teamID,
		UserID:       removedBy,
		Action:       entity.ActionMemberRemoved,
		ResourceType: "team_member",
		ResourceID:   userID,
		Details:      map[string]string{"removed_user": userID},
		Timestamp:    time.Now(),
	}
	s.teamRepo.LogActivity(ctx, activity)

	s.auditService.LogUserOperation(ctx, removedBy, "REMOVE_TEAM_MEMBER", team.Name, true, fmt.Sprintf("Removed member %s", userID))
	return nil
}

func (s *teamService) UpdateTeamMember(ctx context.Context, teamID, userID string, req dto.UpdateTeamMemberRequest, updatedBy string) (*dto.TeamMemberResponse, error) {
	// Get team
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	// Check permissions
	if !team.IsOwner(updatedBy) && !s.hasTeamPermission(team, updatedBy, "team:members:update") {
		return nil, fmt.Errorf("insufficient permissions to update team member")
	}

	// Update member role
	if err := team.UpdateMemberRole(userID, req.RoleID); err != nil {
		return nil, fmt.Errorf("failed to update member role: %w", err)
	}

	// Update team in repository
	if err := s.teamRepo.Update(ctx, team); err != nil {
		return nil, fmt.Errorf("failed to update team: %w", err)
	}

	// Log activity
	activity := &entity.TeamActivity{
		ID:           entity.GenerateUUID(),
		TeamID:       teamID,
		UserID:       updatedBy,
		Action:       entity.ActionMemberRoleChanged,
		ResourceType: "team_member",
		ResourceID:   userID,
		Details:      map[string]string{"new_role": req.RoleID},
		Timestamp:    time.Now(),
	}
	s.teamRepo.LogActivity(ctx, activity)

	// Get updated member
	member, err := team.GetMember(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get updated member: %w", err)
	}

	response := dto.TeamMemberToResponse(member)
	return &response, nil
}

func (s *teamService) GetTeamMembers(ctx context.Context, teamID string) ([]dto.TeamMemberResponse, error) {
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	var members []dto.TeamMemberResponse
	for _, member := range team.Members {
		members = append(members, dto.TeamMemberToResponse(&member))
	}

	return members, nil
}

func (s *teamService) GetUserTeams(ctx context.Context, userID string) ([]dto.TeamResponse, error) {
	// Get teams where user is owner
	ownerTeams, err := s.teamRepo.GetByOwnerID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get owner teams: %w", err)
	}

	// Get teams where user is member
	memberTeams, err := s.teamRepo.GetMemberTeams(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get member teams: %w", err)
	}

	// Combine and deduplicate
	teamMap := make(map[string]*entity.Team)
	for _, team := range ownerTeams {
		teamMap[team.ID] = team
	}
	for _, team := range memberTeams {
		teamMap[team.ID] = team
	}

	var teams []dto.TeamResponse
	for _, team := range teamMap {
		teams = append(teams, dto.TeamToResponse(team))
	}

	return teams, nil
}

func (s *teamService) CreateTeamInvite(ctx context.Context, teamID string, req dto.CreateTeamInviteRequest, invitedBy string) (*dto.TeamInviteResponse, error) {
	// Get team
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	// Check permissions
	if !team.IsOwner(invitedBy) && !s.hasTeamPermission(team, invitedBy, "team:invites:create") {
		return nil, fmt.Errorf("insufficient permissions to create team invite")
	}

	// Generate invite token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	inviteToken := hex.EncodeToString(tokenBytes)

	// Create invite
	invite := &entity.TeamInvite{
		ID:          entity.GenerateUUID(),
		TeamID:      teamID,
		Email:       req.Email,
		RoleID:      req.RoleID,
		InvitedBy:   invitedBy,
		InviteToken: inviteToken,
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour), // 7 days
		CreatedAt:   time.Now(),
		Message:     req.Message,
	}

	// Save invite
	if err := s.teamRepo.CreateInvite(ctx, invite); err != nil {
		return nil, fmt.Errorf("failed to create invite: %w", err)
	}

	response := dto.TeamInviteToResponse(invite)
	return &response, nil
}

func (s *teamService) AcceptTeamInvite(ctx context.Context, req dto.AcceptInviteRequest) (*dto.TeamMemberResponse, error) {
	// Get invite by token
	invite, err := s.teamRepo.GetInviteByToken(ctx, req.InviteToken)
	if err != nil {
		return nil, fmt.Errorf("invalid invite token: %w", err)
	}

	// Check if invite is expired
	if time.Now().After(invite.ExpiresAt) {
		return nil, fmt.Errorf("invite has expired")
	}

	// Check if invite already accepted
	if invite.AcceptedAt != nil {
		return nil, fmt.Errorf("invite has already been accepted")
	}

	// Add user to team
	member := &entity.TeamMember{
		UserID:    req.UserID,
		TeamID:    invite.TeamID,
		RoleID:    invite.RoleID,
		JoinedAt:  time.Now(),
		InvitedBy: invite.InvitedBy,
		IsOwner:   false,
	}

	if err := s.teamRepo.AddMember(ctx, invite.TeamID, member); err != nil {
		return nil, fmt.Errorf("failed to add member to team: %w", err)
	}

	// Mark invite as accepted
	now := time.Now()
	invite.AcceptedAt = &now
	if err := s.teamRepo.UpdateInvite(ctx, invite); err != nil {
		return nil, fmt.Errorf("failed to update invite: %w", err)
	}

	response := dto.TeamMemberToResponse(member)
	return &response, nil
}

func (s *teamService) GetTeamInvites(ctx context.Context, teamID string) ([]dto.TeamInviteResponse, error) {
	invites, err := s.teamRepo.ListInvites(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team invites: %w", err)
	}

	var responses []dto.TeamInviteResponse
	for _, invite := range invites {
		responses = append(responses, dto.TeamInviteToResponse(invite))
	}

	return responses, nil
}

func (s *teamService) CancelTeamInvite(ctx context.Context, inviteID string, cancelledBy string) error {
	// Get invite
	invite, err := s.teamRepo.GetInvite(ctx, inviteID)
	if err != nil {
		return fmt.Errorf("failed to get invite: %w", err)
	}

	// Get team to check permissions
	team, err := s.teamRepo.GetByID(ctx, invite.TeamID)
	if err != nil {
		return fmt.Errorf("failed to get team: %w", err)
	}

	// Check permissions
	if !team.IsOwner(cancelledBy) && !s.hasTeamPermission(team, cancelledBy, "team:invites:cancel") && invite.InvitedBy != cancelledBy {
		return fmt.Errorf("insufficient permissions to cancel team invite")
	}

	// Delete invite
	return s.teamRepo.DeleteInvite(ctx, inviteID)
}

func (s *teamService) UpdateTeamSettings(ctx context.Context, teamID string, req dto.UpdateTeamSettingsRequest, updatedBy string) (*dto.TeamResponse, error) {
	// Get team
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	// Check permissions
	if !team.IsOwner(updatedBy) && !s.hasTeamPermission(team, updatedBy, "team:settings:update") {
		return nil, fmt.Errorf("insufficient permissions to update team settings")
	}

	// Update settings
	team.Settings = entity.TeamSettings{
		RequireMFA:               req.RequireMFA,
		AllowAPIKeys:             req.AllowAPIKeys,
		SecretRotationDays:       req.SecretRotationDays,
		SessionTimeoutMinutes:    req.SessionTimeoutMinutes,
		IPWhitelist:              req.IPWhitelist,
		AllowedDomains:           req.AllowedDomains,
		DefaultRoleID:            req.DefaultRoleID,
		EnforceSecretNaming:      req.EnforceSecretNaming,
		SecretNamingPattern:      req.SecretNamingPattern,
		AuditRetentionDays:       req.AuditRetentionDays,
		RequireApprovalForDelete: req.RequireApprovalForDelete,
		EnabledFeatures:          req.EnabledFeatures,
		WebhookURL:               req.WebhookURL,
		SlackWebhookURL:          req.SlackWebhookURL,
		NotificationEmails:       req.NotificationEmails,
	}

	// Update team
	if err := s.teamRepo.Update(ctx, team); err != nil {
		return nil, fmt.Errorf("failed to update team settings: %w", err)
	}

	// Log activity
	activity := &entity.TeamActivity{
		ID:           entity.GenerateUUID(),
		TeamID:       teamID,
		UserID:       updatedBy,
		Action:       entity.ActionSettingsUpdated,
		ResourceType: "team_settings",
		ResourceID:   teamID,
		Timestamp:    time.Now(),
	}
	s.teamRepo.LogActivity(ctx, activity)

	response := dto.TeamToResponse(team)
	return &response, nil
}

func (s *teamService) GetTeamStats(ctx context.Context, teamID string) (*dto.TeamStatsResponse, error) {
	stats, err := s.teamRepo.GetStats(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team stats: %w", err)
	}

	response := dto.TeamStatsToResponse(stats)
	return &response, nil
}

func (s *teamService) GetTeamActivities(ctx context.Context, teamID string, page, pageSize int) (*dto.ListTeamActivitiesResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	activities, err := s.teamRepo.GetActivities(ctx, teamID, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get team activities: %w", err)
	}

	var responses []dto.TeamActivityResponse
	for _, activity := range activities {
		responses = append(responses, dto.TeamActivityToResponse(activity))
	}

	// For simplicity, assume total equals returned count
	total := len(responses)
	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))

	return &dto.ListTeamActivitiesResponse{
		Activities: responses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}, nil
}

func (s *teamService) UpgradeTeamPlan(ctx context.Context, teamID string, req dto.UpgradePlanRequest, upgradedBy string) (*dto.TeamBillingResponse, error) {
	// Get team
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	// Check permissions (only owner can upgrade plan)
	if !team.IsOwner(upgradedBy) {
		return nil, fmt.Errorf("only team owner can upgrade plan")
	}

	// Upgrade plan
	if err := team.UpgradePlan(req.PlanType); err != nil {
		return nil, fmt.Errorf("failed to upgrade plan: %w", err)
	}

	// Update team
	if err := s.teamRepo.Update(ctx, team); err != nil {
		return nil, fmt.Errorf("failed to update team plan: %w", err)
	}

	// Log activity
	activity := &entity.TeamActivity{
		ID:           entity.GenerateUUID(),
		TeamID:       teamID,
		UserID:       upgradedBy,
		Action:       entity.ActionPlanUpgraded,
		ResourceType: "team_plan",
		ResourceID:   teamID,
		Details:      map[string]string{"new_plan": req.PlanType},
		Timestamp:    time.Now(),
	}
	s.teamRepo.LogActivity(ctx, activity)

	// Return billing response
	return s.GetTeamBilling(ctx, teamID)
}

func (s *teamService) GetTeamBilling(ctx context.Context, teamID string) (*dto.TeamBillingResponse, error) {
	team, err := s.teamRepo.GetByID(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("failed to get team: %w", err)
	}

	limits := entity.PlanLimits[team.BillingPlan]

	response := &dto.TeamBillingResponse{
		TeamID:         teamID,
		BillingPlan:    team.BillingPlan,
		SubscriptionID: team.SubscriptionID,
		TrialEndsAt:    team.TrialEndsAt,
		IsInTrial:      team.IsInTrial(),
	}

	response.Limits.Members = limits.Members
	response.Limits.Secrets = limits.Secrets
	response.Limits.APIKeys = limits.APIKeys
	response.Limits.StorageGB = limits.StorageGB
	response.Limits.AuditDays = limits.AuditDays

	response.Usage.Members = team.MemberCount
	response.Usage.Secrets = team.SecretCount
	response.Usage.StorageGB = int(team.StorageUsed / (1024 * 1024 * 1024))

	return response, nil
}

// Helper method to check team permissions
func (s *teamService) hasTeamPermission(team *entity.Team, userID, permission string) bool {
	// Get member
	member, err := team.GetMember(userID)
	if err != nil {
		return false
	}

	// Check member permissions
	for _, perm := range member.Permissions {
		if perm == permission {
			return true
		}
	}

	// TODO: Check role permissions when role service is available
	return false
}
