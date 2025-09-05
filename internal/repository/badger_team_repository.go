package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"PropGuard/internal/entity"
)

// BadgerTeamRepository implements team storage using BadgerDB
type BadgerTeamRepository struct {
	client *BadgerClient
}

// NewBadgerTeamRepository creates a new BadgerDB-based team repository
func NewBadgerTeamRepository(client *BadgerClient) *BadgerTeamRepository {
	return &BadgerTeamRepository{
		client: client,
	}
}

const (
	teamKeyPrefix         = "team:"
	teamNameKeyPrefix     = "teamname:"
	teamOwnerKeyPrefix    = "teamowner:"
	teamMemberKeyPrefix   = "teammember:"
	teamInviteKeyPrefix   = "teaminvite:"
	teamActivityKeyPrefix = "teamactivity:"
	teamIndexKey          = "teams:index"
)

// Create creates a new team
func (r *BadgerTeamRepository) Create(ctx context.Context, team *entity.Team) error {
	// Check if team name already exists
	if exists, _ := r.client.Exists(ctx, teamNameKeyPrefix+team.Name); exists {
		return fmt.Errorf("team name %s already exists", team.Name)
	}

	// Transaction to create team and indexes
	return r.client.Transaction(ctx, func(txn *Transaction) error {
		teamKey := teamKeyPrefix + team.ID

		// Serialize team
		teamData, err := json.Marshal(team)
		if err != nil {
			return fmt.Errorf("failed to marshal team: %w", err)
		}

		// Store team
		if err := txn.Set(teamKey, teamData); err != nil {
			return err
		}

		// Create name index
		if err := txn.Set(teamNameKeyPrefix+team.Name, []byte(team.ID)); err != nil {
			return err
		}

		// Create owner index
		ownerKey := teamOwnerKeyPrefix + team.OwnerID + ":" + team.ID
		if err := txn.Set(ownerKey, []byte(team.ID)); err != nil {
			return err
		}

		// Add to teams index
		indexData, _ := txn.Get(teamIndexKey)
		var teamIDs []string
		if indexData != nil {
			json.Unmarshal(indexData, &teamIDs)
		}
		teamIDs = append(teamIDs, team.ID)
		indexBytes, _ := json.Marshal(teamIDs)

		return txn.Set(teamIndexKey, indexBytes)
	})
}

// GetByID retrieves a team by ID
func (r *BadgerTeamRepository) GetByID(ctx context.Context, id string) (*entity.Team, error) {
	teamKey := teamKeyPrefix + id
	data, err := r.client.Get(ctx, teamKey)
	if err == ErrNotFound {
		return nil, fmt.Errorf("team with ID %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve team: %w", err)
	}

	var team entity.Team
	if err := json.Unmarshal(data, &team); err != nil {
		return nil, fmt.Errorf("failed to unmarshal team: %w", err)
	}

	return &team, nil
}

// GetByName retrieves a team by name
func (r *BadgerTeamRepository) GetByName(ctx context.Context, name string) (*entity.Team, error) {
	nameKey := teamNameKeyPrefix + name
	teamIDData, err := r.client.Get(ctx, nameKey)
	if err == ErrNotFound {
		return nil, fmt.Errorf("team with name %s not found", name)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve team by name: %w", err)
	}

	teamID := string(teamIDData)
	return r.GetByID(ctx, teamID)
}

// GetByOwnerID retrieves all teams owned by a user
func (r *BadgerTeamRepository) GetByOwnerID(ctx context.Context, ownerID string) ([]*entity.Team, error) {
	prefix := teamOwnerKeyPrefix + ownerID + ":"
	data, err := r.client.GetAll(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve teams by owner: %w", err)
	}

	var teams []*entity.Team
	for _, teamIDData := range data {
		teamID := string(teamIDData)
		if team, err := r.GetByID(ctx, teamID); err == nil {
			teams = append(teams, team)
		}
	}

	return teams, nil
}

// Update updates an existing team
func (r *BadgerTeamRepository) Update(ctx context.Context, team *entity.Team) error {
	// Check if team exists
	existingTeam, err := r.GetByID(ctx, team.ID)
	if err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		teamKey := teamKeyPrefix + team.ID

		// Update timestamp
		team.UpdatedAt = time.Now()

		// Serialize team
		teamData, err := json.Marshal(team)
		if err != nil {
			return fmt.Errorf("failed to marshal team: %w", err)
		}

		// Update team
		if err := txn.Set(teamKey, teamData); err != nil {
			return err
		}

		// Update name index if name changed
		if existingTeam.Name != team.Name {
			// Remove old name index
			if err := txn.Delete(teamNameKeyPrefix + existingTeam.Name); err != nil {
				return err
			}
			// Create new name index
			if err := txn.Set(teamNameKeyPrefix+team.Name, []byte(team.ID)); err != nil {
				return err
			}
		}

		return nil
	})
}

// Delete removes a team
func (r *BadgerTeamRepository) Delete(ctx context.Context, id string) error {
	// Get team first to clean up indexes
	team, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		teamKey := teamKeyPrefix + id

		// Delete team
		if err := txn.Delete(teamKey); err != nil {
			return err
		}

		// Delete name index
		if err := txn.Delete(teamNameKeyPrefix + team.Name); err != nil {
			return err
		}

		// Delete owner index
		ownerKey := teamOwnerKeyPrefix + team.OwnerID + ":" + team.ID
		if err := txn.Delete(ownerKey); err != nil {
			return err
		}

		// Remove from teams index
		indexData, _ := txn.Get(teamIndexKey)
		if indexData != nil {
			var teamIDs []string
			if json.Unmarshal(indexData, &teamIDs) == nil {
				var filteredIDs []string
				for _, teamID := range teamIDs {
					if teamID != id {
						filteredIDs = append(filteredIDs, teamID)
					}
				}
				indexBytes, _ := json.Marshal(filteredIDs)
				txn.Set(teamIndexKey, indexBytes)
			}
		}

		return nil
	})
}

// List retrieves teams with pagination
func (r *BadgerTeamRepository) List(ctx context.Context, limit, offset int) ([]*entity.Team, error) {
	// Get teams index
	indexData, err := r.client.Get(ctx, teamIndexKey)
	if err == ErrNotFound {
		return []*entity.Team{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve teams index: %w", err)
	}

	var teamIDs []string
	if err := json.Unmarshal(indexData, &teamIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal teams index: %w", err)
	}

	// Apply pagination
	start := offset
	if start < 0 || start >= len(teamIDs) {
		return []*entity.Team{}, nil
	}

	end := start + limit
	if end > len(teamIDs) {
		end = len(teamIDs)
	}

	var teams []*entity.Team
	for _, teamID := range teamIDs[start:end] {
		if team, err := r.GetByID(ctx, teamID); err == nil {
			teams = append(teams, team)
		}
	}

	return teams, nil
}

// Count returns the total number of teams
func (r *BadgerTeamRepository) Count(ctx context.Context) (int, error) {
	indexData, err := r.client.Get(ctx, teamIndexKey)
	if err == ErrNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve teams index: %w", err)
	}

	var teamIDs []string
	if err := json.Unmarshal(indexData, &teamIDs); err != nil {
		return 0, fmt.Errorf("failed to unmarshal teams index: %w", err)
	}

	return len(teamIDs), nil
}

// GetMemberTeams retrieves all teams where a user is a member
func (r *BadgerTeamRepository) GetMemberTeams(ctx context.Context, userID string) ([]*entity.Team, error) {
	prefix := teamMemberKeyPrefix + userID + ":"
	data, err := r.client.GetAll(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve member teams: %w", err)
	}

	var teams []*entity.Team
	for _, teamIDData := range data {
		teamID := string(teamIDData)
		if team, err := r.GetByID(ctx, teamID); err == nil {
			teams = append(teams, team)
		}
	}

	return teams, nil
}

// AddMember adds a member to a team
func (r *BadgerTeamRepository) AddMember(ctx context.Context, teamID string, member *entity.TeamMember) error {
	// Get team
	team, err := r.GetByID(ctx, teamID)
	if err != nil {
		return err
	}

	// Add member to team
	if err := team.AddMember(member.UserID, member.RoleID, member.InvitedBy); err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Update team with new member
		if err := r.Update(ctx, team); err != nil {
			return err
		}

		// Create member index
		memberKey := teamMemberKeyPrefix + member.UserID + ":" + teamID
		return txn.Set(memberKey, []byte(teamID))
	})
}

// RemoveMember removes a member from a team
func (r *BadgerTeamRepository) RemoveMember(ctx context.Context, teamID, userID string) error {
	// Get team
	team, err := r.GetByID(ctx, teamID)
	if err != nil {
		return err
	}

	// Remove member from team
	if err := team.RemoveMember(userID); err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Update team
		if err := r.Update(ctx, team); err != nil {
			return err
		}

		// Remove member index
		memberKey := teamMemberKeyPrefix + userID + ":" + teamID
		return txn.Delete(memberKey)
	})
}

// CreateInvite creates a team invitation
func (r *BadgerTeamRepository) CreateInvite(ctx context.Context, invite *entity.TeamInvite) error {
	inviteKey := teamInviteKeyPrefix + invite.ID

	inviteData, err := json.Marshal(invite)
	if err != nil {
		return fmt.Errorf("failed to marshal invite: %w", err)
	}

	return r.client.Set(ctx, inviteKey, inviteData)
}

// GetInvite retrieves a team invitation
func (r *BadgerTeamRepository) GetInvite(ctx context.Context, inviteID string) (*entity.TeamInvite, error) {
	inviteKey := teamInviteKeyPrefix + inviteID
	data, err := r.client.Get(ctx, inviteKey)
	if err == ErrNotFound {
		return nil, fmt.Errorf("invite with ID %s not found", inviteID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve invite: %w", err)
	}

	var invite entity.TeamInvite
	if err := json.Unmarshal(data, &invite); err != nil {
		return nil, fmt.Errorf("failed to unmarshal invite: %w", err)
	}

	return &invite, nil
}

// GetInviteByToken retrieves a team invitation by token
func (r *BadgerTeamRepository) GetInviteByToken(ctx context.Context, token string) (*entity.TeamInvite, error) {
	// We need to scan all invites to find the one with the matching token
	// This could be optimized with a token index if needed
	prefix := teamInviteKeyPrefix
	data, err := r.client.GetAll(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve invites: %w", err)
	}

	for _, inviteData := range data {
		var invite entity.TeamInvite
		if json.Unmarshal(inviteData, &invite) == nil {
			if invite.InviteToken == token {
				return &invite, nil
			}
		}
	}

	return nil, fmt.Errorf("invite with token not found")
}

// UpdateInvite updates a team invitation
func (r *BadgerTeamRepository) UpdateInvite(ctx context.Context, invite *entity.TeamInvite) error {
	inviteKey := teamInviteKeyPrefix + invite.ID

	inviteData, err := json.Marshal(invite)
	if err != nil {
		return fmt.Errorf("failed to marshal invite: %w", err)
	}

	return r.client.Set(ctx, inviteKey, inviteData)
}

// DeleteInvite removes a team invitation
func (r *BadgerTeamRepository) DeleteInvite(ctx context.Context, inviteID string) error {
	inviteKey := teamInviteKeyPrefix + inviteID
	return r.client.Delete(ctx, inviteKey)
}

// ListInvites retrieves all invitations for a team
func (r *BadgerTeamRepository) ListInvites(ctx context.Context, teamID string) ([]*entity.TeamInvite, error) {
	prefix := teamInviteKeyPrefix
	data, err := r.client.GetAll(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve invites: %w", err)
	}

	var invites []*entity.TeamInvite
	for _, inviteData := range data {
		var invite entity.TeamInvite
		if json.Unmarshal(inviteData, &invite) == nil {
			if invite.TeamID == teamID {
				invites = append(invites, &invite)
			}
		}
	}

	return invites, nil
}

// LogActivity logs a team activity
func (r *BadgerTeamRepository) LogActivity(ctx context.Context, activity *entity.TeamActivity) error {
	activityKey := teamActivityKeyPrefix + activity.ID

	activityData, err := json.Marshal(activity)
	if err != nil {
		return fmt.Errorf("failed to marshal activity: %w", err)
	}

	return r.client.Set(ctx, activityKey, activityData)
}

// GetActivities retrieves team activities with pagination
func (r *BadgerTeamRepository) GetActivities(ctx context.Context, teamID string, limit, offset int) ([]*entity.TeamActivity, error) {
	prefix := teamActivityKeyPrefix
	data, err := r.client.GetAll(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve activities: %w", err)
	}

	var activities []*entity.TeamActivity
	for _, activityData := range data {
		var activity entity.TeamActivity
		if json.Unmarshal(activityData, &activity) == nil {
			if activity.TeamID == teamID {
				activities = append(activities, &activity)
			}
		}
	}

	// Sort activities by timestamp (newest first)
	// Apply pagination
	start := offset
	if start < 0 || start >= len(activities) {
		return []*entity.TeamActivity{}, nil
	}

	end := start + limit
	if end > len(activities) {
		end = len(activities)
	}

	return activities[start:end], nil
}

// GetStats calculates team statistics
func (r *BadgerTeamRepository) GetStats(ctx context.Context, teamID string) (*entity.TeamStats, error) {
	team, err := r.GetByID(ctx, teamID)
	if err != nil {
		return nil, err
	}

	stats := &entity.TeamStats{
		TeamID:           teamID,
		TotalMembers:     team.MemberCount,
		TotalSecrets:     team.SecretCount,
		StorageUsedBytes: team.StorageUsed,
		LastActivityAt:   team.LastActivityAt,
		CalculatedAt:     time.Now(),
	}

	return stats, nil
}

// SearchTeams searches teams by name pattern
func (r *BadgerTeamRepository) SearchTeams(ctx context.Context, query string, limit, offset int) ([]*entity.Team, error) {
	// Get all teams
	teams, err := r.List(ctx, -1, 0) // Get all teams
	if err != nil {
		return nil, err
	}

	// Filter teams by name containing query
	var filteredTeams []*entity.Team
	query = strings.ToLower(query)
	for _, team := range teams {
		if strings.Contains(strings.ToLower(team.Name), query) ||
			strings.Contains(strings.ToLower(team.Description), query) {
			filteredTeams = append(filteredTeams, team)
		}
	}

	// Apply pagination
	start := offset
	if start < 0 || start >= len(filteredTeams) {
		return []*entity.Team{}, nil
	}

	end := start + limit
	if end > len(filteredTeams) {
		end = len(filteredTeams)
	}

	return filteredTeams[start:end], nil
}
