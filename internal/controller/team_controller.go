package controller

import (
	"net/http"
	"strconv"

	"PropGuard/internal/dto"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
)

type TeamController struct {
	teamService   service.TeamService
	jwtMiddleware *security.JWTMiddleware
}

func NewTeamController(teamService service.TeamService, jwtMiddleware *security.JWTMiddleware) *TeamController {
	return &TeamController{
		teamService:   teamService,
		jwtMiddleware: jwtMiddleware,
	}
}

// RegisterRoutes registers team management routes
func (c *TeamController) RegisterRoutes(router *gin.RouterGroup) {
	teams := router.Group("/teams")
	teams.Use(c.jwtMiddleware.Authenticate())
	{
		// Team CRUD operations
		teams.POST("", c.CreateTeam)
		teams.GET("", c.ListTeams)
		teams.GET("/search", c.SearchTeams)
		teams.GET("/:id", c.GetTeam)
		teams.PUT("/:id", c.UpdateTeam)
		teams.DELETE("/:id", c.DeleteTeam)

		// Team member management
		teams.GET("/:id/members", c.GetTeamMembers)
		teams.POST("/:id/members", c.AddTeamMember)
		teams.PUT("/:id/members/:userID", c.UpdateTeamMember)
		teams.DELETE("/:id/members/:userID", c.RemoveTeamMember)

		// Team invitations
		teams.GET("/:id/invites", c.GetTeamInvites)
		teams.POST("/:id/invites", c.CreateTeamInvite)
		teams.DELETE("/:id/invites/:inviteID", c.CancelTeamInvite)
		teams.POST("/invites/accept", c.AcceptTeamInvite)

		// Team settings
		teams.PUT("/:id/settings", c.UpdateTeamSettings)

		// Team stats and activity
		teams.GET("/:id/stats", c.GetTeamStats)
		teams.GET("/:id/activities", c.GetTeamActivities)

		// Team billing
		teams.GET("/:id/billing", c.GetTeamBilling)
		teams.POST("/:id/billing/upgrade", c.UpgradeTeamPlan)

		// User's teams
		teams.GET("/user/:userID", c.GetUserTeams)
	}
}

// CreateTeam godoc
// @Summary Create a new team
// @Description Creates a new team with the authenticated user as owner
// @Tags teams
// @Accept json
// @Produce json
// @Param team body dto.CreateTeamRequest true "Team creation request"
// @Success 201 {object} dto.TeamResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams [post]
func (c *TeamController) CreateTeam(ctx *gin.Context) {
	var req dto.CreateTeamRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	// Get current user from context
	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	team, err := c.teamService.CreateTeam(ctx, req, username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create team", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, team)
}

// ListTeams godoc
// @Summary List teams
// @Description Get a paginated list of teams
// @Tags teams
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(20)
// @Success 200 {object} dto.ListTeamsResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams [get]
func (c *TeamController) ListTeams(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("pageSize", "20"))

	teams, err := c.teamService.ListTeams(ctx, page, pageSize)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list teams", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, teams)
}

// SearchTeams godoc
// @Summary Search teams
// @Description Search teams by name or description
// @Tags teams
// @Accept json
// @Produce json
// @Param query query string true "Search query"
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(20)
// @Success 200 {object} dto.ListTeamsResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/search [get]
func (c *TeamController) SearchTeams(ctx *gin.Context) {
	var req dto.SearchTeamsRequest
	if err := ctx.ShouldBindQuery(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid search parameters", "details": err.Error()})
		return
	}

	teams, err := c.teamService.SearchTeams(ctx, req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search teams", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, teams)
}

// GetTeam godoc
// @Summary Get team by ID
// @Description Get team details by ID
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Success 200 {object} dto.TeamResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id} [get]
func (c *TeamController) GetTeam(ctx *gin.Context) {
	teamID := ctx.Param("id")

	team, err := c.teamService.GetTeam(ctx, teamID)
	if err != nil {
		if err.Error() == "team not found" {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Team not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get team", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, team)
}

// UpdateTeam godoc
// @Summary Update team
// @Description Update team information
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param team body dto.UpdateTeamRequest true "Team update request"
// @Success 200 {object} dto.TeamResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id} [put]
func (c *TeamController) UpdateTeam(ctx *gin.Context) {
	teamID := ctx.Param("id")
	var req dto.UpdateTeamRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	team, err := c.teamService.UpdateTeam(ctx, teamID, req, username)
	if err != nil {
		if err.Error() == "insufficient permissions to update team" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update team", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, team)
}

// DeleteTeam godoc
// @Summary Delete team
// @Description Delete a team (only owner can delete)
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Success 204
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id} [delete]
func (c *TeamController) DeleteTeam(ctx *gin.Context) {
	teamID := ctx.Param("id")

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	err := c.teamService.DeleteTeam(ctx, teamID, username)
	if err != nil {
		if err.Error() == "only team owner can delete team" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Only team owner can delete team"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete team", "details": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// GetTeamMembers godoc
// @Summary Get team members
// @Description Get all members of a team
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Success 200 {array} dto.TeamMemberResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/members [get]
func (c *TeamController) GetTeamMembers(ctx *gin.Context) {
	teamID := ctx.Param("id")

	members, err := c.teamService.GetTeamMembers(ctx, teamID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get team members", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, members)
}

// AddTeamMember godoc
// @Summary Add team member
// @Description Add a user to a team
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param member body dto.AddTeamMemberRequest true "Add member request"
// @Success 201 {object} dto.TeamMemberResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/members [post]
func (c *TeamController) AddTeamMember(ctx *gin.Context) {
	teamID := ctx.Param("id")
	var req dto.AddTeamMemberRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	member, err := c.teamService.AddTeamMember(ctx, teamID, req, username)
	if err != nil {
		if err.Error() == "insufficient permissions to add team member" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add team member", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, member)
}

// UpdateTeamMember godoc
// @Summary Update team member
// @Description Update a team member's role or permissions
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param userID path string true "User ID"
// @Param member body dto.UpdateTeamMemberRequest true "Update member request"
// @Success 200 {object} dto.TeamMemberResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/members/{userID} [put]
func (c *TeamController) UpdateTeamMember(ctx *gin.Context) {
	teamID := ctx.Param("id")
	userID := ctx.Param("userID")
	var req dto.UpdateTeamMemberRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	member, err := c.teamService.UpdateTeamMember(ctx, teamID, userID, req, username)
	if err != nil {
		if err.Error() == "insufficient permissions to update team member" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update team member", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, member)
}

// RemoveTeamMember godoc
// @Summary Remove team member
// @Description Remove a user from a team
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param userID path string true "User ID"
// @Success 204
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/members/{userID} [delete]
func (c *TeamController) RemoveTeamMember(ctx *gin.Context) {
	teamID := ctx.Param("id")
	userID := ctx.Param("userID")

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	err := c.teamService.RemoveTeamMember(ctx, teamID, userID, username)
	if err != nil {
		if err.Error() == "insufficient permissions to remove team member" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove team member", "details": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// GetTeamInvites godoc
// @Summary Get team invites
// @Description Get all pending invitations for a team
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Success 200 {array} dto.TeamInviteResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/invites [get]
func (c *TeamController) GetTeamInvites(ctx *gin.Context) {
	teamID := ctx.Param("id")

	invites, err := c.teamService.GetTeamInvites(ctx, teamID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get team invites", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, invites)
}

// CreateTeamInvite godoc
// @Summary Create team invite
// @Description Create an invitation for someone to join the team
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param invite body dto.CreateTeamInviteRequest true "Invite creation request"
// @Success 201 {object} dto.TeamInviteResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/invites [post]
func (c *TeamController) CreateTeamInvite(ctx *gin.Context) {
	teamID := ctx.Param("id")
	var req dto.CreateTeamInviteRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	invite, err := c.teamService.CreateTeamInvite(ctx, teamID, req, username)
	if err != nil {
		if err.Error() == "insufficient permissions to create team invite" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create team invite", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, invite)
}

// AcceptTeamInvite godoc
// @Summary Accept team invite
// @Description Accept an invitation to join a team
// @Tags teams
// @Accept json
// @Produce json
// @Param invite body dto.AcceptInviteRequest true "Accept invite request"
// @Success 201 {object} dto.TeamMemberResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/invites/accept [post]
func (c *TeamController) AcceptTeamInvite(ctx *gin.Context) {
	var req dto.AcceptInviteRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	member, err := c.teamService.AcceptTeamInvite(ctx, req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to accept team invite", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, member)
}

// CancelTeamInvite godoc
// @Summary Cancel team invite
// @Description Cancel a pending team invitation
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param inviteID path string true "Invite ID"
// @Success 204
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/invites/{inviteID} [delete]
func (c *TeamController) CancelTeamInvite(ctx *gin.Context) {
	inviteID := ctx.Param("inviteID")

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	err := c.teamService.CancelTeamInvite(ctx, inviteID, username)
	if err != nil {
		if err.Error() == "insufficient permissions to cancel team invite" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel team invite", "details": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// UpdateTeamSettings godoc
// @Summary Update team settings
// @Description Update team settings and configuration
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param settings body dto.UpdateTeamSettingsRequest true "Settings update request"
// @Success 200 {object} dto.TeamResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/settings [put]
func (c *TeamController) UpdateTeamSettings(ctx *gin.Context) {
	teamID := ctx.Param("id")
	var req dto.UpdateTeamSettingsRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	team, err := c.teamService.UpdateTeamSettings(ctx, teamID, req, username)
	if err != nil {
		if err.Error() == "insufficient permissions to update team settings" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update team settings", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, team)
}

// GetTeamStats godoc
// @Summary Get team statistics
// @Description Get usage statistics for a team
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Success 200 {object} dto.TeamStatsResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/stats [get]
func (c *TeamController) GetTeamStats(ctx *gin.Context) {
	teamID := ctx.Param("id")

	stats, err := c.teamService.GetTeamStats(ctx, teamID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get team stats", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, stats)
}

// GetTeamActivities godoc
// @Summary Get team activities
// @Description Get team activity history with pagination
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(20)
// @Success 200 {object} dto.ListTeamActivitiesResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/activities [get]
func (c *TeamController) GetTeamActivities(ctx *gin.Context) {
	teamID := ctx.Param("id")
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("pageSize", "20"))

	activities, err := c.teamService.GetTeamActivities(ctx, teamID, page, pageSize)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get team activities", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, activities)
}

// GetTeamBilling godoc
// @Summary Get team billing information
// @Description Get billing and subscription information for a team
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Success 200 {object} dto.TeamBillingResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/billing [get]
func (c *TeamController) GetTeamBilling(ctx *gin.Context) {
	teamID := ctx.Param("id")

	billing, err := c.teamService.GetTeamBilling(ctx, teamID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get team billing", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, billing)
}

// UpgradeTeamPlan godoc
// @Summary Upgrade team plan
// @Description Upgrade a team's billing plan
// @Tags teams
// @Accept json
// @Produce json
// @Param id path string true "Team ID"
// @Param plan body dto.UpgradePlanRequest true "Plan upgrade request"
// @Success 200 {object} dto.TeamBillingResponse
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/{id}/billing/upgrade [post]
func (c *TeamController) UpgradeTeamPlan(ctx *gin.Context) {
	teamID := ctx.Param("id")
	var req dto.UpgradePlanRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body", "details": err.Error()})
		return
	}

	username := security.GetUsername(ctx)
	if username == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
		return
	}

	billing, err := c.teamService.UpgradeTeamPlan(ctx, teamID, req, username)
	if err != nil {
		if err.Error() == "only team owner can upgrade plan" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Only team owner can upgrade plan"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upgrade team plan", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, billing)
}

// GetUserTeams godoc
// @Summary Get user's teams
// @Description Get all teams where a user is owner or member
// @Tags teams
// @Accept json
// @Produce json
// @Param userID path string true "User ID"
// @Success 200 {array} dto.TeamResponse
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/teams/user/{userID} [get]
func (c *TeamController) GetUserTeams(ctx *gin.Context) {
	userID := ctx.Param("userID")

	teams, err := c.teamService.GetUserTeams(ctx, userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user teams", "details": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, teams)
}
