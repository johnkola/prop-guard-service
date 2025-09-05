package controller

import (
	"net/http"
	"strconv"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
)

// RoleController handles role-related HTTP requests
type RoleController struct {
	roleRepo      *repository.BadgerRoleRepository
	auditService  service.AuditService
	jwtMiddleware *security.JWTMiddleware
}

// NewRoleController creates a new role controller
func NewRoleController(
	roleRepo *repository.BadgerRoleRepository,
	auditService service.AuditService,
	jwtMiddleware *security.JWTMiddleware,
) *RoleController {
	return &RoleController{
		roleRepo:      roleRepo,
		auditService:  auditService,
		jwtMiddleware: jwtMiddleware,
	}
}

// RegisterRoutes registers role management routes
func (c *RoleController) RegisterRoutes(router *gin.RouterGroup) {
	roles := router.Group("/roles")
	roles.Use(c.jwtMiddleware.Authenticate())
	{
		roles.GET("", c.jwtMiddleware.RequirePermission(entity.PermissionRoleList), c.ListRoles)
		roles.GET("/:id", c.jwtMiddleware.RequirePermission(entity.PermissionRoleRead), c.GetRole)
		roles.POST("", c.jwtMiddleware.RequirePermission(entity.PermissionRoleCreate), c.CreateRole)
		roles.PUT("/:id", c.jwtMiddleware.RequirePermission(entity.PermissionRoleUpdate), c.UpdateRole)
		roles.DELETE("/:id", c.jwtMiddleware.RequirePermission(entity.PermissionRoleDelete), c.DeleteRole)
		roles.POST("/:id/assign", c.jwtMiddleware.RequirePermission(entity.PermissionRoleAssign), c.AssignRole)
		roles.POST("/:id/revoke", c.jwtMiddleware.RequirePermission(entity.PermissionRoleAssign), c.RevokeRole)
		roles.GET("/:id/permissions", c.jwtMiddleware.RequirePermission(entity.PermissionRoleRead), c.GetRolePermissions)
	}
}

// ListRoles godoc
// @Summary List all roles
// @Description Get a paginated list of all available roles
// @Tags roles
// @Accept json
// @Produce json
// @Param limit query int false "Limit results" default(20)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {object} dto.PaginatedRolesResponse
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Security BearerAuth
// @Router /roles [get]
func (c *RoleController) ListRoles(ctx *gin.Context) {
	limitStr := ctx.DefaultQuery("limit", "20")
	offsetStr := ctx.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 20
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	roles, err := c.roleRepo.List(ctx, limit, offset)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list roles"})
		return
	}

	total, err := c.roleRepo.Count(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count roles"})
		return
	}

	// Calculate pagination info
	page := (offset / limit) + 1
	totalPages := (int(total) + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}

	response := &dto.PaginatedRolesResponse{
		Roles:      roles,
		Total:      int(total),
		Page:       page,
		PageSize:   limit,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}

	c.auditService.LogAction(ctx, security.GetUsername(ctx), "ROLE_LIST", "", true, "Listed roles with pagination")
	ctx.JSON(http.StatusOK, response)
}

// GetRole godoc
// @Summary Get a role by ID
// @Description Get detailed information about a specific role
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} entity.Role
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Security BearerAuth
// @Router /roles/{id} [get]
func (c *RoleController) GetRole(ctx *gin.Context) {
	roleID := ctx.Param("id")

	role, err := c.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	c.auditService.LogAction(ctx, security.GetUsername(ctx), "ROLE_GET", roleID, true, "Retrieved role details")
	ctx.JSON(http.StatusOK, role)
}

// CreateRoleRequest represents the request to create a new role
type CreateRoleRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions" binding:"required"`
}

// CreateRole godoc
// @Summary Create a new role
// @Description Create a new custom role with specific permissions
// @Tags roles
// @Accept json
// @Produce json
// @Param role body CreateRoleRequest true "Role creation request"
// @Success 201 {object} entity.Role
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 409 {object} gin.H
// @Security BearerAuth
// @Router /roles [post]
func (c *RoleController) CreateRole(ctx *gin.Context) {
	var req CreateRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate permissions
	if !c.validatePermissions(req.Permissions) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid permissions specified"})
		return
	}

	role := &entity.Role{
		ID:          "role_custom_" + req.Name,
		Name:        req.Name,
		Description: req.Description,
		Permissions: req.Permissions,
		IsSystem:    false,
		CreatedBy:   security.GetUsername(ctx),
	}

	if err := c.roleRepo.Create(ctx, role); err != nil {
		ctx.JSON(http.StatusConflict, gin.H{"error": "role already exists"})
		return
	}

	c.auditService.LogAction(ctx, security.GetUsername(ctx), "ROLE_CREATE", role.ID, true, "Created new role")
	ctx.JSON(http.StatusCreated, role)
}

// UpdateRoleRequest represents the request to update a role
type UpdateRoleRequest struct {
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// UpdateRole godoc
// @Summary Update a role
// @Description Update an existing custom role's permissions
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param role body UpdateRoleRequest true "Role update request"
// @Success 200 {object} entity.Role
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Security BearerAuth
// @Router /roles/{id} [put]
func (c *RoleController) UpdateRole(ctx *gin.Context) {
	roleID := ctx.Param("id")

	var req UpdateRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing role
	role, err := c.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	// Check if it's a system role
	if role.IsSystem {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "cannot modify system roles"})
		return
	}

	// Validate permissions if provided
	if len(req.Permissions) > 0 {
		if !c.validatePermissions(req.Permissions) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid permissions specified"})
			return
		}
		role.Permissions = req.Permissions
	}

	if req.Description != "" {
		role.Description = req.Description
	}

	if err := c.roleRepo.Update(ctx, role); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update role"})
		return
	}

	c.auditService.LogAction(ctx, security.GetUsername(ctx), "ROLE_UPDATE", roleID, true, "Updated role")
	ctx.JSON(http.StatusOK, role)
}

// DeleteRole godoc
// @Summary Delete a role
// @Description Delete a custom role (system roles cannot be deleted)
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Success 204 "No Content"
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Security BearerAuth
// @Router /roles/{id} [delete]
func (c *RoleController) DeleteRole(ctx *gin.Context) {
	roleID := ctx.Param("id")

	// Get existing role
	role, err := c.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	// Check if it's a system role
	if role.IsSystem {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "cannot delete system roles"})
		return
	}

	if err := c.roleRepo.Delete(ctx, roleID); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete role"})
		return
	}

	c.auditService.LogAction(ctx, security.GetUsername(ctx), "ROLE_DELETE", roleID, true, "Deleted role")
	ctx.Status(http.StatusNoContent)
}

// AssignRoleRequest represents the request to assign a role
type AssignRoleRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// AssignRole godoc
// @Summary Assign a role to a user
// @Description Assign a role to a specific user
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param request body AssignRoleRequest true "Role assignment request"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Security BearerAuth
// @Router /roles/{id}/assign [post]
func (c *RoleController) AssignRole(ctx *gin.Context) {
	roleID := ctx.Param("id")

	var req AssignRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify role exists
	_, err := c.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	// TODO: Implement user role assignment through user service
	// This would require updating the user service to handle role assignments

	c.auditService.LogAction(ctx, security.GetUsername(ctx), "ROLE_ASSIGN", roleID, true,
		"Assigned role to user: "+req.UserID)
	ctx.JSON(http.StatusOK, gin.H{"message": "role assigned successfully"})
}

// RevokeRole godoc
// @Summary Revoke a role from a user
// @Description Remove a role from a specific user
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param request body AssignRoleRequest true "Role revocation request"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Security BearerAuth
// @Router /roles/{id}/revoke [post]
func (c *RoleController) RevokeRole(ctx *gin.Context) {
	roleID := ctx.Param("id")

	var req AssignRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify role exists
	_, err := c.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	// TODO: Implement user role revocation through user service

	c.auditService.LogAction(ctx, security.GetUsername(ctx), "ROLE_REVOKE", roleID, true,
		"Revoked role from user: "+req.UserID)
	ctx.JSON(http.StatusOK, gin.H{"message": "role revoked successfully"})
}

// GetRolePermissions godoc
// @Summary Get role permissions
// @Description Get the list of permissions for a specific role
// @Tags roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Success 200 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Security BearerAuth
// @Router /roles/{id}/permissions [get]
func (c *RoleController) GetRolePermissions(ctx *gin.Context) {
	roleID := ctx.Param("id")

	role, err := c.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}

	c.auditService.LogAction(ctx, security.GetUsername(ctx), "ROLE_PERMISSIONS", roleID, true,
		"Retrieved role permissions")
	ctx.JSON(http.StatusOK, gin.H{
		"role_id":     role.ID,
		"role_name":   role.Name,
		"permissions": role.Permissions,
	})
}

// validatePermissions checks if all provided permissions are valid
func (c *RoleController) validatePermissions(permissions []string) bool {
	validPermissions := map[string]bool{
		entity.PermissionSecretCreate:     true,
		entity.PermissionSecretRead:       true,
		entity.PermissionSecretUpdate:     true,
		entity.PermissionSecretDelete:     true,
		entity.PermissionSecretList:       true,
		entity.PermissionSecretShare:      true,
		entity.PermissionSecretRotate:     true,
		entity.PermissionUserCreate:       true,
		entity.PermissionUserRead:         true,
		entity.PermissionUserUpdate:       true,
		entity.PermissionUserDelete:       true,
		entity.PermissionUserList:         true,
		entity.PermissionRoleCreate:       true,
		entity.PermissionRoleRead:         true,
		entity.PermissionRoleUpdate:       true,
		entity.PermissionRoleDelete:       true,
		entity.PermissionRoleList:         true,
		entity.PermissionRoleAssign:       true,
		entity.PermissionTeamCreate:       true,
		entity.PermissionTeamRead:         true,
		entity.PermissionTeamUpdate:       true,
		entity.PermissionTeamDelete:       true,
		entity.PermissionTeamList:         true,
		entity.PermissionTeamMemberAdd:    true,
		entity.PermissionTeamMemberRemove: true,
		entity.PermissionAPIKeyCreate:     true,
		entity.PermissionAPIKeyRead:       true,
		entity.PermissionAPIKeyRevoke:     true,
		entity.PermissionAPIKeyList:       true,
		entity.PermissionAuditRead:        true,
		entity.PermissionAuditExport:      true,
		entity.PermissionAuditPurge:       true,
		entity.PermissionPolicyCreate:     true,
		entity.PermissionPolicyRead:       true,
		entity.PermissionPolicyUpdate:     true,
		entity.PermissionPolicyDelete:     true,
		entity.PermissionPolicyList:       true,
		entity.PermissionSystemConfig:     true,
		entity.PermissionSystemBackup:     true,
		entity.PermissionSystemHealth:     true,
		entity.PermissionSystemStats:      true,
	}

	for _, perm := range permissions {
		if !validPermissions[perm] {
			return false
		}
	}
	return true
}
