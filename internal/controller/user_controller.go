package controller

import (
	"net/http"
	"strconv"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type UserController struct {
	userService   service.UserService
	jwtMiddleware *security.JWTMiddleware
}

func NewUserController(userService service.UserService, jwtMiddleware *security.JWTMiddleware) *UserController {
	return &UserController{
		userService:   userService,
		jwtMiddleware: jwtMiddleware,
	}
}

// RegisterRoutes registers user management routes
func (c *UserController) RegisterRoutes(router *gin.RouterGroup) {
	users := router.Group("/users")
	users.Use(c.jwtMiddleware.Authenticate())
	{
		users.POST("", c.jwtMiddleware.RequireRole("role_admin"), c.CreateUser)
		users.GET("", c.jwtMiddleware.RequireRole("role_admin"), c.ListUsers)
		users.GET("/:id", c.jwtMiddleware.RequireRole("role_admin"), c.GetUser)
		users.PUT("/:id", c.jwtMiddleware.RequireRole("role_admin"), c.UpdateUser)
		users.DELETE("/:id", c.jwtMiddleware.RequireRole("role_admin"), c.DeleteUser)
		users.PUT("/:id/password", c.ChangePassword) // Users can change their own password
		users.PUT("/:id/reset-password", c.jwtMiddleware.RequireRole("role_admin"), c.ResetPassword)

		// System user routes
		system := users.Group("/system")
		system.Use(c.jwtMiddleware.RequireRole("role_admin"))
		{
			system.POST("", c.CreateSystemUser)
		}
	}
}

// CreateUser godoc
// @Summary Create a new user
// @Description Create a new vault user with specified roles and policies
// @Tags users
// @Accept json
// @Produce json
// @Param user body dto.CreateUserRequest true "User creation request"
// @Success 201 {object} dto.UserResponse
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /users [post]
func (c *UserController) CreateUser(ctx *gin.Context) {
	var req dto.CreateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username := c.getUsernameFromContext(ctx)
	user, err := c.userService.CreateUser(ctx.Request.Context(), req, username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, user)
}

// GetUser godoc
// @Summary Get user by ID
// @Description Get a specific user by their ID
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} dto.UserResponse
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Security BearerAuth
// @Router /users/{id} [get]
func (c *UserController) GetUser(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	user, err := c.userService.GetUser(ctx.Request.Context(), id)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// ListUsers godoc
// @Summary List all users
// @Description Get a paginated list of all users
// @Tags users
// @Accept json
// @Produce json
// @Param page query int false "Page number (default: 1)"
// @Param pageSize query int false "Page size (default: 20, max: 100)"
// @Success 200 {object} dto.ListUsersResponse
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /users [get]
func (c *UserController) ListUsers(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("pageSize", "20"))

	users, err := c.userService.ListUsers(ctx.Request.Context(), page, pageSize)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, users)
}

// UpdateUser godoc
// @Summary Update user
// @Description Update user properties, roles, and policies
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param user body dto.UpdateUserRequest true "User update request"
// @Success 200 {object} dto.UserResponse
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /users/{id} [put]
func (c *UserController) UpdateUser(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	var req dto.UpdateUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username := c.getUsernameFromContext(ctx)
	user, err := c.userService.UpdateUser(ctx.Request.Context(), id, req, username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// DeleteUser godoc
// @Summary Delete user
// @Description Delete a user (system users cannot be deleted)
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 204
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /users/{id} [delete]
func (c *UserController) DeleteUser(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	username := c.getUsernameFromContext(ctx)
	if err := c.userService.DeleteUser(ctx.Request.Context(), id, username); err != nil {
		if err.Error() == "cannot delete system user" {
			ctx.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// ChangePassword godoc
// @Summary Change user password
// @Description Change user's password (users can change their own password)
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param password body dto.ChangePasswordRequest true "Password change request"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /users/{id}/password [put]
func (c *UserController) ChangePassword(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	// Users can only change their own password unless they are admin
	username := c.getUsernameFromContext(ctx)
	currentUser, err := c.userService.GetUserByUsername(ctx.Request.Context(), username)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user"})
		return
	}

	// Allow if user is changing their own password or if they have admin role
	if currentUser.ID != id && !currentUser.HasRoleID("role_admin") {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "Cannot change other user's password"})
		return
	}

	var req dto.ChangePasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := c.userService.ChangePassword(ctx.Request.Context(), id, req, username); err != nil {
		if err.Error() == "current password is incorrect" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// ResetPassword godoc
// @Summary Reset user password
// @Description Reset user's password (admin only)
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param password body dto.ResetPasswordRequest true "Password reset request"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /users/{id}/reset-password [put]
func (c *UserController) ResetPassword(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID format"})
		return
	}

	var req dto.ResetPasswordRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username := c.getUsernameFromContext(ctx)
	if err := c.userService.ResetPassword(ctx.Request.Context(), id, req, username); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// CreateSystemUser godoc
// @Summary Create system user
// @Description Create a system user with specified roles (root only)
// @Tags users
// @Accept json
// @Produce json
// @Param user body gin.H true "System user request with username and roles"
// @Success 201 {object} dto.UserResponse
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /users/system [post]
func (c *UserController) CreateSystemUser(ctx *gin.Context) {
	var req struct {
		Username string             `json:"username" binding:"required"`
		Roles    []entity.VaultRole `json:"roles" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := c.userService.CreateSystemUser(ctx.Request.Context(), req.Username, req.Roles)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, user)
}

func (c *UserController) getUsernameFromContext(ctx *gin.Context) string {
	return security.GetUsername(ctx)
}

func hasRole(userRoles []entity.VaultRole, targetRole entity.VaultRole) bool {
	for _, role := range userRoles {
		if role == targetRole {
			return true
		}
	}
	return false
}
