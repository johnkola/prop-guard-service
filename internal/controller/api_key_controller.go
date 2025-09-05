package controller

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"PropGuard/internal/dto"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
)

type APIKeyController struct {
	apiKeyService service.APIKeyService
	jwtMiddleware *security.JWTMiddleware
}

func NewAPIKeyController(apiKeyService service.APIKeyService, jwtMiddleware *security.JWTMiddleware) *APIKeyController {
	return &APIKeyController{
		apiKeyService: apiKeyService,
		jwtMiddleware: jwtMiddleware,
	}
}

// RegisterRoutes registers API key routes
func (c *APIKeyController) RegisterRoutes(router *gin.RouterGroup) {
	apiKeys := router.Group("/api-keys")
	apiKeys.Use(c.jwtMiddleware.Authenticate())
	{
		// User API keys
		apiKeys.POST("", c.CreateAPIKey)
		apiKeys.GET("", c.ListAPIKeys)
		apiKeys.GET("/:id", c.GetAPIKey)
		apiKeys.PUT("/:id", c.UpdateAPIKey)
		apiKeys.DELETE("/:id", c.DeleteAPIKey)
		apiKeys.POST("/:id/revoke", c.RevokeAPIKey)
		apiKeys.POST("/:id/regenerate", c.RegenerateAPIKey)
		apiKeys.GET("/:id/usage", c.GetUsageStats)

		// Team API keys
		apiKeys.POST("/team/:teamId", c.CreateTeamAPIKey)
		apiKeys.GET("/team/:teamId", c.ListTeamAPIKeys)
	}
}

// CreateAPIKey creates a new API key
// @Summary Create API key
// @Description Create a new API key for the authenticated user
// @Tags api-keys
// @Accept json
// @Produce json
// @Param request body dto.CreateAPIKeyRequest true "API key creation request"
// @Success 201 {object} dto.CreateAPIKeyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/api-keys [post]
func (c *APIKeyController) CreateAPIKey(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	var req dto.CreateAPIKeyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(err))
		return
	}

	apiKey, err := c.apiKeyService.CreateAPIKey(ctx.Request.Context(), &req, userID.(string))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		return
	}

	ctx.JSON(http.StatusCreated, apiKey)
}

// GetAPIKey retrieves an API key by ID
// @Summary Get API key
// @Description Get an API key by ID
// @Tags api-keys
// @Produce json
// @Param id path string true "API key ID"
// @Success 200 {object} dto.APIKeyResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /api/v1/api-keys/{id} [get]
func (c *APIKeyController) GetAPIKey(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	keyID := ctx.Param("id")
	if keyID == "" {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(
			fmt.Errorf("API key ID is required")))
		return
	}

	apiKey, err := c.apiKeyService.GetAPIKey(ctx.Request.Context(), keyID, userID.(string))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, dto.NewErrorResponse(err))
		} else {
			ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		}
		return
	}

	ctx.JSON(http.StatusOK, apiKey)
}

// UpdateAPIKey updates an API key
// @Summary Update API key
// @Description Update an API key
// @Tags api-keys
// @Accept json
// @Produce json
// @Param id path string true "API key ID"
// @Param request body dto.UpdateAPIKeyRequest true "API key update request"
// @Success 200 {object} dto.APIKeyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /api/v1/api-keys/{id} [put]
func (c *APIKeyController) UpdateAPIKey(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	keyID := ctx.Param("id")
	if keyID == "" {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(
			fmt.Errorf("API key ID is required")))
		return
	}

	var req dto.UpdateAPIKeyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(err))
		return
	}

	apiKey, err := c.apiKeyService.UpdateAPIKey(ctx.Request.Context(), keyID, &req, userID.(string))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, dto.NewErrorResponse(err))
		} else {
			ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		}
		return
	}

	ctx.JSON(http.StatusOK, apiKey)
}

// DeleteAPIKey deletes an API key
// @Summary Delete API key
// @Description Delete an API key
// @Tags api-keys
// @Param id path string true "API key ID"
// @Success 204
// @Failure 404 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /api/v1/api-keys/{id} [delete]
func (c *APIKeyController) DeleteAPIKey(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	keyID := ctx.Param("id")
	if keyID == "" {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(
			fmt.Errorf("API key ID is required")))
		return
	}

	err := c.apiKeyService.DeleteAPIKey(ctx.Request.Context(), keyID, userID.(string))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, dto.NewErrorResponse(err))
		} else {
			ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// ListAPIKeys lists user's API keys
// @Summary List API keys
// @Description List API keys for the authenticated user
// @Tags api-keys
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(10)
// @Success 200 {object} dto.ListAPIKeysResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/api-keys [get]
func (c *APIKeyController) ListAPIKeys(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	// Parse pagination parameters
	page, err := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(ctx.DefaultQuery("pageSize", "10"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	apiKeys, err := c.apiKeyService.ListAPIKeys(ctx.Request.Context(), userID.(string), page, pageSize)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, apiKeys)
}

// RevokeAPIKey revokes an API key
// @Summary Revoke API key
// @Description Revoke an API key, making it invalid for future use
// @Tags api-keys
// @Param id path string true "API key ID"
// @Success 200 {object} dto.SuccessResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /api/v1/api-keys/{id}/revoke [post]
func (c *APIKeyController) RevokeAPIKey(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	keyID := ctx.Param("id")
	if keyID == "" {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(
			fmt.Errorf("API key ID is required")))
		return
	}

	err := c.apiKeyService.RevokeAPIKey(ctx.Request.Context(), keyID, userID.(string))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, dto.NewErrorResponse(err))
		} else {
			ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		}
		return
	}

	ctx.JSON(http.StatusOK, dto.NewSuccessResponse("API key revoked successfully", nil))
}

// RegenerateAPIKey regenerates an API key
// @Summary Regenerate API key
// @Description Generate a new key for an existing API key (invalidates the old key)
// @Tags api-keys
// @Param id path string true "API key ID"
// @Success 200 {object} dto.RegenerateAPIKeyResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /api/v1/api-keys/{id}/regenerate [post]
func (c *APIKeyController) RegenerateAPIKey(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	keyID := ctx.Param("id")
	if keyID == "" {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(
			fmt.Errorf("API key ID is required")))
		return
	}

	response, err := c.apiKeyService.RegenerateAPIKey(ctx.Request.Context(), keyID, userID.(string))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, dto.NewErrorResponse(err))
		} else {
			ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		}
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// GetUsageStats gets usage statistics for an API key
// @Summary Get API key usage stats
// @Description Get usage statistics for an API key
// @Tags api-keys
// @Produce json
// @Param id path string true "API key ID"
// @Success 200 {object} dto.APIKeyUsageStatsResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /api/v1/api-keys/{id}/usage [get]
func (c *APIKeyController) GetUsageStats(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	keyID := ctx.Param("id")
	if keyID == "" {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(
			fmt.Errorf("API key ID is required")))
		return
	}

	stats, err := c.apiKeyService.GetUsageStats(ctx.Request.Context(), keyID, userID.(string))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, dto.NewErrorResponse(err))
		} else {
			ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		}
		return
	}

	ctx.JSON(http.StatusOK, stats)
}

// CreateTeamAPIKey creates a team API key
// @Summary Create team API key
// @Description Create a new API key for a team
// @Tags api-keys
// @Accept json
// @Produce json
// @Param teamId path string true "Team ID"
// @Param request body dto.CreateAPIKeyRequest true "API key creation request"
// @Success 201 {object} dto.CreateAPIKeyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 403 {object} dto.ErrorResponse
// @Router /api/v1/api-keys/team/{teamId} [post]
func (c *APIKeyController) CreateTeamAPIKey(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	teamID := ctx.Param("teamId")
	if teamID == "" {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(
			fmt.Errorf("team ID is required")))
		return
	}

	var req dto.CreateAPIKeyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(err))
		return
	}

	apiKey, err := c.apiKeyService.CreateTeamAPIKey(ctx.Request.Context(), &req, userID.(string), teamID)
	if err != nil {
		if strings.Contains(err.Error(), "access denied") || strings.Contains(err.Error(), "permission") {
			ctx.JSON(http.StatusForbidden, dto.NewErrorResponse(err))
		} else {
			ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		}
		return
	}

	ctx.JSON(http.StatusCreated, apiKey)
}

// ListTeamAPIKeys lists API keys for a team
// @Summary List team API keys
// @Description List API keys for a specific team
// @Tags api-keys
// @Produce json
// @Param teamId path string true "Team ID"
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(10)
// @Success 200 {object} dto.ListAPIKeysResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 403 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/api-keys/team/{teamId} [get]
func (c *APIKeyController) ListTeamAPIKeys(ctx *gin.Context) {
	userID, exists := ctx.Get("userID")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, dto.NewErrorResponse(
			fmt.Errorf("user not authenticated")))
		return
	}

	teamID := ctx.Param("teamId")
	if teamID == "" {
		ctx.JSON(http.StatusBadRequest, dto.NewErrorResponse(
			fmt.Errorf("team ID is required")))
		return
	}

	// Parse pagination parameters
	page, err := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(ctx.DefaultQuery("pageSize", "10"))
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	apiKeys, err := c.apiKeyService.ListTeamAPIKeys(ctx.Request.Context(), teamID, userID.(string), page, pageSize)
	if err != nil {
		if strings.Contains(err.Error(), "access denied") || strings.Contains(err.Error(), "permission") {
			ctx.JSON(http.StatusForbidden, dto.NewErrorResponse(err))
		} else {
			ctx.JSON(http.StatusInternalServerError, dto.NewErrorResponse(err))
		}
		return
	}

	ctx.JSON(http.StatusOK, apiKeys)
}
