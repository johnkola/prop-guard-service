package controller

import (
	"net/http"
	"strconv"

	"PropGuard/internal/dto"
	"PropGuard/internal/security"
	"PropGuard/internal/service"
	"github.com/gin-gonic/gin"
)

type SecretController struct {
	secretService service.SecretService
	jwtMiddleware *security.JWTMiddleware
}

func NewSecretController(secretService service.SecretService, jwtMiddleware *security.JWTMiddleware) *SecretController {
	return &SecretController{
		secretService: secretService,
		jwtMiddleware: jwtMiddleware,
	}
}

func (c *SecretController) RegisterRoutes(router *gin.RouterGroup) {
	secrets := router.Group("/secrets")
	secrets.Use(c.jwtMiddleware.Authenticate())
	{
		secrets.GET("", c.ListSecrets)
		secrets.POST("/*path", c.CreateSecret)
		secrets.GET("/*path", c.GetSecret)
		secrets.PUT("/*path", c.UpdateSecret)
		secrets.DELETE("/*path", c.DeleteSecret)
	}
}

// CreateSecret godoc
// @Summary Create a new secret
// @Description Store a new secret at the specified path
// @Tags secrets
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param path path string true "Secret path"
// @Param request body dto.SecretRequest true "Secret data"
// @Success 201 {object} dto.SecretResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /secrets/{path} [post]
func (c *SecretController) CreateSecret(ctx *gin.Context) {
	path := ctx.Param("path")
	if path == "" || path == "/" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	var request dto.SecretRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username := security.GetUsername(ctx)
	response, err := c.secretService.CreateSecret(ctx, path, &request, username)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, response)
}

// GetSecret godoc
// @Summary Get a secret
// @Description Retrieve a secret from the specified path
// @Tags secrets
// @Produce json
// @Security BearerAuth
// @Param path path string true "Secret path"
// @Success 200 {object} dto.SecretResponse
// @Failure 404 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /secrets/{path} [get]
func (c *SecretController) GetSecret(ctx *gin.Context) {
	path := ctx.Param("path")
	if path == "" || path == "/" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	// TODO: Get namespace from context
	namespace := "default"

	response, err := c.secretService.GetSecret(ctx, namespace, path)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// UpdateSecret godoc
// @Summary Update a secret
// @Description Update an existing secret at the specified path
// @Tags secrets
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param path path string true "Secret path"
// @Param request body dto.SecretRequest true "Updated secret data"
// @Success 200 {object} dto.SecretResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /secrets/{path} [put]
func (c *SecretController) UpdateSecret(ctx *gin.Context) {
	path := ctx.Param("path")
	if path == "" || path == "/" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	var request dto.SecretRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	username := security.GetUsername(ctx)
	response, err := c.secretService.UpdateSecret(ctx, path, &request, username)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// DeleteSecret godoc
// @Summary Delete a secret
// @Description Remove a secret from the specified path
// @Tags secrets
// @Security BearerAuth
// @Param path path string true "Secret path"
// @Success 204
// @Failure 404 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /secrets/{path} [delete]
func (c *SecretController) DeleteSecret(ctx *gin.Context) {
	path := ctx.Param("path")
	if path == "" || path == "/" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	// TODO: Get namespace from context
	namespace := "default"
	username := security.GetUsername(ctx)

	if err := c.secretService.DeleteSecret(ctx, namespace, path, username); err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// ListSecrets godoc
// @Summary List secrets
// @Description List all secrets in the current namespace
// @Tags secrets
// @Produce json
// @Security BearerAuth
// @Param limit query int false "Limit results" default(20)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {array} dto.SecretResponse
// @Failure 401 {object} map[string]string
// @Router /secrets [get]
func (c *SecretController) ListSecrets(ctx *gin.Context) {
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

	// TODO: Get namespace from context
	namespace := "default"

	secrets, err := c.secretService.ListSecrets(ctx, namespace, limit, offset)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, secrets)
}
