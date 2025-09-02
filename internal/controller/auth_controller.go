package controller

import (
	"net/http"

	"github.com/bazarbozorg/PropGuard/internal/dto"
	"github.com/bazarbozorg/PropGuard/internal/service"
	"github.com/gin-gonic/gin"
)

type AuthController struct {
	authService service.AuthService
}

func NewAuthController(authService service.AuthService) *AuthController {
	return &AuthController{
		authService: authService,
	}
}

func (c *AuthController) RegisterRoutes(router *gin.RouterGroup) {
	auth := router.Group("/auth")
	{
		auth.POST("/login", c.Login)
		auth.POST("/logout", c.Logout)
		auth.POST("/refresh", c.RefreshToken)
	}
}

// Login godoc
// @Summary Login to the vault
// @Description Authenticate with username and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login credentials"
// @Success 200 {object} dto.AuthResponse
// @Failure 401 {object} map[string]string
// @Router /auth/login [post]
func (c *AuthController) Login(ctx *gin.Context) {
	var request dto.LoginRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	response, err := c.authService.Login(ctx, &request)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, response)
}

// Logout godoc
// @Summary Logout from the vault
// @Description Invalidate the current token
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Router /auth/logout [post]
func (c *AuthController) Logout(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	if len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
		c.authService.Logout(token)
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "logout successful"})
}

// RefreshToken godoc
// @Summary Refresh authentication token
// @Description Get a new token before the current one expires
// @Tags auth
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /auth/refresh [post]
func (c *AuthController) RefreshToken(ctx *gin.Context) {
	token := ctx.GetHeader("Authorization")
	if len(token) <= 7 || token[:7] != "Bearer " {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid token format"})
		return
	}

	token = token[7:]
	newToken, err := c.authService.RefreshToken(token)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"token": newToken})
}
