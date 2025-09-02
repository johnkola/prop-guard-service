package security

import (
	"net/http"
	"strings"

	"github.com/bazarbozorg/PropGuard/internal/service"
	"github.com/gin-gonic/gin"
)

const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
	UserContextKey      = "user"
	ClaimsContextKey    = "claims"
)

type JWTMiddleware struct {
	authService service.AuthService
}

func NewJWTMiddleware(authService service.AuthService) *JWTMiddleware {
	return &JWTMiddleware{
		authService: authService,
	}
}

func (m *JWTMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authentication token"})
			c.Abort()
			return
		}

		claims, err := m.authService.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			c.Abort()
			return
		}

		// Store user information in context
		c.Set(UserContextKey, claims.Username)
		c.Set(ClaimsContextKey, claims)
		c.Next()
	}
}

func (m *JWTMiddleware) RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsInterface, exists := c.Get(ClaimsContextKey)
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "no claims found"})
			c.Abort()
			return
		}

		claims, ok := claimsInterface.(*service.Claims)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid claims type"})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, requiredRole := range roles {
			for _, userRole := range claims.Roles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func (m *JWTMiddleware) extractToken(c *gin.Context) string {
	authHeader := c.GetHeader(AuthorizationHeader)
	if authHeader == "" {
		return ""
	}

	if !strings.HasPrefix(authHeader, BearerPrefix) {
		return ""
	}

	return strings.TrimPrefix(authHeader, BearerPrefix)
}

// GetUsername extracts the username from the context
func GetUsername(c *gin.Context) string {
	username, _ := c.Get(UserContextKey)
	if str, ok := username.(string); ok {
		return str
	}
	return ""
}

// GetClaims extracts the claims from the context
func GetClaims(c *gin.Context) *service.Claims {
	claimsInterface, exists := c.Get(ClaimsContextKey)
	if !exists {
		return nil
	}

	claims, _ := claimsInterface.(*service.Claims)
	return claims
}
