package service

import (
	"context"
	"fmt"
	"time"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	Login(ctx context.Context, request *dto.LoginRequest) (*dto.AuthResponse, error)
	ValidateToken(tokenString string) (*Claims, error)
	RefreshToken(tokenString string) (string, error)
	Logout(tokenString string)
}

type Claims struct {
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

type authService struct {
	userRepo     *repository.BadgerUserRepository
	auditService AuditService
	jwtSecret    []byte
	jwtExpiry    time.Duration
}

func NewAuthService(
	userRepo *repository.BadgerUserRepository,
	auditService AuditService,
	jwtSecret string,
	jwtExpiryHours int,
) AuthService {
	return &authService{
		userRepo:     userRepo,
		auditService: auditService,
		jwtSecret:    []byte(jwtSecret),
		jwtExpiry:    time.Duration(jwtExpiryHours) * time.Hour,
	}
}

func (s *authService) Login(ctx context.Context, request *dto.LoginRequest) (*dto.AuthResponse, error) {
	// Find user by username
	user, err := s.userRepo.FindByUsername(ctx, request.Username)
	if err != nil {
		s.auditService.LogAction(ctx, request.Username, "LOGIN", "", false, "User not found")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if !user.Enabled {
		s.auditService.LogAction(ctx, request.Username, "LOGIN", "", false, "User account is not active")
		return nil, fmt.Errorf("account is disabled")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)); err != nil {
		s.auditService.LogAction(ctx, request.Username, "LOGIN", "", false, "Invalid password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate JWT token
	token, expiresAt, err := s.generateToken(user)
	if err != nil {
		s.auditService.LogAction(ctx, request.Username, "LOGIN", "", false, "Token generation failed")
		return nil, fmt.Errorf("failed to generate token")
	}

	// Convert roles to strings (use new RBAC RoleIDs, fallback to legacy Roles)
	var roles []string
	if len(user.RoleIDs) > 0 {
		roles = make([]string, len(user.RoleIDs))
		copy(roles, user.RoleIDs)
	} else {
		// Fallback to legacy roles for backward compatibility
		roles = make([]string, len(user.Roles))
		for i, role := range user.Roles {
			roles[i] = string(role)
		}
	}

	s.auditService.LogAction(ctx, request.Username, "LOGIN", "", true, "Login successful")

	return &dto.AuthResponse{
		Token:     token,
		Username:  user.Username,
		Roles:     roles,
		ExpiresIn: int64(time.Until(expiresAt).Seconds()),
	}, nil
}

func (s *authService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *authService) RefreshToken(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	// Check if token is close to expiry (within 1 hour)
	if time.Until(claims.ExpiresAt.Time) > time.Hour {
		return "", fmt.Errorf("token is not eligible for refresh yet")
	}

	// Generate new token with same claims
	newClaims := &Claims{
		Username:    claims.Username,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.jwtExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	return token.SignedString(s.jwtSecret)
}

func (s *authService) Logout(tokenString string) {
	// In a production system, you might want to maintain a blacklist of tokens
	// For now, this is a no-op as JWT tokens are stateless
	// The client should remove the token from their storage
}

func (s *authService) generateToken(user *entity.VaultUser) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.jwtExpiry)

	// Convert roles to strings and collect permissions (use new RBAC RoleIDs, fallback to legacy Roles)
	var roles []string
	permissionMap := make(map[string]bool)

	if len(user.RoleIDs) > 0 {
		// Use new RBAC system
		roles = make([]string, len(user.RoleIDs))
		copy(roles, user.RoleIDs)

		for _, roleID := range user.RoleIDs {
			// Get role permissions from predefined system roles
			for _, systemRole := range entity.GetSystemRoles() {
				if systemRole.ID == roleID {
					for _, perm := range systemRole.Permissions {
						permissionMap[perm] = true
					}
					break
				}
			}
		}
	} else {
		// Fallback to legacy roles
		roles = make([]string, len(user.Roles))
		for i, role := range user.Roles {
			roles[i] = string(role)

			// Get role permissions from predefined system roles
			for _, systemRole := range entity.GetSystemRoles() {
				if systemRole.ID == string(role) {
					for _, perm := range systemRole.Permissions {
						permissionMap[perm] = true
					}
					break
				}
			}
		}
	}

	// Convert permission map to slice
	permissions := make([]string, 0, len(permissionMap))
	for perm := range permissionMap {
		permissions = append(permissions, perm)
	}

	claims := &Claims{
		Username:    user.Username,
		Roles:       roles,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// HashPassword hashes a plain text password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}
