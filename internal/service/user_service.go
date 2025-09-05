package service

import (
	"context"
	"fmt"
	"math"
	"time"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserService interface {
	CreateUser(ctx context.Context, req dto.CreateUserRequest, createdBy string) (*dto.UserResponse, error)
	GetUser(ctx context.Context, id uuid.UUID) (*dto.UserResponse, error)
	GetUserByUsername(ctx context.Context, username string) (*dto.UserResponse, error)
	UpdateUser(ctx context.Context, id uuid.UUID, req dto.UpdateUserRequest, updatedBy string) (*dto.UserResponse, error)
	DeleteUser(ctx context.Context, id uuid.UUID, deletedBy string) error
	ListUsers(ctx context.Context, page, pageSize int) (*dto.ListUsersResponse, error)
	ChangePassword(ctx context.Context, id uuid.UUID, req dto.ChangePasswordRequest, changedBy string) error
	ResetPassword(ctx context.Context, id uuid.UUID, req dto.ResetPasswordRequest, resetBy string) error
	CreateSystemUser(ctx context.Context, username string, roles []entity.VaultRole) (*dto.UserResponse, error)
}

type userService struct {
	userRepo     *repository.BadgerUserRepository
	auditService AuditService
}

func NewUserService(userRepo *repository.BadgerUserRepository, auditService AuditService) UserService {
	return &userService{
		userRepo:     userRepo,
		auditService: auditService,
	}
}

func (s *userService) CreateUser(ctx context.Context, req dto.CreateUserRequest, createdBy string) (*dto.UserResponse, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.auditService.LogUserOperation(ctx, createdBy, "CREATE_USER", req.Username, false, fmt.Sprintf("Password hashing failed: %v", err))
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user entity
	user := entity.NewVaultUser(req.Username, req.Email, string(hashedPassword))

	// Set optional fields with defaults
	if req.Enabled != nil {
		user.Enabled = *req.Enabled
	}
	if req.AccountNonExpired != nil {
		user.AccountNonExpired = *req.AccountNonExpired
	}
	if req.AccountNonLocked != nil {
		user.AccountNonLocked = *req.AccountNonLocked
	}
	if req.CredentialsNonExpired != nil {
		user.CredentialsNonExpired = *req.CredentialsNonExpired
	}

	user.Roles = req.Roles
	user.Policies = req.Policies

	// Save to database
	if err := s.userRepo.Create(ctx, user); err != nil {
		s.auditService.LogUserOperation(ctx, createdBy, "CREATE_USER", req.Username, false, fmt.Sprintf("Database save failed: %v", err))
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Log successful creation
	s.auditService.LogUserOperation(ctx, createdBy, "CREATE_USER", req.Username, true, "User created successfully")

	response := dto.ToUserResponse(user)
	return &response, nil
}

func (s *userService) GetUser(ctx context.Context, id uuid.UUID) (*dto.UserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	response := dto.ToUserResponse(user)
	return &response, nil
}

func (s *userService) GetUserByUsername(ctx context.Context, username string) (*dto.UserResponse, error) {
	user, err := s.userRepo.FindByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	response := dto.ToUserResponse(user)
	return &response, nil
}

func (s *userService) UpdateUser(ctx context.Context, id uuid.UUID, req dto.UpdateUserRequest, updatedBy string) (*dto.UserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.auditService.LogUserOperation(ctx, updatedBy, "UPDATE_USER", user.Username, false, fmt.Sprintf("User not found: %v", err))
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Update fields if provided
	if req.Enabled != nil {
		user.Enabled = *req.Enabled
	}
	if req.AccountNonExpired != nil {
		user.AccountNonExpired = *req.AccountNonExpired
	}
	if req.AccountNonLocked != nil {
		user.AccountNonLocked = *req.AccountNonLocked
	}
	if req.CredentialsNonExpired != nil {
		user.CredentialsNonExpired = *req.CredentialsNonExpired
	}
	if req.Roles != nil {
		user.Roles = req.Roles
	}
	if req.Policies != nil {
		user.Policies = req.Policies
	}

	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.auditService.LogUserOperation(ctx, updatedBy, "UPDATE_USER", user.Username, false, fmt.Sprintf("Database update failed: %v", err))
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	s.auditService.LogUserOperation(ctx, updatedBy, "UPDATE_USER", user.Username, true, "User updated successfully")

	response := dto.ToUserResponse(user)
	return &response, nil
}

func (s *userService) DeleteUser(ctx context.Context, id uuid.UUID, deletedBy string) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.auditService.LogUserOperation(ctx, deletedBy, "DELETE_USER", "unknown", false, fmt.Sprintf("User not found: %v", err))
		return fmt.Errorf("failed to find user: %w", err)
	}

	// Prevent deletion of system users
	if user.IsSystemUser() {
		s.auditService.LogUserOperation(ctx, deletedBy, "DELETE_USER", user.Username, false, "Attempted to delete system user")
		return fmt.Errorf("cannot delete system user")
	}

	if err := s.userRepo.Delete(ctx, id); err != nil {
		s.auditService.LogUserOperation(ctx, deletedBy, "DELETE_USER", user.Username, false, fmt.Sprintf("Database delete failed: %v", err))
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.auditService.LogUserOperation(ctx, deletedBy, "DELETE_USER", user.Username, true, "User deleted successfully")
	return nil
}

func (s *userService) ListUsers(ctx context.Context, page, pageSize int) (*dto.ListUsersResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize
	users, err := s.userRepo.List(ctx, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	total, err := s.userRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}

	userResponses := make([]dto.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = dto.ToUserResponse(user)
	}

	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))

	return &dto.ListUsersResponse{
		Users:      userResponses,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

func (s *userService) ChangePassword(ctx context.Context, id uuid.UUID, req dto.ChangePasswordRequest, changedBy string) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.auditService.LogUserOperation(ctx, changedBy, "CHANGE_PASSWORD", "unknown", false, fmt.Sprintf("User not found: %v", err))
		return fmt.Errorf("failed to find user: %w", err)
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		s.auditService.LogUserOperation(ctx, changedBy, "CHANGE_PASSWORD", user.Username, false, "Invalid current password")
		return fmt.Errorf("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.auditService.LogUserOperation(ctx, changedBy, "CHANGE_PASSWORD", user.Username, false, fmt.Sprintf("Password hashing failed: %v", err))
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.auditService.LogUserOperation(ctx, changedBy, "CHANGE_PASSWORD", user.Username, false, fmt.Sprintf("Database update failed: %v", err))
		return fmt.Errorf("failed to update password: %w", err)
	}

	s.auditService.LogUserOperation(ctx, changedBy, "CHANGE_PASSWORD", user.Username, true, "Password changed successfully")
	return nil
}

func (s *userService) ResetPassword(ctx context.Context, id uuid.UUID, req dto.ResetPasswordRequest, resetBy string) error {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		s.auditService.LogUserOperation(ctx, resetBy, "RESET_PASSWORD", "unknown", false, fmt.Sprintf("User not found: %v", err))
		return fmt.Errorf("failed to find user: %w", err)
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		s.auditService.LogUserOperation(ctx, resetBy, "RESET_PASSWORD", user.Username, false, fmt.Sprintf("Password hashing failed: %v", err))
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		s.auditService.LogUserOperation(ctx, resetBy, "RESET_PASSWORD", user.Username, false, fmt.Sprintf("Database update failed: %v", err))
		return fmt.Errorf("failed to reset password: %w", err)
	}

	s.auditService.LogUserOperation(ctx, resetBy, "RESET_PASSWORD", user.Username, true, "Password reset successfully")
	return nil
}

func (s *userService) CreateSystemUser(ctx context.Context, username string, roles []entity.VaultRole) (*dto.UserResponse, error) {
	// Generate a secure random password for system users
	systemPassword := uuid.New().String()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(systemPassword), bcrypt.DefaultCost)
	if err != nil {
		s.auditService.LogUserOperation(ctx, "system", "CREATE_SYSTEM_USER", username, false, fmt.Sprintf("Password hashing failed: %v", err))
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create system user
	systemEmail := fmt.Sprintf("%s@system.local", username)
	user := entity.NewVaultUser(username, systemEmail, string(hashedPassword))
	user.Roles = roles

	if err := s.userRepo.Create(ctx, user); err != nil {
		s.auditService.LogUserOperation(ctx, "system", "CREATE_SYSTEM_USER", username, false, fmt.Sprintf("Database save failed: %v", err))
		return nil, fmt.Errorf("failed to create system user: %w", err)
	}

	s.auditService.LogUserOperation(ctx, "system", "CREATE_SYSTEM_USER", username, true, "System user created successfully")

	response := dto.ToUserResponse(user)
	return &response, nil
}
