package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"PropGuard/internal/entity"

	"github.com/google/uuid"
)

// BadgerUserRepository implements user storage using BadgerDB
type BadgerUserRepository struct {
	client *BadgerClient
}

// NewBadgerUserRepository creates a new BadgerDB-based user repository
func NewBadgerUserRepository(client *BadgerClient) *BadgerUserRepository {
	return &BadgerUserRepository{
		client: client,
	}
}

const (
	userKeyPrefix     = "user:"
	usernameKeyPrefix = "username:"
	emailKeyPrefix    = "email:"
	userIndexKey      = "users:index"
)

// Create creates a new user
func (r *BadgerUserRepository) Create(ctx context.Context, user *entity.VaultUser) error {
	// Check if username already exists
	if exists, _ := r.client.Exists(ctx, usernameKeyPrefix+user.Username); exists {
		return fmt.Errorf("username %s already exists", user.Username)
	}

	// Check if email already exists
	if exists, _ := r.client.Exists(ctx, emailKeyPrefix+user.Email); exists {
		return fmt.Errorf("email %s already exists", user.Email)
	}

	// Transaction to create user and indexes
	return r.client.Transaction(ctx, func(txn *Transaction) error {
		userKey := userKeyPrefix + user.ID.String()

		// Serialize user
		userData, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("failed to marshal user: %w", err)
		}

		// Store user
		if err := txn.Set(userKey, userData); err != nil {
			return err
		}

		// Create username index
		if err := txn.Set(usernameKeyPrefix+user.Username, []byte(user.ID.String())); err != nil {
			return err
		}

		// Create email index
		if err := txn.Set(emailKeyPrefix+user.Email, []byte(user.ID.String())); err != nil {
			return err
		}

		// Add to user index
		indexData, _ := txn.Get(userIndexKey)
		var userIDs []string
		if indexData != nil {
			json.Unmarshal(indexData, &userIDs)
		}
		userIDs = append(userIDs, user.ID.String())

		indexBytes, _ := json.Marshal(userIDs)
		return txn.Set(userIndexKey, indexBytes)
	})
}

// GetByID retrieves a user by ID
func (r *BadgerUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.VaultUser, error) {
	key := userKeyPrefix + id.String()

	var user entity.VaultUser
	if err := r.client.GetJSON(ctx, key, &user); err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	return &user, nil
}

// FindByUsername retrieves a user by username
func (r *BadgerUserRepository) FindByUsername(ctx context.Context, username string) (*entity.VaultUser, error) {
	// Get user ID from username index
	userIDBytes, err := r.client.Get(ctx, usernameKeyPrefix+username)
	if err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	userID, err := uuid.Parse(string(userIDBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in index: %w", err)
	}

	return r.GetByID(ctx, userID)
}

// FindByEmail retrieves a user by email
func (r *BadgerUserRepository) FindByEmail(ctx context.Context, email string) (*entity.VaultUser, error) {
	// Get user ID from email index
	userIDBytes, err := r.client.Get(ctx, emailKeyPrefix+email)
	if err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	userID, err := uuid.Parse(string(userIDBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in index: %w", err)
	}

	return r.GetByID(ctx, userID)
}

// Update updates an existing user
func (r *BadgerUserRepository) Update(ctx context.Context, user *entity.VaultUser) error {
	// Check if user exists
	exists, err := r.client.Exists(ctx, userKeyPrefix+user.ID.String())
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("user not found")
	}

	// Get old user to check if username/email changed
	oldUser, err := r.GetByID(ctx, user.ID)
	if err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Update user
		user.UpdatedAt = time.Now()
		user.Version++

		userData, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("failed to marshal user: %w", err)
		}

		if err := txn.Set(userKeyPrefix+user.ID.String(), userData); err != nil {
			return err
		}

		// Update username index if changed
		if oldUser.Username != user.Username {
			// Remove old username index
			if err := txn.Delete(usernameKeyPrefix + oldUser.Username); err != nil {
				return err
			}
			// Add new username index
			if err := txn.Set(usernameKeyPrefix+user.Username, []byte(user.ID.String())); err != nil {
				return err
			}
		}

		// Update email index if changed
		if oldUser.Email != user.Email {
			// Remove old email index
			if err := txn.Delete(emailKeyPrefix + oldUser.Email); err != nil {
				return err
			}
			// Add new email index
			if err := txn.Set(emailKeyPrefix+user.Email, []byte(user.ID.String())); err != nil {
				return err
			}
		}

		return nil
	})
}

// Delete deletes a user
func (r *BadgerUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	user, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Delete user
		if err := txn.Delete(userKeyPrefix + id.String()); err != nil {
			return err
		}

		// Delete username index
		if err := txn.Delete(usernameKeyPrefix + user.Username); err != nil {
			return err
		}

		// Delete email index
		if err := txn.Delete(emailKeyPrefix + user.Email); err != nil {
			return err
		}

		// Remove from user index
		indexData, _ := txn.Get(userIndexKey)
		if indexData != nil {
			var userIDs []string
			json.Unmarshal(indexData, &userIDs)

			// Remove user ID from list
			newIDs := []string{}
			for _, uid := range userIDs {
				if uid != id.String() {
					newIDs = append(newIDs, uid)
				}
			}

			indexBytes, _ := json.Marshal(newIDs)
			return txn.Set(userIndexKey, indexBytes)
		}

		return nil
	})
}

// List retrieves all users with pagination
func (r *BadgerUserRepository) List(ctx context.Context, limit, offset int) ([]*entity.VaultUser, error) {
	// Get user index
	indexData, err := r.client.Get(ctx, userIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return []*entity.VaultUser{}, nil
		}
		return nil, err
	}

	var userIDs []string
	if err := json.Unmarshal(indexData, &userIDs); err != nil {
		return nil, err
	}

	// Apply pagination
	start := offset
	if start > len(userIDs) {
		return []*entity.VaultUser{}, nil
	}

	end := start + limit
	if end > len(userIDs) {
		end = len(userIDs)
	}

	paginatedIDs := userIDs[start:end]
	users := make([]*entity.VaultUser, 0, len(paginatedIDs))

	for _, idStr := range paginatedIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue
		}

		user, err := r.GetByID(ctx, id)
		if err != nil {
			continue
		}

		users = append(users, user)
	}

	return users, nil
}

// Count returns the total number of users
func (r *BadgerUserRepository) Count(ctx context.Context) (int64, error) {
	indexData, err := r.client.Get(ctx, userIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return 0, nil
		}
		return 0, err
	}

	var userIDs []string
	if err := json.Unmarshal(indexData, &userIDs); err != nil {
		return 0, err
	}

	return int64(len(userIDs)), nil
}

// UpdateLastLogin updates the user's last login time and IP
func (r *BadgerUserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID, ip string) error {
	user, err := r.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = ip
	user.LoginAttempts = 0
	user.LockedUntil = nil

	return r.Update(ctx, user)
}

// IncrementLoginAttempts increments failed login attempts
func (r *BadgerUserRepository) IncrementLoginAttempts(ctx context.Context, userID uuid.UUID) error {
	user, err := r.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.LoginAttempts++

	// Lock account after 5 failed attempts
	if user.LoginAttempts >= 5 {
		lockUntil := time.Now().Add(30 * time.Minute)
		user.LockedUntil = &lockUntil
	}

	return r.Update(ctx, user)
}

// GetByRole retrieves users with a specific role
func (r *BadgerUserRepository) GetByRole(ctx context.Context, roleID string) ([]*entity.VaultUser, error) {
	// Get all users and filter by role
	// In a production system, you'd want to maintain a role index
	allUsers, err := r.List(ctx, 10000, 0) // Get all users
	if err != nil {
		return nil, err
	}

	var usersWithRole []*entity.VaultUser
	for _, user := range allUsers {
		for _, rid := range user.RoleIDs {
			if rid == roleID {
				usersWithRole = append(usersWithRole, user)
				break
			}
		}
	}

	return usersWithRole, nil
}

// GetByTeam retrieves users in a specific team
func (r *BadgerUserRepository) GetByTeam(ctx context.Context, teamID string) ([]*entity.VaultUser, error) {
	// Get all users and filter by team
	// In a production system, you'd want to maintain a team index
	allUsers, err := r.List(ctx, 10000, 0) // Get all users
	if err != nil {
		return nil, err
	}

	var usersInTeam []*entity.VaultUser
	for _, user := range allUsers {
		for _, tid := range user.TeamIDs {
			if tid == teamID {
				usersInTeam = append(usersInTeam, user)
				break
			}
		}
	}

	return usersInTeam, nil
}
