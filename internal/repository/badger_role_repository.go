package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"PropGuard/internal/entity"
)

type BadgerRoleRepository struct {
	client *BadgerClient
}

func NewBadgerRoleRepository(client *BadgerClient) *BadgerRoleRepository {
	return &BadgerRoleRepository{
		client: client,
	}
}

const (
	roleKeyPrefix  = "role:"
	roleNamePrefix = "rolename:"
	roleIndexKey   = "roles:index"
)

func (r *BadgerRoleRepository) Create(ctx context.Context, role *entity.Role) error {
	if exists, _ := r.client.Exists(ctx, roleNamePrefix+role.Name); exists {
		return fmt.Errorf("role with name %s already exists", role.Name)
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		now := time.Now()
		role.CreatedAt = now
		role.UpdatedAt = now

		key := roleKeyPrefix + role.ID
		roleData, err := json.Marshal(role)
		if err != nil {
			return fmt.Errorf("failed to marshal role: %w", err)
		}

		if err := txn.Set(key, roleData); err != nil {
			return err
		}

		if err := txn.Set(roleNamePrefix+role.Name, []byte(role.ID)); err != nil {
			return err
		}

		indexData, _ := txn.Get(roleIndexKey)
		var roleIDs []string
		if indexData != nil {
			json.Unmarshal(indexData, &roleIDs)
		}
		roleIDs = append(roleIDs, role.ID)

		indexBytes, _ := json.Marshal(roleIDs)
		return txn.Set(roleIndexKey, indexBytes)
	})
}

func (r *BadgerRoleRepository) GetByID(ctx context.Context, id string) (*entity.Role, error) {
	key := roleKeyPrefix + id

	var role entity.Role
	if err := r.client.GetJSON(ctx, key, &role); err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("role not found")
		}
		return nil, err
	}

	return &role, nil
}

func (r *BadgerRoleRepository) GetByName(ctx context.Context, name string) (*entity.Role, error) {
	roleIDBytes, err := r.client.Get(ctx, roleNamePrefix+name)
	if err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("role not found")
		}
		return nil, err
	}

	roleID := string(roleIDBytes)
	return r.GetByID(ctx, roleID)
}

func (r *BadgerRoleRepository) Update(ctx context.Context, role *entity.Role) error {
	exists, err := r.client.Exists(ctx, roleKeyPrefix+role.ID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("role not found")
	}

	oldRole, err := r.GetByID(ctx, role.ID)
	if err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		role.UpdatedAt = time.Now()

		roleData, err := json.Marshal(role)
		if err != nil {
			return fmt.Errorf("failed to marshal role: %w", err)
		}

		if err := txn.Set(roleKeyPrefix+role.ID, roleData); err != nil {
			return err
		}

		if oldRole.Name != role.Name {
			if err := txn.Delete(roleNamePrefix + oldRole.Name); err != nil {
				return err
			}
			if err := txn.Set(roleNamePrefix+role.Name, []byte(role.ID)); err != nil {
				return err
			}
		}

		return nil
	})
}

func (r *BadgerRoleRepository) Delete(ctx context.Context, id string) error {
	role, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		if err := txn.Delete(roleKeyPrefix + id); err != nil {
			return err
		}

		if err := txn.Delete(roleNamePrefix + role.Name); err != nil {
			return err
		}

		indexData, _ := txn.Get(roleIndexKey)
		if indexData != nil {
			var roleIDs []string
			json.Unmarshal(indexData, &roleIDs)

			newIDs := []string{}
			for _, rid := range roleIDs {
				if rid != id {
					newIDs = append(newIDs, rid)
				}
			}

			indexBytes, _ := json.Marshal(newIDs)
			return txn.Set(roleIndexKey, indexBytes)
		}

		return nil
	})
}

func (r *BadgerRoleRepository) List(ctx context.Context, limit, offset int) ([]*entity.Role, error) {
	indexData, err := r.client.Get(ctx, roleIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return []*entity.Role{}, nil
		}
		return nil, err
	}

	var roleIDs []string
	if err := json.Unmarshal(indexData, &roleIDs); err != nil {
		return nil, err
	}

	start := offset
	if start > len(roleIDs) {
		return []*entity.Role{}, nil
	}

	end := start + limit
	if end > len(roleIDs) {
		end = len(roleIDs)
	}

	paginatedIDs := roleIDs[start:end]
	roles := make([]*entity.Role, 0, len(paginatedIDs))

	for _, idStr := range paginatedIDs {
		role, err := r.GetByID(ctx, idStr)
		if err != nil {
			continue
		}

		roles = append(roles, role)
	}

	return roles, nil
}

func (r *BadgerRoleRepository) Count(ctx context.Context) (int64, error) {
	indexData, err := r.client.Get(ctx, roleIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return 0, nil
		}
		return 0, err
	}

	var roleIDs []string
	if err := json.Unmarshal(indexData, &roleIDs); err != nil {
		return 0, err
	}

	return int64(len(roleIDs)), nil
}

func (r *BadgerRoleRepository) GetSystemRoles(ctx context.Context) ([]*entity.Role, error) {
	allRoles, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	var systemRoles []*entity.Role
	for _, role := range allRoles {
		if role.IsSystem {
			systemRoles = append(systemRoles, role)
		}
	}

	return systemRoles, nil
}

func (r *BadgerRoleRepository) GetUserRoles(ctx context.Context) ([]*entity.Role, error) {
	allRoles, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	var userRoles []*entity.Role
	for _, role := range allRoles {
		if !role.IsSystem {
			userRoles = append(userRoles, role)
		}
	}

	return userRoles, nil
}

func (r *BadgerRoleRepository) HasPermission(ctx context.Context, roleID string, permission string) (bool, error) {
	role, err := r.GetByID(ctx, roleID)
	if err != nil {
		return false, err
	}

	for _, perm := range role.Permissions {
		if perm == permission {
			return true, nil
		}
	}

	return false, nil
}

func (r *BadgerRoleRepository) AddPermission(ctx context.Context, roleID string, permission string) error {
	role, err := r.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	for _, perm := range role.Permissions {
		if perm == permission {
			return nil
		}
	}

	role.Permissions = append(role.Permissions, permission)
	return r.Update(ctx, role)
}

func (r *BadgerRoleRepository) RemovePermission(ctx context.Context, roleID string, permission string) error {
	role, err := r.GetByID(ctx, roleID)
	if err != nil {
		return err
	}

	newPermissions := []string{}
	for _, perm := range role.Permissions {
		if perm != permission {
			newPermissions = append(newPermissions, perm)
		}
	}

	role.Permissions = newPermissions
	return r.Update(ctx, role)
}
