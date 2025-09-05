package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"PropGuard/internal/entity"
)

// BadgerSecretRepository implements secret storage using BadgerDB
type BadgerSecretRepository struct {
	client *BadgerClient
}

// NewBadgerSecretRepository creates a new BadgerDB-based secret repository
func NewBadgerSecretRepository(client *BadgerClient) *BadgerSecretRepository {
	return &BadgerSecretRepository{
		client: client,
	}
}

const (
	secretKeyPrefix     = "secret:"
	secretIndexKey      = "secrets:index"
	secretVersionPrefix = "secret:version:"
)

// Create creates a new secret
func (r *BadgerSecretRepository) Create(ctx context.Context, secret *entity.Secret) error {
	key := secretKeyPrefix + secret.Path

	// Check if secret already exists
	exists, _ := r.client.Exists(ctx, key)
	if exists {
		return fmt.Errorf("secret at path %s already exists", secret.Path)
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Set timestamps
		now := time.Now()
		secret.CreatedAt = now
		secret.UpdatedAt = now
		secret.Version = 1

		// Serialize secret
		secretData, err := json.Marshal(secret)
		if err != nil {
			return fmt.Errorf("failed to marshal secret: %w", err)
		}

		// Store secret
		if err := txn.Set(key, secretData); err != nil {
			return err
		}

		// Store version history
		versionKey := fmt.Sprintf("%s%s:%d", secretVersionPrefix, secret.Path, secret.Version)
		if err := txn.Set(versionKey, secretData); err != nil {
			return err
		}

		// Update secret index
		indexData, _ := txn.Get(secretIndexKey)
		var paths []string
		if indexData != nil {
			json.Unmarshal(indexData, &paths)
		}
		paths = append(paths, secret.Path)

		indexBytes, _ := json.Marshal(paths)
		return txn.Set(secretIndexKey, indexBytes)
	})
}

// GetByPath retrieves a secret by path
func (r *BadgerSecretRepository) GetByPath(ctx context.Context, path string) (*entity.Secret, error) {
	key := secretKeyPrefix + path

	var secret entity.Secret
	if err := r.client.GetJSON(ctx, key, &secret); err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("secret not found at path: %s", path)
		}
		return nil, err
	}

	return &secret, nil
}

// Update updates an existing secret
func (r *BadgerSecretRepository) Update(ctx context.Context, secret *entity.Secret) error {
	key := secretKeyPrefix + secret.Path

	// Check if secret exists
	exists, err := r.client.Exists(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("secret not found at path: %s", secret.Path)
	}

	// Get current secret for version history
	var current entity.Secret
	if err := r.client.GetJSON(ctx, key, &current); err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Update metadata
		secret.UpdatedAt = time.Now()
		secret.Version = current.Version + 1
		secret.CreatedAt = current.CreatedAt // Preserve creation time

		// Serialize secret
		secretData, err := json.Marshal(secret)
		if err != nil {
			return fmt.Errorf("failed to marshal secret: %w", err)
		}

		// Update secret
		if err := txn.Set(key, secretData); err != nil {
			return err
		}

		// Store version history
		versionKey := fmt.Sprintf("%s%s:%d", secretVersionPrefix, secret.Path, secret.Version)
		if err := txn.Set(versionKey, secretData); err != nil {
			return err
		}

		return nil
	})
}

// Delete deletes a secret
func (r *BadgerSecretRepository) Delete(ctx context.Context, path string) error {
	key := secretKeyPrefix + path

	// Check if secret exists
	exists, err := r.client.Exists(ctx, key)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("secret not found at path: %s", path)
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Delete secret
		if err := txn.Delete(key); err != nil {
			return err
		}

		// Remove from index
		indexData, _ := txn.Get(secretIndexKey)
		if indexData != nil {
			var paths []string
			json.Unmarshal(indexData, &paths)

			// Remove path from list
			newPaths := []string{}
			for _, p := range paths {
				if p != path {
					newPaths = append(newPaths, p)
				}
			}

			indexBytes, _ := json.Marshal(newPaths)
			return txn.Set(secretIndexKey, indexBytes)
		}

		// Note: We keep version history for audit purposes

		return nil
	})
}

// List retrieves secrets with pagination
func (r *BadgerSecretRepository) List(ctx context.Context, limit, offset int) ([]*entity.Secret, error) {
	// Get secret index
	indexData, err := r.client.Get(ctx, secretIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return []*entity.Secret{}, nil
		}
		return nil, err
	}

	var paths []string
	if err := json.Unmarshal(indexData, &paths); err != nil {
		return nil, err
	}

	// Apply pagination
	start := offset
	if start > len(paths) {
		return []*entity.Secret{}, nil
	}

	end := start + limit
	if end > len(paths) {
		end = len(paths)
	}

	paginatedPaths := paths[start:end]
	secrets := make([]*entity.Secret, 0, len(paginatedPaths))

	for _, path := range paginatedPaths {
		secret, err := r.GetByPath(ctx, path)
		if err != nil {
			continue
		}
		secrets = append(secrets, secret)
	}

	return secrets, nil
}

// ListByPrefix retrieves secrets with a specific path prefix
func (r *BadgerSecretRepository) ListByPrefix(ctx context.Context, prefix string) ([]*entity.Secret, error) {
	// Get all secrets with prefix
	results, err := r.client.GetAll(ctx, secretKeyPrefix+prefix)
	if err != nil {
		return nil, err
	}

	secrets := make([]*entity.Secret, 0, len(results))
	for _, data := range results {
		var secret entity.Secret
		if err := json.Unmarshal(data, &secret); err != nil {
			continue
		}
		secrets = append(secrets, &secret)
	}

	return secrets, nil
}

// Count returns the total number of secrets
func (r *BadgerSecretRepository) Count(ctx context.Context) (int64, error) {
	indexData, err := r.client.Get(ctx, secretIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return 0, nil
		}
		return 0, err
	}

	var paths []string
	if err := json.Unmarshal(indexData, &paths); err != nil {
		return 0, err
	}

	return int64(len(paths)), nil
}

// GetVersion retrieves a specific version of a secret
func (r *BadgerSecretRepository) GetVersion(ctx context.Context, path string, version int) (*entity.Secret, error) {
	versionKey := fmt.Sprintf("%s%s:%d", secretVersionPrefix, path, version)

	var secret entity.Secret
	if err := r.client.GetJSON(ctx, versionKey, &secret); err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("version %d not found for secret at path: %s", version, path)
		}
		return nil, err
	}

	return &secret, nil
}

// ListVersions lists all versions of a secret
func (r *BadgerSecretRepository) ListVersions(ctx context.Context, path string) ([]*entity.Secret, error) {
	prefix := secretVersionPrefix + path + ":"
	results, err := r.client.GetAll(ctx, prefix)
	if err != nil {
		return nil, err
	}

	versions := make([]*entity.Secret, 0, len(results))
	for _, data := range results {
		var secret entity.Secret
		if err := json.Unmarshal(data, &secret); err != nil {
			continue
		}
		versions = append(versions, &secret)
	}

	return versions, nil
}

// Rotate rotates a secret value
func (r *BadgerSecretRepository) Rotate(ctx context.Context, path string, newValue string) error {
	secret, err := r.GetByPath(ctx, path)
	if err != nil {
		return err
	}

	// Update secret value
	secret.EncryptedData = newValue
	secret.UpdatedAt = time.Now()

	return r.Update(ctx, secret)
}

// SearchSecrets searches for secrets by various criteria
func (r *BadgerSecretRepository) SearchSecrets(ctx context.Context, query string) ([]*entity.Secret, error) {
	// Get all secrets
	allSecrets, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	// Filter by query
	query = strings.ToLower(query)
	var results []*entity.Secret

	for _, secret := range allSecrets {
		// Search in path and network namespace
		if strings.Contains(strings.ToLower(secret.Path), query) ||
			strings.Contains(strings.ToLower(secret.NetworkNamespace), query) ||
			strings.Contains(strings.ToLower(secret.NetworkSegment), query) {
			results = append(results, secret)
		}
	}

	return results, nil
}

// GetExpiredSecrets retrieves secrets that have expired
func (r *BadgerSecretRepository) GetExpiredSecrets(ctx context.Context) ([]*entity.Secret, error) {
	allSecrets, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var expired []*entity.Secret

	for _, secret := range allSecrets {
		if secret.ExpiresAt != nil && secret.ExpiresAt.Before(now) {
			expired = append(expired, secret)
		}
	}

	return expired, nil
}

// GetUnusedSecrets retrieves secrets not updated in the specified number of days
func (r *BadgerSecretRepository) GetUnusedSecrets(ctx context.Context, days int) ([]*entity.Secret, error) {
	allSecrets, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	threshold := time.Now().AddDate(0, 0, -days)
	var unused []*entity.Secret

	for _, secret := range allSecrets {
		if secret.UpdatedAt.Before(threshold) {
			unused = append(unused, secret)
		}
	}

	return unused, nil
}
