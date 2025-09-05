package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"PropGuard/internal/entity"

	"github.com/google/uuid"
)

type BadgerAPIKeyRepository struct {
	client *BadgerClient
}

func NewBadgerAPIKeyRepository(client *BadgerClient) *BadgerAPIKeyRepository {
	return &BadgerAPIKeyRepository{
		client: client,
	}
}

const (
	apiKeyPrefix     = "apikey:"
	apiKeyHashPrefix = "apikey:hash:"
	apiKeyIndexKey   = "apikeys:index"
)

func (r *BadgerAPIKeyRepository) Create(ctx context.Context, apiKey *entity.APIKey) error {
	exists, _ := r.client.Exists(ctx, apiKeyHashPrefix+apiKey.KeyHash)
	if exists {
		return fmt.Errorf("API key hash already exists")
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		now := time.Now()
		apiKey.CreatedAt = now
		apiKey.UpdatedAt = now

		key := apiKeyPrefix + apiKey.ID
		apiKeyData, err := json.Marshal(apiKey)
		if err != nil {
			return fmt.Errorf("failed to marshal API key: %w", err)
		}

		if err := txn.Set(key, apiKeyData); err != nil {
			return err
		}

		if err := txn.Set(apiKeyHashPrefix+apiKey.KeyHash, []byte(apiKey.ID)); err != nil {
			return err
		}

		indexData, _ := txn.Get(apiKeyIndexKey)
		var keyIDs []string
		if indexData != nil {
			json.Unmarshal(indexData, &keyIDs)
		}
		keyIDs = append(keyIDs, apiKey.ID)

		indexBytes, _ := json.Marshal(keyIDs)
		return txn.Set(apiKeyIndexKey, indexBytes)
	})
}

func (r *BadgerAPIKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.APIKey, error) {
	key := apiKeyPrefix + id.String()

	var apiKey entity.APIKey
	if err := r.client.GetJSON(ctx, key, &apiKey); err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("API key not found")
		}
		return nil, err
	}

	return &apiKey, nil
}

func (r *BadgerAPIKeyRepository) GetByHash(ctx context.Context, keyHash string) (*entity.APIKey, error) {
	keyIDBytes, err := r.client.Get(ctx, apiKeyHashPrefix+keyHash)
	if err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("API key not found")
		}
		return nil, err
	}

	keyID, err := uuid.Parse(string(keyIDBytes))
	if err != nil {
		return nil, fmt.Errorf("invalid API key ID in index: %w", err)
	}

	return r.GetByID(ctx, keyID)
}

func (r *BadgerAPIKeyRepository) Update(ctx context.Context, apiKey *entity.APIKey) error {
	exists, err := r.client.Exists(ctx, apiKeyPrefix+apiKey.ID)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("API key not found")
	}

	apiKey.UpdatedAt = time.Now()

	key := apiKeyPrefix + apiKey.ID
	apiKeyData, err := json.Marshal(apiKey)
	if err != nil {
		return fmt.Errorf("failed to marshal API key: %w", err)
	}

	return r.client.Set(ctx, key, apiKeyData)
}

func (r *BadgerAPIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	apiKey, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		if err := txn.Delete(apiKeyPrefix + id.String()); err != nil {
			return err
		}

		if err := txn.Delete(apiKeyHashPrefix + apiKey.KeyHash); err != nil {
			return err
		}

		indexData, _ := txn.Get(apiKeyIndexKey)
		if indexData != nil {
			var keyIDs []string
			json.Unmarshal(indexData, &keyIDs)

			newIDs := []string{}
			for _, kid := range keyIDs {
				if kid != id.String() {
					newIDs = append(newIDs, kid)
				}
			}

			indexBytes, _ := json.Marshal(newIDs)
			return txn.Set(apiKeyIndexKey, indexBytes)
		}

		return nil
	})
}

func (r *BadgerAPIKeyRepository) List(ctx context.Context, limit, offset int) ([]*entity.APIKey, error) {
	indexData, err := r.client.Get(ctx, apiKeyIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return []*entity.APIKey{}, nil
		}
		return nil, err
	}

	var keyIDs []string
	if err := json.Unmarshal(indexData, &keyIDs); err != nil {
		return nil, err
	}

	start := offset
	if start > len(keyIDs) {
		return []*entity.APIKey{}, nil
	}

	end := start + limit
	if end > len(keyIDs) {
		end = len(keyIDs)
	}

	paginatedIDs := keyIDs[start:end]
	keys := make([]*entity.APIKey, 0, len(paginatedIDs))

	for _, idStr := range paginatedIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue
		}

		apiKey, err := r.GetByID(ctx, id)
		if err != nil {
			continue
		}

		keys = append(keys, apiKey)
	}

	return keys, nil
}

func (r *BadgerAPIKeyRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*entity.APIKey, error) {
	allKeys, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	var userKeys []*entity.APIKey
	for _, key := range allKeys {
		if key.UserID == userID.String() {
			userKeys = append(userKeys, key)
		}
	}

	return userKeys, nil
}

func (r *BadgerAPIKeyRepository) GetByTeamID(ctx context.Context, teamID string) ([]*entity.APIKey, error) {
	allKeys, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	var teamKeys []*entity.APIKey
	for _, key := range allKeys {
		if key.TeamID == teamID {
			teamKeys = append(teamKeys, key)
		}
	}

	return teamKeys, nil
}

func (r *BadgerAPIKeyRepository) Count(ctx context.Context) (int64, error) {
	indexData, err := r.client.Get(ctx, apiKeyIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return 0, nil
		}
		return 0, err
	}

	var keyIDs []string
	if err := json.Unmarshal(indexData, &keyIDs); err != nil {
		return 0, err
	}

	return int64(len(keyIDs)), nil
}

func (r *BadgerAPIKeyRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	apiKey, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	apiKey.LastUsedAt = &now
	apiKey.LastUsedIP = ip
	apiKey.UsageCount++

	return r.Update(ctx, apiKey)
}

func (r *BadgerAPIKeyRepository) GetExpired(ctx context.Context) ([]*entity.APIKey, error) {
	allKeys, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	var expired []*entity.APIKey

	for _, key := range allKeys {
		if key.ExpiresAt != nil && key.ExpiresAt.Before(now) {
			expired = append(expired, key)
		}
	}

	return expired, nil
}

func (r *BadgerAPIKeyRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	apiKey, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	apiKey.IsActive = false
	now := time.Now()
	apiKey.RevokedAt = &now

	return r.Update(ctx, apiKey)
}

func GenerateAPIKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return "pk_" + hex.EncodeToString(bytes), nil
}
