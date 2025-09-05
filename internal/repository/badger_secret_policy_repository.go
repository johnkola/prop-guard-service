package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"PropGuard/internal/entity"

	"github.com/google/uuid"
)

type BadgerSecretPolicyRepository struct {
	client *BadgerClient
}

func NewBadgerSecretPolicyRepository(client *BadgerClient) *BadgerSecretPolicyRepository {
	return &BadgerSecretPolicyRepository{
		client: client,
	}
}

const (
	secretPolicyPrefix   = "secret_policy:"
	secretPolicyIndexKey = "secret_policies:index"
)

func (r *BadgerSecretPolicyRepository) Create(ctx context.Context, policy *entity.SecretPolicy) error {
	return r.client.Transaction(ctx, func(txn *Transaction) error {
		now := time.Now()
		policy.CreatedAt = now
		policy.UpdatedAt = now
		policy.Version = 1

		key := secretPolicyPrefix + policy.ID.String()
		policyData, err := json.Marshal(policy)
		if err != nil {
			return fmt.Errorf("failed to marshal secret policy: %w", err)
		}

		if err := txn.Set(key, policyData); err != nil {
			return err
		}

		// Update index
		indexData, _ := txn.Get(secretPolicyIndexKey)
		var policyIDs []string
		if indexData != nil {
			json.Unmarshal(indexData, &policyIDs)
		}

		policyIDs = append(policyIDs, policy.ID.String())
		indexBytes, _ := json.Marshal(policyIDs)
		return txn.Set(secretPolicyIndexKey, indexBytes)
	})
}

func (r *BadgerSecretPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.SecretPolicy, error) {
	key := secretPolicyPrefix + id.String()
	data, err := r.client.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var policy entity.SecretPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret policy: %w", err)
	}

	return &policy, nil
}

func (r *BadgerSecretPolicyRepository) Update(ctx context.Context, policy *entity.SecretPolicy) error {
	exists, err := r.client.Exists(ctx, secretPolicyPrefix+policy.ID.String())
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("secret policy not found")
	}

	policy.UpdatedAt = time.Now()
	policy.Version++

	key := secretPolicyPrefix + policy.ID.String()
	policyData, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal secret policy: %w", err)
	}

	return r.client.Set(ctx, key, policyData)
}

func (r *BadgerSecretPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.client.Transaction(ctx, func(txn *Transaction) error {
		if err := txn.Delete(secretPolicyPrefix + id.String()); err != nil {
			return err
		}

		// Update index
		indexData, _ := txn.Get(secretPolicyIndexKey)
		if indexData != nil {
			var policyIDs []string
			json.Unmarshal(indexData, &policyIDs)

			newIDs := []string{}
			for _, pid := range policyIDs {
				if pid != id.String() {
					newIDs = append(newIDs, pid)
				}
			}

			indexBytes, _ := json.Marshal(newIDs)
			return txn.Set(secretPolicyIndexKey, indexBytes)
		}

		return nil
	})
}

func (r *BadgerSecretPolicyRepository) List(ctx context.Context, limit, offset int) ([]*entity.SecretPolicy, error) {
	indexData, err := r.client.Get(ctx, secretPolicyIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return []*entity.SecretPolicy{}, nil
		}
		return nil, err
	}

	var policyIDs []string
	if err := json.Unmarshal(indexData, &policyIDs); err != nil {
		return nil, err
	}

	start := offset
	if start > len(policyIDs) {
		return []*entity.SecretPolicy{}, nil
	}

	end := start + limit
	if end > len(policyIDs) {
		end = len(policyIDs)
	}

	paginatedIDs := policyIDs[start:end]
	policies := make([]*entity.SecretPolicy, 0, len(paginatedIDs))

	for _, idStr := range paginatedIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue
		}

		policy, err := r.GetByID(ctx, id)
		if err != nil {
			continue
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

func (r *BadgerSecretPolicyRepository) Count(ctx context.Context) (int64, error) {
	indexData, err := r.client.Get(ctx, secretPolicyIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return 0, nil
		}
		return 0, err
	}

	var policyIDs []string
	if err := json.Unmarshal(indexData, &policyIDs); err != nil {
		return 0, err
	}

	return int64(len(policyIDs)), nil
}

// GetPolicyByPath finds the most specific policy that matches the given path
func (r *BadgerSecretPolicyRepository) GetPolicyByPath(ctx context.Context, path string) (*entity.SecretPolicy, error) {
	// Get all enabled policies
	allPolicies, err := r.GetEnabledPolicies(ctx)
	if err != nil {
		return nil, err
	}

	var bestMatch *entity.SecretPolicy
	maxScore := 0

	for _, policy := range allPolicies {
		if r.pathMatches(path, policy.PathPattern) {
			score := r.calculateMatchScore(path, policy.PathPattern)
			if score > maxScore {
				maxScore = score
				bestMatch = policy
			}
		}
	}

	if bestMatch == nil {
		return nil, fmt.Errorf("no policy found for path: %s", path)
	}

	return bestMatch, nil
}

func (r *BadgerSecretPolicyRepository) GetEnabledPolicies(ctx context.Context) ([]*entity.SecretPolicy, error) {
	allPolicies, err := r.List(ctx, 1000, 0) // Get all policies
	if err != nil {
		return nil, err
	}

	var enabledPolicies []*entity.SecretPolicy
	for _, policy := range allPolicies {
		if policy.Enabled {
			enabledPolicies = append(enabledPolicies, policy)
		}
	}

	return enabledPolicies, nil
}

func (r *BadgerSecretPolicyRepository) GetPoliciesByType(ctx context.Context, secretType entity.SecretType) ([]*entity.SecretPolicy, error) {
	allPolicies, err := r.GetEnabledPolicies(ctx)
	if err != nil {
		return nil, err
	}

	var typePolicies []*entity.SecretPolicy
	for _, policy := range allPolicies {
		if policy.SecretType == secretType {
			typePolicies = append(typePolicies, policy)
		}
	}

	return typePolicies, nil
}

// Helper methods for path matching
func (r *BadgerSecretPolicyRepository) pathMatches(path, pattern string) bool {
	matched, _ := filepath.Match(pattern, path)
	return matched
}

func (r *BadgerSecretPolicyRepository) calculateMatchScore(path, pattern string) int {
	// More specific patterns (fewer wildcards) get higher scores
	wildcardCount := strings.Count(pattern, "*") + strings.Count(pattern, "?")
	baseScore := len(pattern) - wildcardCount

	// Exact matches get bonus points
	if path == pattern {
		baseScore += 100
	}

	return baseScore
}
