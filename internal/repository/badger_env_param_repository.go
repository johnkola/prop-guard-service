package repository

import (
	"context"
	"fmt"
	"strings"

	"PropGuard/internal/entity"
)

type BadgerEnvParamRepository struct {
	client *BadgerClient
}

func NewBadgerEnvParamRepository(client *BadgerClient) *BadgerEnvParamRepository {
	return &BadgerEnvParamRepository{client: client}
}

// GetByKey retrieves an environment parameter by key and environment
func (r *BadgerEnvParamRepository) GetByKey(ctx context.Context, key, environment string) (*entity.EnvParam, error) {
	paramKey := fmt.Sprintf("env_param:%s:%s", environment, key)

	var param entity.EnvParam
	err := r.client.GetJSON(ctx, paramKey, &param)
	if err != nil {
		return nil, err
	}

	return &param, nil
}

// GetMultiple retrieves multiple environment parameters by keys
func (r *BadgerEnvParamRepository) GetMultiple(ctx context.Context, keys []string, environment string) (map[string]*entity.EnvParam, error) {
	results := make(map[string]*entity.EnvParam)

	for _, key := range keys {
		param, err := r.GetByKey(ctx, key, environment)
		if err == nil && param != nil {
			results[key] = param
		}
	}

	return results, nil
}

// Create creates a new environment parameter
func (r *BadgerEnvParamRepository) Create(ctx context.Context, param *entity.EnvParam) error {
	paramKey := fmt.Sprintf("env_param:%s:%s", param.Environment, param.Key)

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Store the parameter
		if err := r.client.SetJSON(ctx, paramKey, param); err != nil {
			return err
		}

		// Update environment index
		envIndexKey := fmt.Sprintf("env_params:index:%s", param.Environment)
		var paramKeys []string
		if err := r.client.GetJSON(ctx, envIndexKey, &paramKeys); err == nil {
			// Add key if not exists
			exists := false
			for _, existingKey := range paramKeys {
				if existingKey == param.Key {
					exists = true
					break
				}
			}
			if !exists {
				paramKeys = append(paramKeys, param.Key)
			}
		} else {
			paramKeys = []string{param.Key}
		}

		if err := r.client.SetJSON(ctx, envIndexKey, paramKeys); err != nil {
			return err
		}

		// Update global index
		globalIndexKey := "env_params:global_index"
		var globalKeys []string
		if err := r.client.GetJSON(ctx, globalIndexKey, &globalKeys); err == nil {
			globalKey := fmt.Sprintf("%s:%s", param.Environment, param.Key)
			exists := false
			for _, existingKey := range globalKeys {
				if existingKey == globalKey {
					exists = true
					break
				}
			}
			if !exists {
				globalKeys = append(globalKeys, globalKey)
			}
		} else {
			globalKeys = []string{fmt.Sprintf("%s:%s", param.Environment, param.Key)}
		}

		return r.client.SetJSON(ctx, globalIndexKey, globalKeys)
	})
}

// Update updates an environment parameter
func (r *BadgerEnvParamRepository) Update(ctx context.Context, param *entity.EnvParam) error {
	paramKey := fmt.Sprintf("env_param:%s:%s", param.Environment, param.Key)
	return r.client.SetJSON(ctx, paramKey, param)
}

// Delete deletes an environment parameter
func (r *BadgerEnvParamRepository) Delete(ctx context.Context, key, environment string) error {
	paramKey := fmt.Sprintf("env_param:%s:%s", environment, key)

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		// Delete the parameter
		if err := r.client.Delete(ctx, paramKey); err != nil {
			return err
		}

		// Update environment index
		envIndexKey := fmt.Sprintf("env_params:index:%s", environment)
		var paramKeys []string
		if err := r.client.GetJSON(ctx, envIndexKey, &paramKeys); err == nil {
			var updatedKeys []string
			for _, existingKey := range paramKeys {
				if existingKey != key {
					updatedKeys = append(updatedKeys, existingKey)
				}
			}
			if err := r.client.SetJSON(ctx, envIndexKey, updatedKeys); err != nil {
				return err
			}
		}

		// Update global index
		globalIndexKey := "env_params:global_index"
		var globalKeys []string
		if err := r.client.GetJSON(ctx, globalIndexKey, &globalKeys); err == nil {
			var updatedGlobalKeys []string
			targetKey := fmt.Sprintf("%s:%s", environment, key)
			for _, existingKey := range globalKeys {
				if existingKey != targetKey {
					updatedGlobalKeys = append(updatedGlobalKeys, existingKey)
				}
			}
			return r.client.SetJSON(ctx, globalIndexKey, updatedGlobalKeys)
		}

		return nil
	})
}

// List lists environment parameters for a specific environment with pagination
func (r *BadgerEnvParamRepository) List(ctx context.Context, environment string, limit, offset int) ([]*entity.EnvParam, error) {
	envIndexKey := fmt.Sprintf("env_params:index:%s", environment)

	var paramKeys []string
	if err := r.client.GetJSON(ctx, envIndexKey, &paramKeys); err != nil {
		return []*entity.EnvParam{}, nil // Return empty if index doesn't exist
	}

	// Apply pagination
	start := offset
	if start >= len(paramKeys) {
		return []*entity.EnvParam{}, nil
	}

	end := start + limit
	if end > len(paramKeys) {
		end = len(paramKeys)
	}

	paginatedKeys := paramKeys[start:end]

	var params []*entity.EnvParam
	for _, key := range paginatedKeys {
		param, err := r.GetByKey(ctx, key, environment)
		if err == nil && param != nil {
			params = append(params, param)
		}
	}

	return params, nil
}

// ListAll lists all environment parameters across all environments with pagination
func (r *BadgerEnvParamRepository) ListAll(ctx context.Context, limit, offset int) ([]*entity.EnvParam, error) {
	globalIndexKey := "env_params:global_index"

	var globalKeys []string
	if err := r.client.GetJSON(ctx, globalIndexKey, &globalKeys); err != nil {
		return []*entity.EnvParam{}, nil // Return empty if index doesn't exist
	}

	// Apply pagination
	start := offset
	if start >= len(globalKeys) {
		return []*entity.EnvParam{}, nil
	}

	end := start + limit
	if end > len(globalKeys) {
		end = len(globalKeys)
	}

	paginatedKeys := globalKeys[start:end]

	var params []*entity.EnvParam
	for _, globalKey := range paginatedKeys {
		parts := strings.SplitN(globalKey, ":", 2)
		if len(parts) == 2 {
			environment := parts[0]
			key := parts[1]
			param, err := r.GetByKey(ctx, key, environment)
			if err == nil && param != nil {
				params = append(params, param)
			}
		}
	}

	return params, nil
}

// Count counts environment parameters for a specific environment
func (r *BadgerEnvParamRepository) Count(ctx context.Context, environment string) (int, error) {
	envIndexKey := fmt.Sprintf("env_params:index:%s", environment)

	var paramKeys []string
	if err := r.client.GetJSON(ctx, envIndexKey, &paramKeys); err != nil {
		return 0, nil // Return 0 if index doesn't exist
	}

	return len(paramKeys), nil
}

// CountAll counts all environment parameters across all environments
func (r *BadgerEnvParamRepository) CountAll(ctx context.Context) (int, error) {
	globalIndexKey := "env_params:global_index"

	var globalKeys []string
	if err := r.client.GetJSON(ctx, globalIndexKey, &globalKeys); err != nil {
		return 0, nil // Return 0 if index doesn't exist
	}

	return len(globalKeys), nil
}

// GetEnvironments returns all environments that have parameters
func (r *BadgerEnvParamRepository) GetEnvironments(ctx context.Context) ([]string, error) {
	globalIndexKey := "env_params:global_index"

	var globalKeys []string
	if err := r.client.GetJSON(ctx, globalIndexKey, &globalKeys); err != nil {
		return []string{}, nil // Return empty if index doesn't exist
	}

	envSet := make(map[string]bool)
	for _, globalKey := range globalKeys {
		parts := strings.SplitN(globalKey, ":", 2)
		if len(parts) == 2 {
			envSet[parts[0]] = true
		}
	}

	var environments []string
	for env := range envSet {
		environments = append(environments, env)
	}

	return environments, nil
}
