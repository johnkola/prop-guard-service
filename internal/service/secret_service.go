package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
	"github.com/google/uuid"
)

type SecretService interface {
	CreateSecret(ctx context.Context, path string, request *dto.SecretRequest, username string) (*dto.SecretResponse, error)
	GetSecret(ctx context.Context, namespace, path string) (*dto.SecretResponse, error)
	UpdateSecret(ctx context.Context, path string, request *dto.SecretRequest, username string) (*dto.SecretResponse, error)
	DeleteSecret(ctx context.Context, namespace, path string, username string) error
	ListSecrets(ctx context.Context, namespace string, limit, offset int) ([]*dto.SecretResponse, error)
}

type secretService struct {
	secretRepo        repository.SecretRepository
	userRepo          repository.UserRepository
	encryptionService EncryptionService
	auditService      AuditService
}

func NewSecretService(
	secretRepo repository.SecretRepository,
	userRepo repository.UserRepository,
	encryptionService EncryptionService,
	auditService AuditService,
) SecretService {
	return &secretService{
		secretRepo:        secretRepo,
		userRepo:          userRepo,
		encryptionService: encryptionService,
		auditService:      auditService,
	}
}

func (s *secretService) CreateSecret(ctx context.Context, path string, request *dto.SecretRequest, username string) (*dto.SecretResponse, error) {
	if err := s.validatePath(path); err != nil {
		return nil, err
	}

	// For now, using a default namespace - this should come from network context
	namespace := "default"

	// Check if secret already exists
	existing, _ := s.secretRepo.FindByPath(ctx, namespace, path)
	if existing != nil {
		s.auditService.LogAction(ctx, username, "CREATE_SECRET", namespace+":"+path, false, "Secret already exists")
		return nil, fmt.Errorf("secret already exists at path: %s in namespace: %s", path, namespace)
	}

	// Serialize data to JSON
	jsonData, err := json.Marshal(request.Data)
	if err != nil {
		s.auditService.LogAction(ctx, username, "CREATE_SECRET", path, false, "JSON marshaling error")
		return nil, fmt.Errorf("failed to marshal secret data: %w", err)
	}

	// Encrypt the data
	encryptedData, err := s.encryptionService.Encrypt(string(jsonData))
	if err != nil {
		s.auditService.LogAction(ctx, username, "CREATE_SECRET", path, false, "Encryption error")
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Create hash
	dataHash := s.encryptionService.GenerateHash(string(jsonData))

	// Get user UUID
	userUUID, err := s.getUserUUID(ctx, username)
	if err != nil {
		s.auditService.LogAction(ctx, username, "CREATE_SECRET", path, false, "User not found")
		return nil, err
	}

	// Create secret entity
	secret := entity.NewSecret(path, encryptedData, namespace, userUUID)
	secret.DataHash = dataHash
	if request.TTLSeconds != nil {
		secret.SetTTL(*request.TTLSeconds)
	}

	// Save to repository
	if err := s.secretRepo.Create(ctx, secret); err != nil {
		s.auditService.LogAction(ctx, username, "CREATE_SECRET", path, false, err.Error())
		return nil, err
	}

	s.auditService.LogAction(ctx, username, "CREATE_SECRET", namespace+":"+path, true, "Secret created")
	return s.mapToResponse(secret, request.Data), nil
}

func (s *secretService) GetSecret(ctx context.Context, namespace, path string) (*dto.SecretResponse, error) {
	if err := s.validatePath(path); err != nil {
		return nil, err
	}

	secret, err := s.secretRepo.FindByPath(ctx, namespace, path)
	if err != nil {
		return nil, err
	}

	// Decrypt the data
	decryptedData, err := s.encryptionService.Decrypt(secret.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	// Parse JSON data
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret data: %w", err)
	}

	return s.mapToResponse(secret, data), nil
}

func (s *secretService) UpdateSecret(ctx context.Context, path string, request *dto.SecretRequest, username string) (*dto.SecretResponse, error) {
	if err := s.validatePath(path); err != nil {
		return nil, err
	}

	namespace := "default" // Should come from network context

	// Get existing secret
	existingSecret, err := s.secretRepo.FindByPath(ctx, namespace, path)
	if err != nil {
		s.auditService.LogAction(ctx, username, "UPDATE_SECRET", path, false, "Secret not found")
		return nil, fmt.Errorf("secret not found at path: %s", path)
	}

	if existingSecret.IsExpired() {
		s.auditService.LogAction(ctx, username, "UPDATE_SECRET", path, false, "Secret expired")
		return nil, fmt.Errorf("cannot update expired secret")
	}

	// Serialize and encrypt new data
	jsonData, err := json.Marshal(request.Data)
	if err != nil {
		s.auditService.LogAction(ctx, username, "UPDATE_SECRET", path, false, "JSON marshaling error")
		return nil, fmt.Errorf("failed to marshal secret data: %w", err)
	}

	encryptedData, err := s.encryptionService.Encrypt(string(jsonData))
	if err != nil {
		s.auditService.LogAction(ctx, username, "UPDATE_SECRET", path, false, "Encryption error")
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Get user UUID
	userUUID, err := s.getUserUUID(ctx, username)
	if err != nil {
		s.auditService.LogAction(ctx, username, "UPDATE_SECRET", path, false, "User not found")
		return nil, err
	}

	// Update secret
	existingSecret.EncryptedData = encryptedData
	existingSecret.DataHash = s.encryptionService.GenerateHash(string(jsonData))
	existingSecret.UpdatedBy = userUUID
	if request.TTLSeconds != nil {
		existingSecret.SetTTL(*request.TTLSeconds)
	}

	if err := s.secretRepo.Update(ctx, existingSecret); err != nil {
		s.auditService.LogAction(ctx, username, "UPDATE_SECRET", path, false, err.Error())
		return nil, err
	}

	s.auditService.LogAction(ctx, username, "UPDATE_SECRET", namespace+":"+path, true, "Secret updated")
	return s.mapToResponse(existingSecret, request.Data), nil
}

func (s *secretService) DeleteSecret(ctx context.Context, namespace, path string, username string) error {
	if err := s.validatePath(path); err != nil {
		return err
	}

	secret, err := s.secretRepo.FindByPath(ctx, namespace, path)
	if err != nil {
		s.auditService.LogAction(ctx, username, "DELETE_SECRET", path, false, "Secret not found")
		return fmt.Errorf("secret not found at path: %s", path)
	}

	if err := s.secretRepo.Delete(ctx, secret.ID); err != nil {
		s.auditService.LogAction(ctx, username, "DELETE_SECRET", path, false, err.Error())
		return err
	}

	s.auditService.LogAction(ctx, username, "DELETE_SECRET", namespace+":"+path, true, "Secret deleted")
	return nil
}

func (s *secretService) ListSecrets(ctx context.Context, namespace string, limit, offset int) ([]*dto.SecretResponse, error) {
	secrets, err := s.secretRepo.ListByNamespace(ctx, namespace, limit, offset)
	if err != nil {
		return nil, err
	}

	responses := make([]*dto.SecretResponse, 0, len(secrets))
	for _, secret := range secrets {
		// For list operations, we don't decrypt the actual data
		response := &dto.SecretResponse{
			Path:      secret.Path,
			CreatedAt: secret.CreatedAt,
			UpdatedAt: secret.UpdatedAt,
			CreatedBy: secret.CreatedBy,
			UpdatedBy: secret.UpdatedBy,
			Version:   secret.Version,
			ExpiresAt: secret.ExpiresAt,
		}
		responses = append(responses, response)
	}

	return responses, nil
}

func (s *secretService) validatePath(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path must start with /")
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("path cannot contain ..")
	}
	return nil
}

// getUserUUID resolves a username to user UUID
func (s *secretService) getUserUUID(ctx context.Context, username string) (uuid.UUID, error) {
	user, err := s.userRepo.FindByUsername(ctx, username)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("failed to find user %s: %w", username, err)
	}
	return user.ID, nil
}

func (s *secretService) mapToResponse(secret *entity.Secret, data map[string]interface{}) *dto.SecretResponse {
	return &dto.SecretResponse{
		Path:      secret.Path,
		Data:      data,
		CreatedAt: secret.CreatedAt,
		UpdatedAt: secret.UpdatedAt,
		CreatedBy: secret.CreatedBy,
		UpdatedBy: secret.UpdatedBy,
		Version:   secret.Version,
		ExpiresAt: secret.ExpiresAt,
	}
}
