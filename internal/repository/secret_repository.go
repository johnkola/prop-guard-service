package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bazarbozorg/PropGuard/internal/entity"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SecretRepository interface {
	Create(ctx context.Context, secret *entity.Secret) error
	FindByID(ctx context.Context, id uuid.UUID) (*entity.Secret, error)
	FindByPath(ctx context.Context, namespace, path string) (*entity.Secret, error)
	Update(ctx context.Context, secret *entity.Secret) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListByNamespace(ctx context.Context, namespace string, limit, offset int) ([]*entity.Secret, error)
	ListExpired(ctx context.Context) ([]*entity.Secret, error)
	DeleteExpired(ctx context.Context) (int64, error)
}

type secretRepository struct {
	collection *mongo.Collection
}

func NewSecretRepository(db *MongoDB) SecretRepository {
	return &secretRepository{
		collection: db.Collection("secrets"),
	}
}

func (r *secretRepository) Create(ctx context.Context, secret *entity.Secret) error {
	secret.CreatedAt = time.Now()
	secret.UpdatedAt = time.Now()

	_, err := r.collection.InsertOne(ctx, secret)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fmt.Errorf("secret already exists at this path")
		}
		return fmt.Errorf("failed to create secret: %w", err)
	}
	return nil
}

func (r *secretRepository) FindByID(ctx context.Context, id uuid.UUID) (*entity.Secret, error) {
	var secret entity.Secret
	err := r.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&secret)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("failed to find secret: %w", err)
	}

	// Check if secret is expired
	if secret.IsExpired() {
		return nil, fmt.Errorf("secret has expired")
	}

	return &secret, nil
}

func (r *secretRepository) FindByPath(ctx context.Context, namespace, path string) (*entity.Secret, error) {
	var secret entity.Secret
	filter := bson.M{
		"networkNamespace": namespace,
		"path":             path,
	}

	err := r.collection.FindOne(ctx, filter).Decode(&secret)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("failed to find secret: %w", err)
	}

	// Check if secret is expired
	if secret.IsExpired() {
		return nil, fmt.Errorf("secret has expired")
	}

	return &secret, nil
}

func (r *secretRepository) Update(ctx context.Context, secret *entity.Secret) error {
	filter := bson.M{"_id": secret.ID, "version": secret.Version}
	secret.Version++
	secret.UpdatedAt = time.Now()

	update := bson.M{
		"$set": secret,
	}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	if result.MatchedCount == 0 {
		return fmt.Errorf("secret not found or version mismatch")
	}

	return nil
}

func (r *secretRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("secret not found")
	}

	return nil
}

func (r *secretRepository) ListByNamespace(ctx context.Context, namespace string, limit, offset int) ([]*entity.Secret, error) {
	filter := bson.M{
		"networkNamespace": namespace,
		"$or": []bson.M{
			{"expiresAt": nil},
			{"expiresAt": bson.M{"$gt": time.Now()}},
		},
	}

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(offset)).
		SetSort(bson.M{"path": 1})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer cursor.Close(ctx)

	var secrets []*entity.Secret
	if err := cursor.All(ctx, &secrets); err != nil {
		return nil, fmt.Errorf("failed to decode secrets: %w", err)
	}

	return secrets, nil
}

func (r *secretRepository) ListExpired(ctx context.Context) ([]*entity.Secret, error) {
	filter := bson.M{
		"expiresAt": bson.M{
			"$ne": nil,
			"$lt": time.Now(),
		},
	}

	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list expired secrets: %w", err)
	}
	defer cursor.Close(ctx)

	var secrets []*entity.Secret
	if err := cursor.All(ctx, &secrets); err != nil {
		return nil, fmt.Errorf("failed to decode expired secrets: %w", err)
	}

	return secrets, nil
}

func (r *secretRepository) DeleteExpired(ctx context.Context) (int64, error) {
	filter := bson.M{
		"expiresAt": bson.M{
			"$ne": nil,
			"$lt": time.Now(),
		},
	}

	result, err := r.collection.DeleteMany(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired secrets: %w", err)
	}

	return result.DeletedCount, nil
}
