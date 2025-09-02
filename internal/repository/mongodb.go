package repository

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type MongoDB struct {
	Client   *mongo.Client
	Database *mongo.Database
}

func NewMongoDB(uri, dbName string) (*MongoDB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().
		ApplyURI(uri).
		SetMaxPoolSize(100).
		SetMinPoolSize(10).
		SetMaxConnIdleTime(5 * time.Minute)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	database := client.Database(dbName)

	return &MongoDB{
		Client:   client,
		Database: database,
	}, nil
}

func (m *MongoDB) Disconnect(ctx context.Context) error {
	return m.Client.Disconnect(ctx)
}

func (m *MongoDB) Collection(name string) *mongo.Collection {
	return m.Database.Collection(name)
}

func (m *MongoDB) CreateIndexes(ctx context.Context) error {
	// Create indexes for vault_users collection
	usersCol := m.Collection("vault_users")
	_, err := usersCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    map[string]int{"username": 1},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create username index: %w", err)
	}

	// Create indexes for secrets collection
	secretsCol := m.Collection("secrets")
	secretIndexes := []mongo.IndexModel{
		{
			Keys: map[string]int{
				"networkNamespace": 1,
				"path":             1,
			},
			Options: options.Index().SetUnique(true).SetName("idx_namespace_path"),
		},
		{
			Keys: map[string]int{
				"networkNamespace": 1,
				"networkSegment":   1,
			},
			Options: options.Index().SetName("idx_namespace_segment"),
		},
		{
			Keys: map[string]int{
				"path":    1,
				"version": 1,
			},
			Options: options.Index().SetName("idx_path_version"),
		},
		{
			Keys: map[string]int{"createdBy": 1},
		},
		{
			Keys: map[string]int{"expiresAt": 1},
		},
	}
	_, err = secretsCol.Indexes().CreateMany(ctx, secretIndexes)
	if err != nil {
		return fmt.Errorf("failed to create secret indexes: %w", err)
	}

	// Create indexes for audit_logs collection
	auditCol := m.Collection("audit_logs")
	auditIndexes := []mongo.IndexModel{
		{
			Keys: map[string]int{
				"username": 1,
				"action":   1,
			},
			Options: options.Index().SetName("idx_username_action"),
		},
		{
			Keys: map[string]int{
				"timestamp":  1,
				"secretPath": 1,
			},
			Options: options.Index().SetName("idx_timestamp_path"),
		},
		{
			Keys: map[string]int{"username": 1},
		},
		{
			Keys: map[string]int{"action": 1},
		},
		{
			Keys: map[string]int{"secretPath": 1},
		},
		{
			Keys: map[string]int{"timestamp": 1},
		},
	}
	_, err = auditCol.Indexes().CreateMany(ctx, auditIndexes)
	if err != nil {
		return fmt.Errorf("failed to create audit indexes: %w", err)
	}

	// Create indexes for secret_policies collection
	policiesCol := m.Collection("secret_policies")
	_, err = policiesCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    map[string]int{"name": 1},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("failed to create policy name index: %w", err)
	}

	// Create indexes for secret_rotation_history collection
	rotationCol := m.Collection("secret_rotation_history")
	rotationIndexes := []mongo.IndexModel{
		{
			Keys: map[string]int{
				"secretPath":        1,
				"rotationTimestamp": 1,
			},
			Options: options.Index().SetName("idx_path_timestamp"),
		},
		{
			Keys: map[string]int{
				"status":            1,
				"rotationTimestamp": -1,
			},
			Options: options.Index().SetName("idx_status_timestamp"),
		},
		{
			Keys: map[string]int{"secretPath": 1},
		},
		{
			Keys: map[string]int{"status": 1},
		},
		{
			Keys: map[string]int{"rotationTimestamp": 1},
		},
	}
	_, err = rotationCol.Indexes().CreateMany(ctx, rotationIndexes)
	if err != nil {
		return fmt.Errorf("failed to create rotation history indexes: %w", err)
	}

	return nil
}
