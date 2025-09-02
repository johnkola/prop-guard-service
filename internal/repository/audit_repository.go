package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/bazarbozorg/PropGuard/internal/entity"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type AuditRepository interface {
	Create(ctx context.Context, log *entity.AuditLog) error
	ListByUsername(ctx context.Context, username string, limit, offset int) ([]*entity.AuditLog, error)
	ListByPath(ctx context.Context, path string, limit, offset int) ([]*entity.AuditLog, error)
	ListByDateRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*entity.AuditLog, error)
	DeleteOlderThan(ctx context.Context, days int) (int64, error)
}

type auditRepository struct {
	collection *mongo.Collection
}

func NewAuditRepository(db *MongoDB) AuditRepository {
	return &auditRepository{
		collection: db.Collection("audit_logs"),
	}
}

func (r *auditRepository) Create(ctx context.Context, log *entity.AuditLog) error {
	log.Timestamp = time.Now()

	_, err := r.collection.InsertOne(ctx, log)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

func (r *auditRepository) ListByUsername(ctx context.Context, username string, limit, offset int) ([]*entity.AuditLog, error) {
	filter := bson.M{"username": username}

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(offset)).
		SetSort(bson.M{"timestamp": -1})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer cursor.Close(ctx)

	var logs []*entity.AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, fmt.Errorf("failed to decode audit logs: %w", err)
	}

	return logs, nil
}

func (r *auditRepository) ListByPath(ctx context.Context, path string, limit, offset int) ([]*entity.AuditLog, error) {
	filter := bson.M{"secretPath": path}

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(offset)).
		SetSort(bson.M{"timestamp": -1})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer cursor.Close(ctx)

	var logs []*entity.AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, fmt.Errorf("failed to decode audit logs: %w", err)
	}

	return logs, nil
}

func (r *auditRepository) ListByDateRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*entity.AuditLog, error) {
	filter := bson.M{
		"timestamp": bson.M{
			"$gte": start,
			"$lte": end,
		},
	}

	opts := options.Find().
		SetLimit(int64(limit)).
		SetSkip(int64(offset)).
		SetSort(bson.M{"timestamp": -1})

	cursor, err := r.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer cursor.Close(ctx)

	var logs []*entity.AuditLog
	if err := cursor.All(ctx, &logs); err != nil {
		return nil, fmt.Errorf("failed to decode audit logs: %w", err)
	}

	return logs, nil
}

func (r *auditRepository) DeleteOlderThan(ctx context.Context, days int) (int64, error) {
	cutoffDate := time.Now().AddDate(0, 0, -days)

	filter := bson.M{
		"timestamp": bson.M{
			"$lt": cutoffDate,
		},
	}

	result, err := r.collection.DeleteMany(ctx, filter)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old audit logs: %w", err)
	}

	return result.DeletedCount, nil
}
