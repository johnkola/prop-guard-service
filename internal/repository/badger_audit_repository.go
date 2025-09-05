package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"PropGuard/internal/entity"

	"github.com/google/uuid"
)

type BadgerAuditRepository struct {
	client        *BadgerClient
	retentionDays int
}

func NewBadgerAuditRepository(client *BadgerClient, retentionDays int) *BadgerAuditRepository {
	return &BadgerAuditRepository{
		client:        client,
		retentionDays: retentionDays,
	}
}

const (
	auditKeyPrefix = "audit:"
	auditIndexKey  = "audits:index"
)

func (r *BadgerAuditRepository) Create(ctx context.Context, audit *entity.AuditLog) error {
	key := auditKeyPrefix + audit.ID.String()

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		audit.Timestamp = time.Now()

		auditData, err := json.Marshal(audit)
		if err != nil {
			return fmt.Errorf("failed to marshal audit: %w", err)
		}

		if err := txn.Set(key, auditData); err != nil {
			return err
		}

		indexData, _ := txn.Get(auditIndexKey)
		var auditIDs []string
		if indexData != nil {
			json.Unmarshal(indexData, &auditIDs)
		}
		auditIDs = append(auditIDs, audit.ID.String())

		indexBytes, _ := json.Marshal(auditIDs)
		return txn.Set(auditIndexKey, indexBytes)
	})
}

func (r *BadgerAuditRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.AuditLog, error) {
	key := auditKeyPrefix + id.String()

	var audit entity.AuditLog
	if err := r.client.GetJSON(ctx, key, &audit); err != nil {
		if err == ErrNotFound {
			return nil, fmt.Errorf("audit log not found")
		}
		return nil, err
	}

	return &audit, nil
}

func (r *BadgerAuditRepository) List(ctx context.Context, limit, offset int) ([]*entity.AuditLog, error) {
	indexData, err := r.client.Get(ctx, auditIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return []*entity.AuditLog{}, nil
		}
		return nil, err
	}

	var auditIDs []string
	if err := json.Unmarshal(indexData, &auditIDs); err != nil {
		return nil, err
	}

	start := offset
	if start > len(auditIDs) {
		return []*entity.AuditLog{}, nil
	}

	end := start + limit
	if end > len(auditIDs) {
		end = len(auditIDs)
	}

	paginatedIDs := auditIDs[start:end]
	audits := make([]*entity.AuditLog, 0, len(paginatedIDs))

	for _, idStr := range paginatedIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue
		}

		audit, err := r.GetByID(ctx, id)
		if err != nil {
			continue
		}

		audits = append(audits, audit)
	}

	return audits, nil
}

func (r *BadgerAuditRepository) GetByUsername(ctx context.Context, username string, limit, offset int) ([]*entity.AuditLog, error) {
	allAudits, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	var userAudits []*entity.AuditLog
	for _, audit := range allAudits {
		if audit.Username == username {
			userAudits = append(userAudits, audit)
		}
	}

	start := offset
	if start > len(userAudits) {
		return []*entity.AuditLog{}, nil
	}

	end := start + limit
	if end > len(userAudits) {
		end = len(userAudits)
	}

	return userAudits[start:end], nil
}

func (r *BadgerAuditRepository) GetByAction(ctx context.Context, action string, limit, offset int) ([]*entity.AuditLog, error) {
	allAudits, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	var actionAudits []*entity.AuditLog
	for _, audit := range allAudits {
		if audit.Action == action {
			actionAudits = append(actionAudits, audit)
		}
	}

	start := offset
	if start > len(actionAudits) {
		return []*entity.AuditLog{}, nil
	}

	end := start + limit
	if end > len(actionAudits) {
		end = len(actionAudits)
	}

	return actionAudits[start:end], nil
}

func (r *BadgerAuditRepository) GetByDateRange(ctx context.Context, startDate, endDate time.Time, limit, offset int) ([]*entity.AuditLog, error) {
	allAudits, err := r.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	var rangeAudits []*entity.AuditLog
	for _, audit := range allAudits {
		if audit.Timestamp.After(startDate) && audit.Timestamp.Before(endDate) {
			rangeAudits = append(rangeAudits, audit)
		}
	}

	start := offset
	if start > len(rangeAudits) {
		return []*entity.AuditLog{}, nil
	}

	end := start + limit
	if end > len(rangeAudits) {
		end = len(rangeAudits)
	}

	return rangeAudits[start:end], nil
}

func (r *BadgerAuditRepository) Count(ctx context.Context) (int64, error) {
	indexData, err := r.client.Get(ctx, auditIndexKey)
	if err != nil {
		if err == ErrNotFound {
			return 0, nil
		}
		return 0, err
	}

	var auditIDs []string
	if err := json.Unmarshal(indexData, &auditIDs); err != nil {
		return 0, err
	}

	return int64(len(auditIDs)), nil
}

func (r *BadgerAuditRepository) DeleteOldAudits(ctx context.Context) error {
	if r.retentionDays <= 0 {
		return nil
	}

	cutoffDate := time.Now().AddDate(0, 0, -r.retentionDays)
	allAudits, err := r.List(ctx, 10000, 0)
	if err != nil {
		return err
	}

	var toDelete []uuid.UUID
	for _, audit := range allAudits {
		if audit.Timestamp.Before(cutoffDate) {
			toDelete = append(toDelete, audit.ID)
		}
	}

	return r.client.Transaction(ctx, func(txn *Transaction) error {
		for _, id := range toDelete {
			key := auditKeyPrefix + id.String()
			if err := txn.Delete(key); err != nil {
				return err
			}
		}

		indexData, _ := txn.Get(auditIndexKey)
		if indexData != nil {
			var auditIDs []string
			json.Unmarshal(indexData, &auditIDs)

			newIDs := []string{}
			for _, aid := range auditIDs {
				found := false
				for _, delID := range toDelete {
					if aid == delID.String() {
						found = true
						break
					}
				}
				if !found {
					newIDs = append(newIDs, aid)
				}
			}

			indexBytes, _ := json.Marshal(newIDs)
			return txn.Set(auditIndexKey, indexBytes)
		}

		return nil
	})
}
