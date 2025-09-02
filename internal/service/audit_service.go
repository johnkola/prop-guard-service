package service

import (
	"context"
	"fmt"
	"time"

	"github.com/bazarbozorg/PropGuard/internal/entity"
	"github.com/bazarbozorg/PropGuard/internal/repository"
)

type AuditService interface {
	LogAction(ctx context.Context, username, action, path string, success bool, details string)
	LogUserOperation(ctx context.Context, username, action, targetUser string, success bool, details string)
	GetUserAuditLogs(ctx context.Context, username string, limit, offset int) ([]*entity.AuditLog, error)
	GetPathAuditLogs(ctx context.Context, path string, limit, offset int) ([]*entity.AuditLog, error)
	GetAuditLogsByDateRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*entity.AuditLog, error)
	CleanupOldLogs(ctx context.Context, days int) (int64, error)
}

type auditService struct {
	auditRepo repository.AuditRepository
}

func NewAuditService(auditRepo repository.AuditRepository) AuditService {
	return &auditService{
		auditRepo: auditRepo,
	}
}

func (s *auditService) LogAction(ctx context.Context, username, action, path string, success bool, details string) {
	log := entity.NewAuditLog(username, action, path, success)
	log.Details = details

	// Extract client info from context if available
	// This would typically come from HTTP middleware
	if clientIP, ok := ctx.Value("clientIP").(string); ok {
		log.ClientIP = clientIP
	}
	if userAgent, ok := ctx.Value("userAgent").(string); ok {
		log.UserAgent = userAgent
	}

	if !success && details != "" {
		log.SetError(details)
	}

	// Log asynchronously to avoid blocking the main operation
	go func() {
		// Create a new context with timeout for the audit log operation
		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = s.auditRepo.Create(auditCtx, log)
	}()
}

func (s *auditService) GetUserAuditLogs(ctx context.Context, username string, limit, offset int) ([]*entity.AuditLog, error) {
	return s.auditRepo.ListByUsername(ctx, username, limit, offset)
}

func (s *auditService) GetPathAuditLogs(ctx context.Context, path string, limit, offset int) ([]*entity.AuditLog, error) {
	return s.auditRepo.ListByPath(ctx, path, limit, offset)
}

func (s *auditService) GetAuditLogsByDateRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*entity.AuditLog, error) {
	return s.auditRepo.ListByDateRange(ctx, start, end, limit, offset)
}

func (s *auditService) LogUserOperation(ctx context.Context, username, action, targetUser string, success bool, details string) {
	// Use targetUser as the "path" for user operations to maintain consistency with existing schema
	s.LogAction(ctx, username, action, fmt.Sprintf("user:%s", targetUser), success, details)
}

func (s *auditService) CleanupOldLogs(ctx context.Context, days int) (int64, error) {
	return s.auditRepo.DeleteOlderThan(ctx, days)
}
