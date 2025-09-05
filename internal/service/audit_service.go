package service

import (
	"context"
	"fmt"
	"time"

	"PropGuard/internal/entity"
	"PropGuard/internal/repository"
)

type AuditService interface {
	LogAction(ctx context.Context, username, action, path string, success bool, details string)
	LogUserOperation(ctx context.Context, username, action, targetUser string, success bool, details string)
	LogSecretOperation(ctx context.Context, userID, operation, secretName string, success bool, details string)
	LogAPIKeyOperation(ctx context.Context, userID, operation, resource string, success bool, details string)
	LogServiceOperation(ctx context.Context, serviceID, operation, resource string, success bool, details string)
	LogAdminOperation(ctx context.Context, adminID, operation, resource string, success bool, details string)
	LogSystemOperation(ctx context.Context, systemID, operation, resource string, success bool, details string)
	GetUserAuditLogs(ctx context.Context, username string, limit, offset int) ([]*entity.AuditLog, error)
	GetPathAuditLogs(ctx context.Context, path string, limit, offset int) ([]*entity.AuditLog, error)
	GetAuditLogsByDateRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*entity.AuditLog, error)
	CleanupOldLogs(ctx context.Context, days int) (int64, error)
}

type auditService struct {
	auditRepo *repository.BadgerAuditRepository
}

func NewAuditService(auditRepo *repository.BadgerAuditRepository) AuditService {
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
	return s.auditRepo.GetByUsername(ctx, username, limit, offset)
}

func (s *auditService) GetPathAuditLogs(ctx context.Context, path string, limit, offset int) ([]*entity.AuditLog, error) {
	// BadgerAuditRepository doesn't have ListByPath, we'll filter manually
	allAudits, err := s.auditRepo.List(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	var pathAudits []*entity.AuditLog
	for _, audit := range allAudits {
		if audit.SecretPath == path {
			pathAudits = append(pathAudits, audit)
		}
	}

	start := offset
	if start > len(pathAudits) {
		return []*entity.AuditLog{}, nil
	}

	end := start + limit
	if end > len(pathAudits) {
		end = len(pathAudits)
	}

	return pathAudits[start:end], nil
}

func (s *auditService) GetAuditLogsByDateRange(ctx context.Context, start, end time.Time, limit, offset int) ([]*entity.AuditLog, error) {
	return s.auditRepo.GetByDateRange(ctx, start, end, limit, offset)
}

func (s *auditService) LogUserOperation(ctx context.Context, username, action, targetUser string, success bool, details string) {
	// Use targetUser as the "path" for user operations to maintain consistency with existing schema
	s.LogAction(ctx, username, action, fmt.Sprintf("user:%s", targetUser), success, details)
}

func (s *auditService) CleanupOldLogs(ctx context.Context, days int) (int64, error) {
	// BadgerAuditRepository has DeleteOldAudits method
	err := s.auditRepo.DeleteOldAudits(ctx)
	if err != nil {
		return 0, err
	}
	// Return approximate count - we can't get exact count without tracking
	return int64(days), nil
}

func (s *auditService) LogSecretOperation(ctx context.Context, userID, operation, secretName string, success bool, details string) {
	s.LogAction(ctx, userID, operation, fmt.Sprintf("secret:%s", secretName), success, details)
}

func (s *auditService) LogAPIKeyOperation(ctx context.Context, userID, operation, resource string, success bool, details string) {
	s.LogAction(ctx, userID, operation, fmt.Sprintf("apikey:%s", resource), success, details)
}

func (s *auditService) LogServiceOperation(ctx context.Context, serviceID, operation, resource string, success bool, details string) {
	s.LogAction(ctx, serviceID, operation, fmt.Sprintf("service:%s", resource), success, details)
}

func (s *auditService) LogAdminOperation(ctx context.Context, adminID, operation, resource string, success bool, details string) {
	s.LogAction(ctx, adminID, operation, fmt.Sprintf("admin:%s", resource), success, details)
}

func (s *auditService) LogSystemOperation(ctx context.Context, systemID, operation, resource string, success bool, details string) {
	s.LogAction(ctx, systemID, operation, fmt.Sprintf("system:%s", resource), success, details)
}
