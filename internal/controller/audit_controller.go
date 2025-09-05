package controller

import (
	"net/http"
	"strconv"
	"time"

	"PropGuard/internal/dto"
	"PropGuard/internal/repository"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
)

// AuditController handles audit log related HTTP requests
type AuditController struct {
	auditRepo     *repository.BadgerAuditRepository
	auditService  service.AuditService
	jwtMiddleware *security.JWTMiddleware
}

// NewAuditController creates a new audit controller
func NewAuditController(
	auditRepo *repository.BadgerAuditRepository,
	auditService service.AuditService,
	jwtMiddleware *security.JWTMiddleware,
) *AuditController {
	return &AuditController{
		auditRepo:     auditRepo,
		auditService:  auditService,
		jwtMiddleware: jwtMiddleware,
	}
}

// RegisterRoutes registers audit log routes
func (c *AuditController) RegisterRoutes(router *gin.RouterGroup) {
	audit := router.Group("/audit")
	audit.Use(c.jwtMiddleware.Authenticate())
	{
		audit.GET("", c.jwtMiddleware.RequirePermission("audit:read"), c.ListAuditLogs)
		audit.GET("/export", c.jwtMiddleware.RequirePermission("audit:export"), c.ExportAuditLogs)
		audit.POST("/cleanup", c.jwtMiddleware.RequirePermission("audit:purge"), c.CleanupOldLogs)
	}
}

// ListAuditLogs godoc
// @Summary List audit logs
// @Description Get a paginated list of audit logs with optional filtering
// @Tags audit
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(20)
// @Param search query string false "Search in username, action, path, or details"
// @Param action query string false "Filter by action"
// @Param success query boolean false "Filter by success status"
// @Param from query string false "Filter from date (RFC3339 format)"
// @Param to query string false "Filter to date (RFC3339 format)"
// @Success 200 {object} dto.PaginatedAuditLogsResponse
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /audit [get]
func (c *AuditController) ListAuditLogs(ctx *gin.Context) {
	// Parse pagination parameters
	pageStr := ctx.DefaultQuery("page", "1")
	pageSizeStr := ctx.DefaultQuery("pageSize", "20")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// For now, we'll just return all audit logs with basic pagination
	// In a production system, you'd implement filtering by the query parameters
	auditLogs, err := c.auditRepo.List(ctx, pageSize, offset)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list audit logs"})
		return
	}

	// Get total count for pagination
	total, err := c.auditRepo.Count(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to count audit logs"})
		return
	}

	// Calculate pagination info
	totalPages := (int(total) + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	response := &dto.PaginatedAuditLogsResponse{
		Logs:       auditLogs,
		Total:      int(total),
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}

	// Log this audit access
	c.auditService.LogAction(ctx, security.GetUsername(ctx), "AUDIT_LIST", "", true, "Listed audit logs")

	ctx.JSON(http.StatusOK, response)
}

// ExportAuditLogs godoc
// @Summary Export audit logs
// @Description Export audit logs to CSV format with optional filtering
// @Tags audit
// @Accept json
// @Produce text/csv
// @Param search query string false "Search in username, action, path, or details"
// @Param action query string false "Filter by action"
// @Param success query boolean false "Filter by success status"
// @Param from query string false "Filter from date (RFC3339 format)"
// @Param to query string false "Filter to date (RFC3339 format)"
// @Success 200 {string} string "CSV content"
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /audit/export [get]
func (c *AuditController) ExportAuditLogs(ctx *gin.Context) {
	// For now, return a simple CSV header to indicate the endpoint exists
	// In a production system, you'd implement CSV generation with filtering
	auditLogs, err := c.auditRepo.List(ctx, 1000, 0) // Get up to 1000 logs for export
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export audit logs"})
		return
	}

	// Log this audit export
	c.auditService.LogAction(ctx, security.GetUsername(ctx), "AUDIT_EXPORT", "", true, "Exported audit logs")

	// Set CSV headers
	ctx.Header("Content-Type", "text/csv")
	ctx.Header("Content-Disposition", "attachment; filename=\"audit-logs-"+time.Now().Format("2006-01-02")+".csv\"")

	// Simple CSV generation (in production, use a proper CSV library)
	csvContent := "Timestamp,Username,Action,SecretPath,Success,Details,ClientIP,UserAgent\n"
	for _, log := range auditLogs {
		csvContent += log.Timestamp.Format(time.RFC3339) + "," +
			log.Username + "," +
			log.Action + "," +
			log.SecretPath + "," +
			strconv.FormatBool(log.Success) + "," +
			"\"" + log.Details + "\"," +
			log.ClientIP + "," +
			"\"" + log.UserAgent + "\"\n"
	}

	ctx.String(http.StatusOK, csvContent)
}

// CleanupOldLogs godoc
// @Summary Cleanup old audit logs
// @Description Remove audit logs older than specified days
// @Tags audit
// @Accept json
// @Produce json
// @Param days query int true "Number of days to keep (logs older than this will be deleted)"
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 401 {object} gin.H
// @Failure 403 {object} gin.H
// @Failure 500 {object} gin.H
// @Security BearerAuth
// @Router /audit/cleanup [post]
func (c *AuditController) CleanupOldLogs(ctx *gin.Context) {
	daysStr := ctx.Query("days")
	if daysStr == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "days parameter is required"})
		return
	}

	days, err := strconv.Atoi(daysStr)
	if err != nil || days < 1 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid days parameter"})
		return
	}

	deletedCount, err := c.auditService.CleanupOldLogs(ctx, days)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to cleanup audit logs"})
		return
	}

	// Log this cleanup operation
	c.auditService.LogAction(ctx, security.GetUsername(ctx), "AUDIT_CLEANUP", "", true,
		"Cleaned up "+strconv.FormatInt(deletedCount, 10)+" old audit logs")

	ctx.JSON(http.StatusOK, gin.H{
		"message":       "cleanup completed",
		"deleted_count": deletedCount,
	})
}
