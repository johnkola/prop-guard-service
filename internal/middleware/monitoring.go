package middleware

import (
	"strconv"
	"strings"
	"time"

	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
)

// MonitoringMiddleware tracks HTTP requests and responses for metrics
func MonitoringMiddleware(collector service.MetricsCollector) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method

		// Sanitize path for metrics (remove IDs and sensitive data)
		sanitizedPath := sanitizePath(path)

		// Process request
		c.Next()

		// Record metrics after request completion
		duration := time.Since(start)
		statusCode := c.Writer.Status()

		// Record HTTP request metrics
		collector.RecordHTTPRequest(method, sanitizedPath, statusCode, duration)

		// Record error if needed
		if statusCode >= 400 {
			errorType := getErrorType(statusCode)
			collector.RecordHTTPError(method, sanitizedPath, statusCode, errorType)
		}

		// Record specific operation metrics based on path
		recordOperationMetrics(collector, method, sanitizedPath, statusCode, duration)
	})
}

// AuthenticationMonitoringMiddleware specifically tracks auth operations
func AuthenticationMonitoringMiddleware(collector service.MetricsCollector) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		path := c.Request.URL.Path

		// Check if this is an auth endpoint
		if !isAuthEndpoint(path) {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()

		_ = time.Since(start) // Duration not used for auth monitoring
		statusCode := c.Writer.Status()

		// Extract username if available
		username := c.GetString("username")
		if username == "" {
			username = "unknown"
		}

		// Determine auth method
		authMethod := determineAuthMethod(path, c)

		// Record auth metrics
		if strings.Contains(path, "/login") {
			success := statusCode == 200
			collector.RecordAuthAttempt(username, success, authMethod)
		} else if strings.Contains(path, "/refresh") {
			collector.RecordTokenGeneration("refresh")
		}

		// Record token validation for protected endpoints
		if c.GetHeader("Authorization") != "" {
			success := statusCode != 401
			collector.RecordTokenValidation("jwt", success)
		}
	})
}

// SecretOperationMonitoringMiddleware tracks secret-related operations
func SecretOperationMonitoringMiddleware(collector service.MetricsCollector) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		path := c.Request.URL.Path
		method := c.Request.Method

		// Check if this is a secret endpoint
		if !isSecretEndpoint(path) {
			c.Next()
			return
		}

		start := time.Now()
		c.Next()

		duration := time.Since(start)
		statusCode := c.Writer.Status()
		success := statusCode < 400

		// Extract secret path from URL
		secretPath := extractSecretPath(path)
		userId := c.GetString("user_id")
		if userId == "" {
			userId = "unknown"
		}

		// Determine operation type
		operation := getSecretOperation(method, path)

		// Record secret operation metrics
		collector.RecordSecretOperation(operation, secretPath, success, duration)

		// Record secret access
		if method == "GET" && success {
			collector.RecordSecretAccess(secretPath, userId)
		}

		// Check for policy violations in response headers
		if policyId := c.GetHeader("X-Policy-Violation"); policyId != "" {
			violationType := c.GetHeader("X-Violation-Type")
			if violationType == "" {
				violationType = "unknown"
			}
			collector.RecordPolicyViolation(secretPath, policyId, violationType)
		}
	})
}

// DatabaseOperationMiddleware wraps database operations for monitoring
func DatabaseOperationWrapper(collector service.MetricsCollector, operation, table string, fn func() error) error {
	start := time.Now()
	err := fn()
	duration := time.Since(start)
	success := err == nil

	collector.RecordDatabaseOperation(operation, table, duration, success)
	return err
}

// Helper functions

func sanitizePath(path string) string {
	// Replace UUIDs and IDs with placeholders for better aggregation
	parts := strings.Split(path, "/")
	for i, part := range parts {
		// Replace UUID patterns
		if len(part) == 36 && strings.Count(part, "-") == 4 {
			parts[i] = "{uuid}"
		}
		// Replace numeric IDs
		if _, err := strconv.Atoi(part); err == nil && len(part) > 0 {
			parts[i] = "{id}"
		}
		// Replace long hex strings (likely hashes)
		if len(part) > 20 && isHexString(part) {
			parts[i] = "{hash}"
		}
	}

	return strings.Join(parts, "/")
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func getErrorType(statusCode int) string {
	switch {
	case statusCode == 400:
		return "bad_request"
	case statusCode == 401:
		return "unauthorized"
	case statusCode == 403:
		return "forbidden"
	case statusCode == 404:
		return "not_found"
	case statusCode == 429:
		return "rate_limit"
	case statusCode >= 500:
		return "server_error"
	default:
		return "client_error"
	}
}

func recordOperationMetrics(collector service.MetricsCollector, method, path string, statusCode int, duration time.Duration) {
	success := statusCode < 400

	// Specific operation tracking
	if strings.Contains(path, "/secrets/") {
		operation := getSecretOperation(method, path)
		secretPath := extractSecretPath(path)
		collector.RecordSecretOperation(operation, secretPath, success, duration)
	}

	// Add more specific operation tracking as needed
}

func isAuthEndpoint(path string) bool {
	authPaths := []string{"/auth/", "/login", "/logout", "/refresh"}
	for _, authPath := range authPaths {
		if strings.Contains(path, authPath) {
			return true
		}
	}
	return false
}

func determineAuthMethod(path string, c *gin.Context) string {
	if strings.Contains(path, "/login") {
		return "password"
	} else if strings.Contains(path, "/refresh") {
		return "refresh_token"
	} else if c.GetHeader("Authorization") != "" {
		return "jwt"
	}
	return "unknown"
}

func isSecretEndpoint(path string) bool {
	return strings.Contains(path, "/secrets") || strings.Contains(path, "/vault")
}

func extractSecretPath(urlPath string) string {
	// Extract the secret path from URL
	// e.g., /api/v1/secrets/prod/database/password -> prod/database/password
	parts := strings.Split(urlPath, "/")

	// Find the secrets part
	for i, part := range parts {
		if part == "secrets" && i+1 < len(parts) {
			return strings.Join(parts[i+1:], "/")
		}
	}

	return "unknown"
}

func getSecretOperation(method, path string) string {
	switch method {
	case "POST":
		return "create"
	case "GET":
		return "read"
	case "PUT":
		return "update"
	case "DELETE":
		return "delete"
	default:
		return "unknown"
	}
}

// PerformanceMonitoringMiddleware tracks general performance metrics
func PerformanceMonitoringMiddleware(collector service.MetricsCollector) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Record system metrics periodically
		go func() {
			collector.RecordSystemMetrics()
		}()

		c.Next()
	})
}

// AlertMiddleware checks for alert conditions
func AlertMiddleware(collector service.MetricsCollector) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Next()

		// Check for alert conditions after request
		statusCode := c.Writer.Status()
		path := c.Request.URL.Path

		// High error rate alert
		if statusCode >= 500 {
			// Log critical error
			go func() {
				// Could integrate with alerting system here
				// For now, just ensure it's recorded in metrics
				collector.RecordHTTPError(c.Request.Method, sanitizePath(path), statusCode, "critical_error")
			}()
		}

		// Suspicious authentication attempts
		if statusCode == 401 && isAuthEndpoint(path) {
			// Could trigger security alert
		}
	})
}
