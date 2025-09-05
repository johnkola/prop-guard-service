package controller

import (
	"net/http"
	"runtime"
	"strconv"
	"time"

	"PropGuard/internal/repository"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
)

type MonitoringController struct {
	collector     service.MetricsCollector
	badgerClient  *repository.BadgerClient
	jwtMiddleware *security.JWTMiddleware
}

func NewMonitoringController(
	collector service.MetricsCollector,
	badgerClient *repository.BadgerClient,
	jwtMiddleware *security.JWTMiddleware,
) *MonitoringController {
	return &MonitoringController{
		collector:     collector,
		badgerClient:  badgerClient,
		jwtMiddleware: jwtMiddleware,
	}
}

// RegisterRoutes registers monitoring routes
func (c *MonitoringController) RegisterRoutes(router gin.IRouter) {
	monitoring := router.Group("/monitoring")
	{
		// Public health check (no auth required)
		monitoring.GET("/health", c.HealthCheck)
		monitoring.GET("/status", c.ServiceStatus)

		// Protected monitoring endpoints (require authentication)
		protected := monitoring.Group("")
		protected.Use(c.jwtMiddleware.Authenticate())
		{
			// System metrics
			protected.GET("/metrics", c.GetMetrics)
			protected.GET("/metrics/system", c.GetSystemMetrics)
			protected.GET("/metrics/http", c.GetHTTPMetrics)
			protected.GET("/metrics/auth", c.GetAuthMetrics)
			protected.GET("/metrics/secrets", c.GetSecretMetrics)
			protected.GET("/metrics/database", c.GetDatabaseMetrics)

			// Combined dashboard data
			protected.GET("/dashboard", c.GetDashboard)

			// Performance metrics
			protected.GET("/performance", c.GetPerformanceMetrics)

			// Alert status
			protected.GET("/alerts", c.GetAlerts)

			// System information
			protected.GET("/info", c.GetSystemInfo)

			// Reset metrics (admin only)
			protected.POST("/reset", c.ResetMetrics)
		}

		// Prometheus-compatible metrics endpoint (if needed)
		monitoring.GET("/prometheus", c.PrometheusMetrics)
	}
}

// HealthCheck provides a simple health status
// @Summary Health check
// @Description Returns the current health status of the application
// @Tags Monitoring
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 503 {object} map[string]interface{}
// @Router /monitoring/health [get]
func (c *MonitoringController) HealthCheck(ctx *gin.Context) {
	status := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"service":   "PropGuard",
		"version":   "1.0.0",
	}

	// Test database connectivity
	if c.badgerClient != nil {
		if err := c.badgerClient.Ping(); err != nil {
			status["status"] = "unhealthy"
			status["database_error"] = err.Error()
			ctx.JSON(http.StatusServiceUnavailable, status)
			return
		}
		status["database"] = "healthy"
	}

	ctx.JSON(http.StatusOK, status)
}

// ServiceStatus provides detailed service status
// @Summary Service status
// @Description Returns detailed status information about the service
// @Tags Monitoring
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /monitoring/status [get]
func (c *MonitoringController) ServiceStatus(ctx *gin.Context) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	status := gin.H{
		"service": gin.H{
			"name":        "PropGuard",
			"version":     "1.0.0",
			"environment": getEnvMode(),
			"uptime":      time.Since(startTime).Seconds(),
		},
		"system": gin.H{
			"memory_usage": memStats.Alloc,
			"memory_total": memStats.Sys,
			"goroutines":   runtime.NumGoroutine(),
			"gc_cycles":    memStats.NumGC,
		},
		"database":  c.getDatabaseStatus(),
		"timestamp": time.Now(),
	}

	ctx.JSON(http.StatusOK, status)
}

// GetMetrics returns all collected metrics
// @Summary Get all metrics
// @Description Returns comprehensive metrics data
// @Tags Monitoring
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/metrics [get]
func (c *MonitoringController) GetMetrics(ctx *gin.Context) {
	metrics := gin.H{
		"system":    c.collector.GetMetrics(),
		"http":      c.collector.GetHTTPMetrics(),
		"auth":      c.collector.GetAuthMetrics(),
		"secrets":   c.collector.GetSecretMetrics(),
		"database":  c.collector.GetDatabaseMetrics(),
		"timestamp": time.Now(),
	}

	ctx.JSON(http.StatusOK, metrics)
}

// GetSystemMetrics returns system-level metrics
// @Summary Get system metrics
// @Description Returns system performance and resource usage metrics
// @Tags Monitoring
// @Produce json
// @Success 200 {object} service.SystemMetrics
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/metrics/system [get]
func (c *MonitoringController) GetSystemMetrics(ctx *gin.Context) {
	metrics := c.collector.GetMetrics()
	ctx.JSON(http.StatusOK, metrics)
}

// GetHTTPMetrics returns HTTP request metrics
// @Summary Get HTTP metrics
// @Description Returns HTTP request and response metrics
// @Tags Monitoring
// @Produce json
// @Success 200 {object} service.HTTPMetrics
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/metrics/http [get]
func (c *MonitoringController) GetHTTPMetrics(ctx *gin.Context) {
	metrics := c.collector.GetHTTPMetrics()
	ctx.JSON(http.StatusOK, metrics)
}

// GetAuthMetrics returns authentication metrics
// @Summary Get authentication metrics
// @Description Returns authentication and authorization metrics
// @Tags Monitoring
// @Produce json
// @Success 200 {object} service.AuthMetrics
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/metrics/auth [get]
func (c *MonitoringController) GetAuthMetrics(ctx *gin.Context) {
	metrics := c.collector.GetAuthMetrics()
	ctx.JSON(http.StatusOK, metrics)
}

// GetSecretMetrics returns secret operations metrics
// @Summary Get secret metrics
// @Description Returns metrics about secret operations and policy violations
// @Tags Monitoring
// @Produce json
// @Success 200 {object} service.SecretMetrics
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/metrics/secrets [get]
func (c *MonitoringController) GetSecretMetrics(ctx *gin.Context) {
	metrics := c.collector.GetSecretMetrics()
	ctx.JSON(http.StatusOK, metrics)
}

// GetDatabaseMetrics returns database performance metrics
// @Summary Get database metrics
// @Description Returns database operation and performance metrics
// @Tags Monitoring
// @Produce json
// @Success 200 {object} service.DatabaseMetrics
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/metrics/database [get]
func (c *MonitoringController) GetDatabaseMetrics(ctx *gin.Context) {
	metrics := c.collector.GetDatabaseMetrics()
	ctx.JSON(http.StatusOK, metrics)
}

// GetDashboard returns dashboard-ready metrics
// @Summary Get monitoring dashboard data
// @Description Returns formatted metrics suitable for dashboard display
// @Tags Monitoring
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/dashboard [get]
func (c *MonitoringController) GetDashboard(ctx *gin.Context) {
	systemMetrics := c.collector.GetMetrics()
	httpMetrics := c.collector.GetHTTPMetrics()
	authMetrics := c.collector.GetAuthMetrics()
	secretMetrics := c.collector.GetSecretMetrics()
	dbMetrics := c.collector.GetDatabaseMetrics()

	dashboard := gin.H{
		"overview": gin.H{
			"uptime_seconds":      systemMetrics.Uptime,
			"memory_usage_mb":     float64(systemMetrics.MemoryUsage) / (1024 * 1024),
			"goroutines":          systemMetrics.GoroutineCount,
			"total_requests":      httpMetrics.TotalRequests,
			"requests_per_second": httpMetrics.RequestsPerSecond,
			"error_rate_percent":  httpMetrics.ErrorRate,
			"average_latency_ms":  httpMetrics.AverageLatency,
		},
		"health_indicators": gin.H{
			"system_health":   c.getSystemHealthScore(systemMetrics),
			"database_health": c.getDatabaseHealthScore(dbMetrics),
			"auth_health":     c.getAuthHealthScore(authMetrics),
			"overall_health":  c.getOverallHealthScore(systemMetrics, httpMetrics, authMetrics, dbMetrics),
		},
		"activity": gin.H{
			"recent_logins":     authMetrics.SuccessfulLogins,
			"failed_login_rate": c.calculateFailedLoginRate(authMetrics),
			"secrets_accessed":  secretMetrics.SecretsRead,
			"policy_violations": secretMetrics.PolicyViolations,
			"active_sessions":   authMetrics.ActiveSessions,
		},
		"performance": gin.H{
			"response_times": gin.H{
				"average": httpMetrics.AverageLatency,
				"p95":     httpMetrics.P95Latency,
				"p99":     httpMetrics.P99Latency,
			},
			"database_performance": gin.H{
				"average_latency":       dbMetrics.AverageLatency,
				"operations_per_second": c.calculateDbOpsPerSecond(dbMetrics, systemMetrics.Uptime),
				"error_rate":            dbMetrics.ErrorRate,
			},
		},
		"alerts":    c.generateAlerts(systemMetrics, httpMetrics, authMetrics, secretMetrics, dbMetrics),
		"timestamp": time.Now(),
	}

	ctx.JSON(http.StatusOK, dashboard)
}

// GetPerformanceMetrics returns detailed performance metrics
// @Summary Get performance metrics
// @Description Returns detailed performance and latency metrics
// @Tags Monitoring
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/performance [get]
func (c *MonitoringController) GetPerformanceMetrics(ctx *gin.Context) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	httpMetrics := c.collector.GetHTTPMetrics()
	dbMetrics := c.collector.GetDatabaseMetrics()
	secretMetrics := c.collector.GetSecretMetrics()

	performance := gin.H{
		"latency": gin.H{
			"http": gin.H{
				"average_ms": httpMetrics.AverageLatency,
				"p95_ms":     httpMetrics.P95Latency,
				"p99_ms":     httpMetrics.P99Latency,
			},
			"database": gin.H{
				"average_ms": dbMetrics.AverageLatency,
			},
			"secrets": gin.H{
				"average_operation_ms": secretMetrics.AverageOperationTime,
			},
		},
		"throughput": gin.H{
			"requests_per_second":    httpMetrics.RequestsPerSecond,
			"secrets_ops_per_minute": c.calculateSecretsOpsPerMinute(secretMetrics),
		},
		"memory": gin.H{
			"allocated_mb":   float64(memStats.Alloc) / (1024 * 1024),
			"total_alloc_mb": float64(memStats.TotalAlloc) / (1024 * 1024),
			"sys_mb":         float64(memStats.Sys) / (1024 * 1024),
			"gc_pause_ns":    memStats.PauseTotalNs,
			"num_gc":         memStats.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
		"timestamp":  time.Now(),
	}

	ctx.JSON(http.StatusOK, performance)
}

// GetAlerts returns current alert conditions
// @Summary Get system alerts
// @Description Returns current alerts and warning conditions
// @Tags Monitoring
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/alerts [get]
func (c *MonitoringController) GetAlerts(ctx *gin.Context) {
	systemMetrics := c.collector.GetMetrics()
	httpMetrics := c.collector.GetHTTPMetrics()
	authMetrics := c.collector.GetAuthMetrics()
	secretMetrics := c.collector.GetSecretMetrics()
	dbMetrics := c.collector.GetDatabaseMetrics()

	alerts := c.generateAlerts(systemMetrics, httpMetrics, authMetrics, secretMetrics, dbMetrics)

	ctx.JSON(http.StatusOK, gin.H{
		"alerts":      alerts,
		"alert_count": len(alerts),
		"timestamp":   time.Now(),
	})
}

// GetSystemInfo returns detailed system information
// @Summary Get system information
// @Description Returns detailed system and application information
// @Tags Monitoring
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/info [get]
func (c *MonitoringController) GetSystemInfo(ctx *gin.Context) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	info := gin.H{
		"application": gin.H{
			"name":        "PropGuard",
			"version":     "1.0.0",
			"description": "Secure secrets management and configuration service",
			"environment": getEnvMode(),
			"started_at":  startTime,
			"uptime":      time.Since(startTime).String(),
		},
		"system": gin.H{
			"go_version": runtime.Version(),
			"go_arch":    runtime.GOARCH,
			"go_os":      runtime.GOOS,
			"num_cpu":    runtime.NumCPU(),
			"max_procs":  runtime.GOMAXPROCS(0),
		},
		"runtime": gin.H{
			"goroutines": runtime.NumGoroutine(),
			"memory": gin.H{
				"alloc_mb":       float64(memStats.Alloc) / (1024 * 1024),
				"total_alloc_mb": float64(memStats.TotalAlloc) / (1024 * 1024),
				"sys_mb":         float64(memStats.Sys) / (1024 * 1024),
				"heap_alloc_mb":  float64(memStats.HeapAlloc) / (1024 * 1024),
				"heap_sys_mb":    float64(memStats.HeapSys) / (1024 * 1024),
			},
			"gc": gin.H{
				"num_gc":         memStats.NumGC,
				"pause_total_ns": memStats.PauseTotalNs,
				"last_gc":        time.Unix(0, int64(memStats.LastGC)),
			},
		},
		"database":  c.getDatabaseInfo(),
		"timestamp": time.Now(),
	}

	ctx.JSON(http.StatusOK, info)
}

// ResetMetrics resets all collected metrics
// @Summary Reset metrics
// @Description Resets all collected metrics (admin only)
// @Tags Monitoring
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Security BearerAuth
// @Router /monitoring/reset [post]
func (c *MonitoringController) ResetMetrics(ctx *gin.Context) {
	// Check if user has admin role (simplified check)
	role := ctx.GetString("role")
	if role != "admin" {
		ctx.JSON(http.StatusForbidden, gin.H{
			"error": "Admin access required",
		})
		return
	}

	c.collector.ResetMetrics()

	ctx.JSON(http.StatusOK, gin.H{
		"message":  "Metrics reset successfully",
		"reset_at": time.Now(),
	})
}

// PrometheusMetrics provides Prometheus-compatible metrics
// @Summary Prometheus metrics
// @Description Returns metrics in Prometheus format
// @Tags Monitoring
// @Produce text/plain
// @Success 200 {string} string
// @Router /monitoring/prometheus [get]
func (c *MonitoringController) PrometheusMetrics(ctx *gin.Context) {
	systemMetrics := c.collector.GetMetrics()
	httpMetrics := c.collector.GetHTTPMetrics()
	authMetrics := c.collector.GetAuthMetrics()
	secretMetrics := c.collector.GetSecretMetrics()
	dbMetrics := c.collector.GetDatabaseMetrics()

	prometheus := c.formatPrometheusMetrics(systemMetrics, httpMetrics, authMetrics, secretMetrics, dbMetrics)

	ctx.Header("Content-Type", "text/plain")
	ctx.String(http.StatusOK, prometheus)
}

// Helper functions

var startTime = time.Now()

func getEnvMode() string {
	if mode := gin.Mode(); mode != "" {
		return mode
	}
	return "unknown"
}

func (c *MonitoringController) getDatabaseStatus() gin.H {
	status := gin.H{
		"type":   "BadgerDB",
		"status": "unknown",
	}

	if c.badgerClient != nil {
		if err := c.badgerClient.Ping(); err != nil {
			status["status"] = "unhealthy"
			status["error"] = err.Error()
		} else {
			status["status"] = "healthy"
			if stats := c.badgerClient.GetStats(); stats != nil {
				status["stats"] = stats
			}
		}
	}

	return status
}

func (c *MonitoringController) getDatabaseInfo() gin.H {
	info := gin.H{
		"type":    "BadgerDB",
		"version": "4.x", // Would need to get actual version
	}

	if c.badgerClient != nil {
		if stats := c.badgerClient.GetStats(); stats != nil {
			info["stats"] = stats
		}
	}

	return info
}

// Health scoring functions (0-100 score)
func (c *MonitoringController) getSystemHealthScore(metrics *service.SystemMetrics) int {
	score := 100

	// Memory usage check
	memUsagePercent := float64(metrics.MemoryUsage) / float64(metrics.MemoryTotal) * 100
	if memUsagePercent > 90 {
		score -= 30
	} else if memUsagePercent > 75 {
		score -= 15
	}

	// Goroutine count check
	if metrics.GoroutineCount > 1000 {
		score -= 20
	} else if metrics.GoroutineCount > 500 {
		score -= 10
	}

	return maxInt(score, 0)
}

func (c *MonitoringController) getDatabaseHealthScore(metrics *service.DatabaseMetrics) int {
	score := 100

	// Error rate check
	if metrics.ErrorRate > 10 {
		score -= 40
	} else if metrics.ErrorRate > 5 {
		score -= 20
	} else if metrics.ErrorRate > 1 {
		score -= 10
	}

	// Latency check
	if metrics.AverageLatency > 1000 {
		score -= 30
	} else if metrics.AverageLatency > 500 {
		score -= 15
	}

	return maxInt(score, 0)
}

func (c *MonitoringController) getAuthHealthScore(metrics *service.AuthMetrics) int {
	score := 100

	// Failed login rate check
	if metrics.LoginAttempts > 0 {
		failedRate := float64(metrics.FailedLogins) / float64(metrics.LoginAttempts) * 100
		if failedRate > 50 {
			score -= 40
		} else if failedRate > 25 {
			score -= 20
		} else if failedRate > 10 {
			score -= 10
		}
	}

	return maxInt(score, 0)
}

func (c *MonitoringController) getOverallHealthScore(system *service.SystemMetrics, http *service.HTTPMetrics, auth *service.AuthMetrics, db *service.DatabaseMetrics) int {
	systemScore := c.getSystemHealthScore(system)
	dbScore := c.getDatabaseHealthScore(db)
	authScore := c.getAuthHealthScore(auth)

	// HTTP error rate
	httpScore := 100
	if http.ErrorRate > 20 {
		httpScore -= 40
	} else if http.ErrorRate > 10 {
		httpScore -= 20
	} else if http.ErrorRate > 5 {
		httpScore -= 10
	}

	// Weighted average
	return (systemScore*25 + dbScore*25 + authScore*25 + httpScore*25) / 100
}

func (c *MonitoringController) calculateFailedLoginRate(metrics *service.AuthMetrics) float64 {
	if metrics.LoginAttempts == 0 {
		return 0
	}
	return float64(metrics.FailedLogins) / float64(metrics.LoginAttempts) * 100
}

func (c *MonitoringController) calculateDbOpsPerSecond(metrics *service.DatabaseMetrics, uptimeSeconds int64) float64 {
	if uptimeSeconds == 0 {
		return 0
	}
	return float64(metrics.TotalOperations) / float64(uptimeSeconds)
}

func (c *MonitoringController) calculateSecretsOpsPerMinute(metrics *service.SecretMetrics) float64 {
	total := metrics.SecretsCreated + metrics.SecretsRead + metrics.SecretsUpdated + metrics.SecretsDeleted
	minutesSinceReset := time.Since(metrics.LastReset).Minutes()
	if minutesSinceReset == 0 {
		return 0
	}
	return float64(total) / minutesSinceReset
}

func (c *MonitoringController) generateAlerts(system *service.SystemMetrics, http *service.HTTPMetrics, auth *service.AuthMetrics, secrets *service.SecretMetrics, db *service.DatabaseMetrics) []map[string]interface{} {
	var alerts []map[string]interface{}

	// High memory usage alert
	memUsagePercent := float64(system.MemoryUsage) / float64(system.MemoryTotal) * 100
	if memUsagePercent > 90 {
		alerts = append(alerts, map[string]interface{}{
			"severity":  "critical",
			"type":      "high_memory_usage",
			"message":   "Memory usage is above 90%",
			"value":     memUsagePercent,
			"threshold": 90,
		})
	} else if memUsagePercent > 75 {
		alerts = append(alerts, map[string]interface{}{
			"severity":  "warning",
			"type":      "high_memory_usage",
			"message":   "Memory usage is above 75%",
			"value":     memUsagePercent,
			"threshold": 75,
		})
	}

	// High error rate alert
	if http.ErrorRate > 20 {
		alerts = append(alerts, map[string]interface{}{
			"severity":  "critical",
			"type":      "high_error_rate",
			"message":   "HTTP error rate is above 20%",
			"value":     http.ErrorRate,
			"threshold": 20,
		})
	} else if http.ErrorRate > 10 {
		alerts = append(alerts, map[string]interface{}{
			"severity":  "warning",
			"type":      "high_error_rate",
			"message":   "HTTP error rate is above 10%",
			"value":     http.ErrorRate,
			"threshold": 10,
		})
	}

	// Failed login attempts alert
	if auth.LoginAttempts > 0 {
		failedRate := float64(auth.FailedLogins) / float64(auth.LoginAttempts) * 100
		if failedRate > 50 {
			alerts = append(alerts, map[string]interface{}{
				"severity":  "critical",
				"type":      "high_failed_login_rate",
				"message":   "Failed login rate is above 50%",
				"value":     failedRate,
				"threshold": 50,
			})
		}
	}

	// Policy violations alert
	if secrets.PolicyViolations > 100 {
		alerts = append(alerts, map[string]interface{}{
			"severity":  "warning",
			"type":      "high_policy_violations",
			"message":   "Policy violations count is high",
			"value":     secrets.PolicyViolations,
			"threshold": 100,
		})
	}

	// Database error rate alert
	if db.ErrorRate > 10 {
		alerts = append(alerts, map[string]interface{}{
			"severity":  "critical",
			"type":      "high_database_error_rate",
			"message":   "Database error rate is above 10%",
			"value":     db.ErrorRate,
			"threshold": 10,
		})
	}

	// High latency alert
	if http.AverageLatency > 2000 {
		alerts = append(alerts, map[string]interface{}{
			"severity":  "warning",
			"type":      "high_latency",
			"message":   "Average HTTP latency is above 2 seconds",
			"value":     http.AverageLatency,
			"threshold": 2000,
		})
	}

	return alerts
}

func (c *MonitoringController) formatPrometheusMetrics(system *service.SystemMetrics, http *service.HTTPMetrics, auth *service.AuthMetrics, secrets *service.SecretMetrics, db *service.DatabaseMetrics) string {
	prometheus := ""

	// System metrics
	prometheus += "# HELP propguard_uptime_seconds Application uptime in seconds\n"
	prometheus += "# TYPE propguard_uptime_seconds counter\n"
	prometheus += "propguard_uptime_seconds " + strconv.FormatInt(system.Uptime, 10) + "\n\n"

	prometheus += "# HELP propguard_memory_usage_bytes Memory usage in bytes\n"
	prometheus += "# TYPE propguard_memory_usage_bytes gauge\n"
	prometheus += "propguard_memory_usage_bytes " + strconv.FormatUint(system.MemoryUsage, 10) + "\n\n"

	prometheus += "# HELP propguard_goroutines Number of goroutines\n"
	prometheus += "# TYPE propguard_goroutines gauge\n"
	prometheus += "propguard_goroutines " + strconv.Itoa(system.GoroutineCount) + "\n\n"

	// HTTP metrics
	prometheus += "# HELP propguard_http_requests_total Total HTTP requests\n"
	prometheus += "# TYPE propguard_http_requests_total counter\n"
	prometheus += "propguard_http_requests_total " + strconv.FormatInt(http.TotalRequests, 10) + "\n\n"

	prometheus += "# HELP propguard_http_error_rate HTTP error rate percentage\n"
	prometheus += "# TYPE propguard_http_error_rate gauge\n"
	prometheus += "propguard_http_error_rate " + strconv.FormatFloat(http.ErrorRate, 'f', 2, 64) + "\n\n"

	prometheus += "# HELP propguard_http_latency_ms HTTP request latency in milliseconds\n"
	prometheus += "# TYPE propguard_http_latency_ms histogram\n"
	prometheus += "propguard_http_latency_ms " + strconv.FormatFloat(http.AverageLatency, 'f', 2, 64) + "\n\n"

	// Auth metrics
	prometheus += "# HELP propguard_login_attempts_total Total login attempts\n"
	prometheus += "# TYPE propguard_login_attempts_total counter\n"
	prometheus += "propguard_login_attempts_total " + strconv.FormatInt(auth.LoginAttempts, 10) + "\n\n"

	prometheus += "# HELP propguard_successful_logins_total Successful logins\n"
	prometheus += "# TYPE propguard_successful_logins_total counter\n"
	prometheus += "propguard_successful_logins_total " + strconv.FormatInt(auth.SuccessfulLogins, 10) + "\n\n"

	// Secret metrics
	prometheus += "# HELP propguard_secrets_operations_total Total secret operations\n"
	prometheus += "# TYPE propguard_secrets_operations_total counter\n"
	totalSecretOps := secrets.SecretsCreated + secrets.SecretsRead + secrets.SecretsUpdated + secrets.SecretsDeleted
	prometheus += "propguard_secrets_operations_total " + strconv.FormatInt(totalSecretOps, 10) + "\n\n"

	prometheus += "# HELP propguard_policy_violations_total Total policy violations\n"
	prometheus += "# TYPE propguard_policy_violations_total counter\n"
	prometheus += "propguard_policy_violations_total " + strconv.FormatInt(secrets.PolicyViolations, 10) + "\n\n"

	// Database metrics
	prometheus += "# HELP propguard_database_operations_total Total database operations\n"
	prometheus += "# TYPE propguard_database_operations_total counter\n"
	prometheus += "propguard_database_operations_total " + strconv.FormatInt(db.TotalOperations, 10) + "\n\n"

	prometheus += "# HELP propguard_database_error_rate Database error rate percentage\n"
	prometheus += "# TYPE propguard_database_error_rate gauge\n"
	prometheus += "propguard_database_error_rate " + strconv.FormatFloat(db.ErrorRate, 'f', 2, 64) + "\n\n"

	return prometheus
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
