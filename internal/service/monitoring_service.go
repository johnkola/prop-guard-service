package service

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"PropGuard/internal/repository"
)

// MetricsCollector collects and stores application metrics
type MetricsCollector interface {
	// HTTP Metrics
	RecordHTTPRequest(method, path string, statusCode int, duration time.Duration)
	RecordHTTPError(method, path string, statusCode int, errorType string)

	// Authentication Metrics
	RecordAuthAttempt(username string, success bool, method string)
	RecordTokenGeneration(tokenType string)
	RecordTokenValidation(tokenType string, success bool)

	// Secret Operations Metrics
	RecordSecretOperation(operation string, path string, success bool, duration time.Duration)
	RecordSecretAccess(path string, userId string)
	RecordPolicyViolation(path string, policyId string, violationType string)

	// System Metrics
	RecordSystemMetrics()

	// Database Metrics
	RecordDatabaseOperation(operation string, table string, duration time.Duration, success bool)

	// Get collected metrics
	GetMetrics() *SystemMetrics
	GetHTTPMetrics() *HTTPMetrics
	GetAuthMetrics() *AuthMetrics
	GetSecretMetrics() *SecretMetrics
	GetDatabaseMetrics() *DatabaseMetrics

	// Reset metrics
	ResetMetrics()
}

// SystemMetrics contains system-level metrics
type SystemMetrics struct {
	Timestamp      time.Time `json:"timestamp"`
	Uptime         int64     `json:"uptime_seconds"`
	MemoryUsage    uint64    `json:"memory_usage_bytes"`
	MemoryTotal    uint64    `json:"memory_total_bytes"`
	GoroutineCount int       `json:"goroutine_count"`
	GCPauseTime    uint64    `json:"gc_pause_time_ns"`
	GCCount        uint64    `json:"gc_count"`
	CPUPercent     float64   `json:"cpu_percent"`

	// PropGuard specific
	ActiveSessions int64   `json:"active_sessions"`
	CacheHitRate   float64 `json:"cache_hit_rate"`
}

// HTTPMetrics contains HTTP request metrics
type HTTPMetrics struct {
	TotalRequests     int64            `json:"total_requests"`
	RequestsByMethod  map[string]int64 `json:"requests_by_method"`
	RequestsByPath    map[string]int64 `json:"requests_by_path"`
	ResponseCodes     map[int]int64    `json:"response_codes"`
	AverageLatency    float64          `json:"average_latency_ms"`
	P95Latency        float64          `json:"p95_latency_ms"`
	P99Latency        float64          `json:"p99_latency_ms"`
	ErrorRate         float64          `json:"error_rate"`
	RequestsPerSecond float64          `json:"requests_per_second"`
	LastReset         time.Time        `json:"last_reset"`
}

// AuthMetrics contains authentication metrics
type AuthMetrics struct {
	LoginAttempts      int64            `json:"login_attempts"`
	SuccessfulLogins   int64            `json:"successful_logins"`
	FailedLogins       int64            `json:"failed_logins"`
	LoginsByMethod     map[string]int64 `json:"logins_by_method"`
	TokensGenerated    int64            `json:"tokens_generated"`
	TokenValidations   int64            `json:"token_validations"`
	FailedValidations  int64            `json:"failed_validations"`
	ActiveSessions     int64            `json:"active_sessions"`
	AverageSessionTime float64          `json:"average_session_time_minutes"`
	SuspiciousActivity int64            `json:"suspicious_activity"`
	LastReset          time.Time        `json:"last_reset"`
}

// SecretMetrics contains secret operations metrics
type SecretMetrics struct {
	SecretsCreated       int64            `json:"secrets_created"`
	SecretsRead          int64            `json:"secrets_read"`
	SecretsUpdated       int64            `json:"secrets_updated"`
	SecretsDeleted       int64            `json:"secrets_deleted"`
	OperationsByPath     map[string]int64 `json:"operations_by_path"`
	PolicyViolations     int64            `json:"policy_violations"`
	ViolationsByType     map[string]int64 `json:"violations_by_type"`
	AverageOperationTime float64          `json:"average_operation_time_ms"`
	EncryptionOps        int64            `json:"encryption_operations"`
	DecryptionOps        int64            `json:"decryption_operations"`
	LastReset            time.Time        `json:"last_reset"`
}

// DatabaseMetrics contains database performance metrics
type DatabaseMetrics struct {
	TotalOperations    int64            `json:"total_operations"`
	OperationsByType   map[string]int64 `json:"operations_by_type"`
	OperationsByTable  map[string]int64 `json:"operations_by_table"`
	AverageLatency     float64          `json:"average_latency_ms"`
	ErrorRate          float64          `json:"error_rate"`
	ConnectionPoolSize int              `json:"connection_pool_size"`
	ActiveConnections  int              `json:"active_connections"`
	CacheHitRate       float64          `json:"cache_hit_rate"`
	StorageUsage       int64            `json:"storage_usage_bytes"`
	LastReset          time.Time        `json:"last_reset"`
}

// LatencyTracker tracks latency percentiles
type LatencyTracker struct {
	mu        sync.RWMutex
	values    []float64
	maxValues int
}

func NewLatencyTracker(maxValues int) *LatencyTracker {
	return &LatencyTracker{
		values:    make([]float64, 0, maxValues),
		maxValues: maxValues,
	}
}

func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	latencyMs := float64(latency.Nanoseconds()) / 1e6

	if len(lt.values) >= lt.maxValues {
		// Remove oldest value
		copy(lt.values, lt.values[1:])
		lt.values = lt.values[:len(lt.values)-1]
	}

	lt.values = append(lt.values, latencyMs)
}

func (lt *LatencyTracker) GetPercentile(percentile float64) float64 {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	if len(lt.values) == 0 {
		return 0
	}

	// Simple percentile calculation (not optimized for production)
	values := make([]float64, len(lt.values))
	copy(values, lt.values)

	// Sort values
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[i] > values[j] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}

	index := int(float64(len(values)-1) * percentile / 100.0)
	return values[index]
}

func (lt *LatencyTracker) GetAverage() float64 {
	lt.mu.RLock()
	defer lt.mu.RUnlock()

	if len(lt.values) == 0 {
		return 0
	}

	var sum float64
	for _, v := range lt.values {
		sum += v
	}

	return sum / float64(len(lt.values))
}

// metricsCollector implements MetricsCollector
type metricsCollector struct {
	mu           sync.RWMutex
	startTime    time.Time
	badgerClient *repository.BadgerClient

	// HTTP metrics
	httpRequests     int64
	httpErrors       int64
	requestsByMethod map[string]int64
	requestsByPath   map[string]int64
	responseCodes    map[int]int64
	latencyTracker   *LatencyTracker

	// Auth metrics
	loginAttempts     int64
	successfulLogins  int64
	failedLogins      int64
	loginsByMethod    map[string]int64
	tokensGenerated   int64
	tokenValidations  int64
	failedValidations int64
	activeSessions    int64

	// Secret metrics
	secretsCreated       int64
	secretsRead          int64
	secretsUpdated       int64
	secretsDeleted       int64
	operationsByPath     map[string]int64
	policyViolations     int64
	violationsByType     map[string]int64
	encryptionOps        int64
	decryptionOps        int64
	secretLatencyTracker *LatencyTracker

	// Database metrics
	dbOperations      int64
	dbErrors          int64
	operationsByType  map[string]int64
	operationsByTable map[string]int64
	dbLatencyTracker  *LatencyTracker

	// System metrics
	lastSystemMetrics *SystemMetrics
}

func NewMetricsCollector(badgerClient *repository.BadgerClient) MetricsCollector {
	return &metricsCollector{
		startTime:            time.Now(),
		badgerClient:         badgerClient,
		requestsByMethod:     make(map[string]int64),
		requestsByPath:       make(map[string]int64),
		responseCodes:        make(map[int]int64),
		latencyTracker:       NewLatencyTracker(1000),
		loginsByMethod:       make(map[string]int64),
		operationsByPath:     make(map[string]int64),
		violationsByType:     make(map[string]int64),
		secretLatencyTracker: NewLatencyTracker(1000),
		operationsByType:     make(map[string]int64),
		operationsByTable:    make(map[string]int64),
		dbLatencyTracker:     NewLatencyTracker(1000),
	}
}

// HTTP Metrics Implementation
func (mc *metricsCollector) RecordHTTPRequest(method, path string, statusCode int, duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	atomic.AddInt64(&mc.httpRequests, 1)
	mc.requestsByMethod[method]++
	mc.requestsByPath[path]++
	mc.responseCodes[statusCode]++

	mc.latencyTracker.Record(duration)

	if statusCode >= 400 {
		atomic.AddInt64(&mc.httpErrors, 1)
	}
}

func (mc *metricsCollector) RecordHTTPError(method, path string, statusCode int, errorType string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	atomic.AddInt64(&mc.httpErrors, 1)
	mc.responseCodes[statusCode]++
}

// Authentication Metrics Implementation
func (mc *metricsCollector) RecordAuthAttempt(username string, success bool, method string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	atomic.AddInt64(&mc.loginAttempts, 1)
	mc.loginsByMethod[method]++

	if success {
		atomic.AddInt64(&mc.successfulLogins, 1)
	} else {
		atomic.AddInt64(&mc.failedLogins, 1)
	}
}

func (mc *metricsCollector) RecordTokenGeneration(tokenType string) {
	atomic.AddInt64(&mc.tokensGenerated, 1)
}

func (mc *metricsCollector) RecordTokenValidation(tokenType string, success bool) {
	atomic.AddInt64(&mc.tokenValidations, 1)
	if !success {
		atomic.AddInt64(&mc.failedValidations, 1)
	}
}

// Secret Operations Metrics Implementation
func (mc *metricsCollector) RecordSecretOperation(operation string, path string, success bool, duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	switch operation {
	case "create":
		atomic.AddInt64(&mc.secretsCreated, 1)
	case "read", "get":
		atomic.AddInt64(&mc.secretsRead, 1)
	case "update":
		atomic.AddInt64(&mc.secretsUpdated, 1)
	case "delete":
		atomic.AddInt64(&mc.secretsDeleted, 1)
	}

	mc.operationsByPath[path]++
	mc.secretLatencyTracker.Record(duration)

	if operation == "encrypt" {
		atomic.AddInt64(&mc.encryptionOps, 1)
	} else if operation == "decrypt" {
		atomic.AddInt64(&mc.decryptionOps, 1)
	}
}

func (mc *metricsCollector) RecordSecretAccess(path string, userId string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.operationsByPath[path]++
}

func (mc *metricsCollector) RecordPolicyViolation(path string, policyId string, violationType string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	atomic.AddInt64(&mc.policyViolations, 1)
	mc.violationsByType[violationType]++
}

// Database Metrics Implementation
func (mc *metricsCollector) RecordDatabaseOperation(operation string, table string, duration time.Duration, success bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	atomic.AddInt64(&mc.dbOperations, 1)
	mc.operationsByType[operation]++
	mc.operationsByTable[table]++
	mc.dbLatencyTracker.Record(duration)

	if !success {
		atomic.AddInt64(&mc.dbErrors, 1)
	}
}

// System Metrics Implementation
func (mc *metricsCollector) RecordSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.lastSystemMetrics = &SystemMetrics{
		Timestamp:      time.Now(),
		Uptime:         int64(time.Since(mc.startTime).Seconds()),
		MemoryUsage:    memStats.Alloc,
		MemoryTotal:    memStats.Sys,
		GoroutineCount: runtime.NumGoroutine(),
		GCPauseTime:    memStats.PauseTotalNs,
		GCCount:        uint64(memStats.NumGC),
		ActiveSessions: atomic.LoadInt64(&mc.activeSessions),
	}
}

// Metrics Getters
func (mc *metricsCollector) GetMetrics() *SystemMetrics {
	mc.RecordSystemMetrics()
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if mc.lastSystemMetrics == nil {
		return &SystemMetrics{Timestamp: time.Now()}
	}

	// Create a copy to avoid concurrent access
	metrics := *mc.lastSystemMetrics
	return &metrics
}

func (mc *metricsCollector) GetHTTPMetrics() *HTTPMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	totalRequests := atomic.LoadInt64(&mc.httpRequests)
	httpErrors := atomic.LoadInt64(&mc.httpErrors)

	// Calculate error rate
	var errorRate float64
	if totalRequests > 0 {
		errorRate = float64(httpErrors) / float64(totalRequests) * 100
	}

	// Calculate requests per second (simplified)
	uptime := time.Since(mc.startTime).Seconds()
	var requestsPerSecond float64
	if uptime > 0 {
		requestsPerSecond = float64(totalRequests) / uptime
	}

	// Copy maps to avoid concurrent access
	methodsCopy := make(map[string]int64)
	for k, v := range mc.requestsByMethod {
		methodsCopy[k] = v
	}

	pathsCopy := make(map[string]int64)
	for k, v := range mc.requestsByPath {
		pathsCopy[k] = v
	}

	codesCopy := make(map[int]int64)
	for k, v := range mc.responseCodes {
		codesCopy[k] = v
	}

	return &HTTPMetrics{
		TotalRequests:     totalRequests,
		RequestsByMethod:  methodsCopy,
		RequestsByPath:    pathsCopy,
		ResponseCodes:     codesCopy,
		AverageLatency:    mc.latencyTracker.GetAverage(),
		P95Latency:        mc.latencyTracker.GetPercentile(95),
		P99Latency:        mc.latencyTracker.GetPercentile(99),
		ErrorRate:         errorRate,
		RequestsPerSecond: requestsPerSecond,
		LastReset:         mc.startTime,
	}
}

func (mc *metricsCollector) GetAuthMetrics() *AuthMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	loginAttempts := atomic.LoadInt64(&mc.loginAttempts)
	successfulLogins := atomic.LoadInt64(&mc.successfulLogins)

	methodsCopy := make(map[string]int64)
	for k, v := range mc.loginsByMethod {
		methodsCopy[k] = v
	}

	return &AuthMetrics{
		LoginAttempts:     loginAttempts,
		SuccessfulLogins:  successfulLogins,
		FailedLogins:      atomic.LoadInt64(&mc.failedLogins),
		LoginsByMethod:    methodsCopy,
		TokensGenerated:   atomic.LoadInt64(&mc.tokensGenerated),
		TokenValidations:  atomic.LoadInt64(&mc.tokenValidations),
		FailedValidations: atomic.LoadInt64(&mc.failedValidations),
		ActiveSessions:    atomic.LoadInt64(&mc.activeSessions),
		LastReset:         mc.startTime,
	}
}

func (mc *metricsCollector) GetSecretMetrics() *SecretMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	pathsCopy := make(map[string]int64)
	for k, v := range mc.operationsByPath {
		pathsCopy[k] = v
	}

	violationsCopy := make(map[string]int64)
	for k, v := range mc.violationsByType {
		violationsCopy[k] = v
	}

	return &SecretMetrics{
		SecretsCreated:       atomic.LoadInt64(&mc.secretsCreated),
		SecretsRead:          atomic.LoadInt64(&mc.secretsRead),
		SecretsUpdated:       atomic.LoadInt64(&mc.secretsUpdated),
		SecretsDeleted:       atomic.LoadInt64(&mc.secretsDeleted),
		OperationsByPath:     pathsCopy,
		PolicyViolations:     atomic.LoadInt64(&mc.policyViolations),
		ViolationsByType:     violationsCopy,
		AverageOperationTime: mc.secretLatencyTracker.GetAverage(),
		EncryptionOps:        atomic.LoadInt64(&mc.encryptionOps),
		DecryptionOps:        atomic.LoadInt64(&mc.decryptionOps),
		LastReset:            mc.startTime,
	}
}

func (mc *metricsCollector) GetDatabaseMetrics() *DatabaseMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	totalOps := atomic.LoadInt64(&mc.dbOperations)
	dbErrors := atomic.LoadInt64(&mc.dbErrors)

	var errorRate float64
	if totalOps > 0 {
		errorRate = float64(dbErrors) / float64(totalOps) * 100
	}

	opTypesCopy := make(map[string]int64)
	for k, v := range mc.operationsByType {
		opTypesCopy[k] = v
	}

	tablesCopy := make(map[string]int64)
	for k, v := range mc.operationsByTable {
		tablesCopy[k] = v
	}

	// Get BadgerDB stats if available
	var storageUsage int64
	if mc.badgerClient != nil {
		if stats := mc.badgerClient.GetStats(); stats != nil {
			if size, ok := stats["disk_size"].(int64); ok {
				storageUsage = size
			}
		}
	}

	return &DatabaseMetrics{
		TotalOperations:   totalOps,
		OperationsByType:  opTypesCopy,
		OperationsByTable: tablesCopy,
		AverageLatency:    mc.dbLatencyTracker.GetAverage(),
		ErrorRate:         errorRate,
		StorageUsage:      storageUsage,
		LastReset:         mc.startTime,
	}
}

// Reset all metrics
func (mc *metricsCollector) ResetMetrics() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Reset atomic counters
	atomic.StoreInt64(&mc.httpRequests, 0)
	atomic.StoreInt64(&mc.httpErrors, 0)
	atomic.StoreInt64(&mc.loginAttempts, 0)
	atomic.StoreInt64(&mc.successfulLogins, 0)
	atomic.StoreInt64(&mc.failedLogins, 0)
	atomic.StoreInt64(&mc.tokensGenerated, 0)
	atomic.StoreInt64(&mc.tokenValidations, 0)
	atomic.StoreInt64(&mc.failedValidations, 0)
	atomic.StoreInt64(&mc.secretsCreated, 0)
	atomic.StoreInt64(&mc.secretsRead, 0)
	atomic.StoreInt64(&mc.secretsUpdated, 0)
	atomic.StoreInt64(&mc.secretsDeleted, 0)
	atomic.StoreInt64(&mc.policyViolations, 0)
	atomic.StoreInt64(&mc.encryptionOps, 0)
	atomic.StoreInt64(&mc.decryptionOps, 0)
	atomic.StoreInt64(&mc.dbOperations, 0)
	atomic.StoreInt64(&mc.dbErrors, 0)

	// Reset maps
	mc.requestsByMethod = make(map[string]int64)
	mc.requestsByPath = make(map[string]int64)
	mc.responseCodes = make(map[int]int64)
	mc.loginsByMethod = make(map[string]int64)
	mc.operationsByPath = make(map[string]int64)
	mc.violationsByType = make(map[string]int64)
	mc.operationsByType = make(map[string]int64)
	mc.operationsByTable = make(map[string]int64)

	// Reset latency trackers
	mc.latencyTracker = NewLatencyTracker(1000)
	mc.secretLatencyTracker = NewLatencyTracker(1000)
	mc.dbLatencyTracker = NewLatencyTracker(1000)

	mc.startTime = time.Now()
}
