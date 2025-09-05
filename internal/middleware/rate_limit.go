package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter interface for different rate limiting strategies
type RateLimiter interface {
	Allow(key string) bool
	Reset(key string)
	GetRemaining(key string) int
	GetResetTime(key string) time.Time
}

// TokenBucketLimiter implements token bucket algorithm for rate limiting
type TokenBucketLimiter struct {
	mu       sync.RWMutex
	buckets  map[string]*TokenBucket
	rate     int           // tokens per window
	window   time.Duration // time window
	capacity int           // bucket capacity
	cleanup  time.Duration // cleanup interval for old buckets
}

type TokenBucket struct {
	tokens   int
	lastSeen time.Time
	resetAt  time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(rate int, window time.Duration, capacity int) *TokenBucketLimiter {
	limiter := &TokenBucketLimiter{
		buckets:  make(map[string]*TokenBucket),
		rate:     rate,
		window:   window,
		capacity: capacity,
		cleanup:  window * 2, // cleanup old buckets after 2 windows
	}

	// Start cleanup goroutine
	go limiter.cleanupBuckets()

	return limiter
}

func (tbl *TokenBucketLimiter) Allow(key string) bool {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	now := time.Now()
	bucket, exists := tbl.buckets[key]

	if !exists {
		// Create new bucket
		bucket = &TokenBucket{
			tokens:   tbl.capacity - 1, // Use one token
			lastSeen: now,
			resetAt:  now.Add(tbl.window),
		}
		tbl.buckets[key] = bucket
		return true
	}

	// Refill bucket if window has passed
	if now.After(bucket.resetAt) {
		bucket.tokens = tbl.capacity
		bucket.resetAt = now.Add(tbl.window)
	}

	bucket.lastSeen = now

	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

func (tbl *TokenBucketLimiter) Reset(key string) {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()
	delete(tbl.buckets, key)
}

func (tbl *TokenBucketLimiter) GetRemaining(key string) int {
	tbl.mu.RLock()
	defer tbl.mu.RUnlock()

	bucket, exists := tbl.buckets[key]
	if !exists {
		return tbl.capacity
	}

	// Check if bucket should be refilled
	if time.Now().After(bucket.resetAt) {
		return tbl.capacity
	}

	return bucket.tokens
}

func (tbl *TokenBucketLimiter) GetResetTime(key string) time.Time {
	tbl.mu.RLock()
	defer tbl.mu.RUnlock()

	bucket, exists := tbl.buckets[key]
	if !exists {
		return time.Now().Add(tbl.window)
	}

	return bucket.resetAt
}

func (tbl *TokenBucketLimiter) cleanupBuckets() {
	ticker := time.NewTicker(tbl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		tbl.mu.Lock()
		now := time.Now()
		for key, bucket := range tbl.buckets {
			// Remove buckets that haven't been accessed in 2 windows
			if now.Sub(bucket.lastSeen) > tbl.cleanup {
				delete(tbl.buckets, key)
			}
		}
		tbl.mu.Unlock()
	}
}

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	// Global rate limits
	GlobalRequestsPerMinute int
	GlobalBurst             int

	// Authentication endpoint specific limits
	LoginAttemptsPerMinute int
	LoginAttemptsBurst     int
	LoginWindowMinutes     int

	// API endpoint limits
	APIRequestsPerMinute int
	APIBurst             int

	// Skip rate limiting for these IPs (for health checks, etc.)
	WhitelistIPs []string

	// Custom error messages
	TooManyRequestsMsg string
	LoginLimitMsg      string
}

// DefaultRateLimitConfig provides sensible defaults for rate limiting
func DefaultRateLimitConfig() *RateLimitConfig {
	return &RateLimitConfig{
		GlobalRequestsPerMinute: 1000,
		GlobalBurst:             50,

		LoginAttemptsPerMinute: 5,
		LoginAttemptsBurst:     3,
		LoginWindowMinutes:     15,

		APIRequestsPerMinute: 300,
		APIBurst:             20,

		WhitelistIPs:       []string{"127.0.0.1", "::1"},
		TooManyRequestsMsg: "Too many requests. Please try again later.",
		LoginLimitMsg:      "Too many login attempts. Please try again in 15 minutes.",
	}
}

// RateLimitMiddleware creates a rate limiting middleware
type RateLimitMiddleware struct {
	config *RateLimitConfig

	// Different limiters for different endpoint types
	globalLimiter RateLimiter
	loginLimiter  RateLimiter
	apiLimiter    RateLimiter

	whitelistMap map[string]bool
}

// NewRateLimitMiddleware creates a new rate limit middleware
func NewRateLimitMiddleware(config *RateLimitConfig) *RateLimitMiddleware {
	if config == nil {
		config = DefaultRateLimitConfig()
	}

	// Create whitelist map for O(1) lookup
	whitelistMap := make(map[string]bool)
	for _, ip := range config.WhitelistIPs {
		whitelistMap[ip] = true
	}

	return &RateLimitMiddleware{
		config: config,
		globalLimiter: NewTokenBucketLimiter(
			config.GlobalRequestsPerMinute,
			time.Minute,
			config.GlobalBurst,
		),
		loginLimiter: NewTokenBucketLimiter(
			config.LoginAttemptsPerMinute,
			time.Duration(config.LoginWindowMinutes)*time.Minute,
			config.LoginAttemptsBurst,
		),
		apiLimiter: NewTokenBucketLimiter(
			config.APIRequestsPerMinute,
			time.Minute,
			config.APIBurst,
		),
		whitelistMap: whitelistMap,
	}
}

// GlobalRateLimit applies global rate limiting to all requests
func (rlm *RateLimitMiddleware) GlobalRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Skip rate limiting for whitelisted IPs
		if rlm.whitelistMap[clientIP] {
			c.Next()
			return
		}

		// Check global rate limit
		if !rlm.globalLimiter.Allow(clientIP) {
			rlm.sendRateLimitResponse(c, rlm.config.TooManyRequestsMsg, rlm.globalLimiter, clientIP)
			return
		}

		// Add rate limit headers
		rlm.addRateLimitHeaders(c, rlm.globalLimiter, clientIP)
		c.Next()
	}
}

// LoginRateLimit applies stricter rate limiting to login attempts
func (rlm *RateLimitMiddleware) LoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Skip rate limiting for whitelisted IPs
		if rlm.whitelistMap[clientIP] {
			c.Next()
			return
		}

		// Check login-specific rate limit
		if !rlm.loginLimiter.Allow(clientIP) {
			rlm.sendRateLimitResponse(c, rlm.config.LoginLimitMsg, rlm.loginLimiter, clientIP)
			return
		}

		// Add rate limit headers
		rlm.addRateLimitHeaders(c, rlm.loginLimiter, clientIP)
		c.Next()
	}
}

// APIRateLimit applies rate limiting to API endpoints
func (rlm *RateLimitMiddleware) APIRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// Skip rate limiting for whitelisted IPs
		if rlm.whitelistMap[clientIP] {
			c.Next()
			return
		}

		// Check API-specific rate limit
		if !rlm.apiLimiter.Allow(clientIP) {
			rlm.sendRateLimitResponse(c, rlm.config.TooManyRequestsMsg, rlm.apiLimiter, clientIP)
			return
		}

		// Add rate limit headers
		rlm.addRateLimitHeaders(c, rlm.apiLimiter, clientIP)
		c.Next()
	}
}

// UserBasedRateLimit applies rate limiting based on authenticated user
func (rlm *RateLimitMiddleware) UserBasedRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user from context (set by JWT middleware)
		username, exists := c.Get("user")
		if !exists {
			// Fall back to IP-based limiting
			c.Next()
			return
		}

		userKey := fmt.Sprintf("user:%s", username)

		// Check user-specific rate limit
		if !rlm.apiLimiter.Allow(userKey) {
			rlm.sendRateLimitResponse(c, rlm.config.TooManyRequestsMsg, rlm.apiLimiter, userKey)
			return
		}

		// Add rate limit headers
		rlm.addRateLimitHeaders(c, rlm.apiLimiter, userKey)
		c.Next()
	}
}

// sendRateLimitResponse sends a standardized rate limit exceeded response
func (rlm *RateLimitMiddleware) sendRateLimitResponse(c *gin.Context, message string, limiter RateLimiter, key string) {
	resetTime := limiter.GetResetTime(key)
	retryAfter := int(time.Until(resetTime).Seconds())

	// Add standard rate limit headers
	c.Header("X-RateLimit-Limit", strconv.Itoa(rlm.config.APIRequestsPerMinute))
	c.Header("X-RateLimit-Remaining", "0")
	c.Header("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
	c.Header("Retry-After", strconv.Itoa(retryAfter))

	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":       "rate_limit_exceeded",
		"message":     message,
		"retry_after": retryAfter,
		"reset_time":  resetTime.Unix(),
	})
	c.Abort()
}

// addRateLimitHeaders adds standard rate limit headers to responses
func (rlm *RateLimitMiddleware) addRateLimitHeaders(c *gin.Context, limiter RateLimiter, key string) {
	remaining := limiter.GetRemaining(key)
	resetTime := limiter.GetResetTime(key)

	c.Header("X-RateLimit-Limit", strconv.Itoa(rlm.config.APIRequestsPerMinute))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))
}

// ResetUserRateLimit allows manual reset of rate limits (for admin operations)
func (rlm *RateLimitMiddleware) ResetUserRateLimit(identifier string) {
	rlm.globalLimiter.Reset(identifier)
	rlm.loginLimiter.Reset(identifier)
	rlm.apiLimiter.Reset(identifier)
	rlm.apiLimiter.Reset(fmt.Sprintf("user:%s", identifier))
}

// GetRateLimitStatus returns current rate limit status for monitoring
func (rlm *RateLimitMiddleware) GetRateLimitStatus(identifier string) map[string]interface{} {
	return map[string]interface{}{
		"global_remaining": rlm.globalLimiter.GetRemaining(identifier),
		"global_reset":     rlm.globalLimiter.GetResetTime(identifier).Unix(),
		"login_remaining":  rlm.loginLimiter.GetRemaining(identifier),
		"login_reset":      rlm.loginLimiter.GetResetTime(identifier).Unix(),
		"api_remaining":    rlm.apiLimiter.GetRemaining(identifier),
		"api_reset":        rlm.apiLimiter.GetResetTime(identifier).Unix(),
	}
}
