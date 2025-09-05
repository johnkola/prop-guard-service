package middleware

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeadersConfig holds configuration for security headers
type SecurityHeadersConfig struct {
	// Content Security Policy (CSP)
	ContentSecurityPolicy string

	// X-Frame-Options: Prevents clickjacking attacks
	FrameOptions string // DENY, SAMEORIGIN, or ALLOW-FROM uri

	// X-Content-Type-Options: Prevents MIME type sniffing
	ContentTypeOptions string // nosniff

	// X-XSS-Protection: Enables XSS filtering in older browsers
	XSSProtection string // 1; mode=block
	// Strict-Transport-Security (HSTS): Forces HTTPS connections
	StrictTransportSecurity string

	// Referrer-Policy: Controls referrer information sent with requests
	ReferrerPolicy string

	// Permissions-Policy: Controls browser feature permissions
	PermissionsPolicy string

	// X-Permitted-Cross-Domain-Policies: Controls Adobe Flash/PDF cross-domain access
	PermittedCrossDomainPolicies string

	// X-DNS-Prefetch-Control: Controls DNS prefetching
	DNSPrefetchControl string

	// Custom security headers
	CustomHeaders map[string]string

	// Environment-specific settings
	Development bool
	TLSEnabled  bool
}

// DefaultSecurityHeadersConfig provides secure defaults
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	isDevelopment := os.Getenv("GIN_MODE") == "debug" || os.Getenv("NODE_ENV") == "development"

	config := &SecurityHeadersConfig{
		// Strict CSP for production, more permissive for development
		ContentSecurityPolicy: buildDefaultCSP(isDevelopment),

		// Prevent framing to avoid clickjacking
		FrameOptions: "DENY",

		// Prevent MIME type sniffing
		ContentTypeOptions: "nosniff",

		// Enable XSS protection in legacy browsers
		XSSProtection: "1; mode=block",

		// HSTS for HTTPS (1 year with includeSubDomains)
		StrictTransportSecurity: "max-age=31536000; includeSubDomains; preload",

		// Control referrer information
		ReferrerPolicy: "strict-origin-when-cross-origin",

		// Restrict browser features
		PermissionsPolicy: buildDefaultPermissionsPolicy(),

		// Restrict Flash/PDF cross-domain access
		PermittedCrossDomainPolicies: "none",

		// Control DNS prefetching
		DNSPrefetchControl: "off",

		// Custom headers for API security
		CustomHeaders: map[string]string{
			"X-Robots-Tag":  "noindex, nofollow, noarchive, nosnippet, noimageindex",
			"X-API-Version": "v1",
			"Cache-Control": "no-cache, no-store, must-revalidate",
			"Pragma":        "no-cache",
			"Expires":       "0",
		},

		Development: isDevelopment,
		TLSEnabled:  os.Getenv("TLS_ENABLED") == "true",
	}

	return config
}

// buildDefaultCSP creates a default Content Security Policy
func buildDefaultCSP(isDevelopment bool) string {
	baseCSP := []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'", // unsafe-inline needed for some CSS frameworks
		"img-src 'self' data: https:",
		"font-src 'self' data:",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	}

	if isDevelopment {
		// More permissive CSP for development (webpack dev server, etc.)
		baseCSP = append(baseCSP,
			"script-src 'self' 'unsafe-eval' 'unsafe-inline' localhost:* 127.0.0.1:*",
			"connect-src 'self' ws: wss: localhost:* 127.0.0.1:*",
		)
	}

	return strings.Join(baseCSP, "; ")
}

// buildDefaultPermissionsPolicy creates a restrictive permissions policy
func buildDefaultPermissionsPolicy() string {
	restrictedFeatures := []string{
		"accelerometer=()",
		"ambient-light-sensor=()",
		"autoplay=()",
		"battery=()",
		"camera=()",
		"cross-origin-isolated=()",
		"display-capture=()",
		"document-domain=()",
		"encrypted-media=()",
		"execution-while-not-rendered=()",
		"execution-while-out-of-viewport=()",
		"fullscreen=()",
		"geolocation=()",
		"gyroscope=()",
		"magnetometer=()",
		"microphone=()",
		"midi=()",
		"navigation-override=()",
		"payment=()",
		"picture-in-picture=()",
		"publickey-credentials-get=()",
		"screen-wake-lock=()",
		"sync-xhr=()",
		"usb=()",
		"web-share=()",
		"xr-spatial-tracking=()",
	}

	return strings.Join(restrictedFeatures, ", ")
}

// SecurityHeadersMiddleware applies comprehensive security headers
func SecurityHeadersMiddleware(config *SecurityHeadersConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(c *gin.Context) {
		// Apply core security headers
		applySecurityHeaders(c, config)

		// Apply environment-specific headers
		if config.TLSEnabled {
			applyTLSHeaders(c, config)
		}

		// Apply API-specific headers for API endpoints
		if isAPIEndpoint(c.Request.RequestURI) {
			applyAPISecurityHeaders(c)
		}

		c.Next()
	}
}

// applySecurityHeaders applies the main security headers
func applySecurityHeaders(c *gin.Context, config *SecurityHeadersConfig) {
	// Content Security Policy
	if config.ContentSecurityPolicy != "" {
		c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
	}

	// X-Frame-Options (clickjacking protection)
	if config.FrameOptions != "" {
		c.Header("X-Frame-Options", config.FrameOptions)
	}

	// X-Content-Type-Options (MIME sniffing protection)
	if config.ContentTypeOptions != "" {
		c.Header("X-Content-Type-Options", config.ContentTypeOptions)
	}

	// X-XSS-Protection (XSS protection for older browsers)
	if config.XSSProtection != "" {
		c.Header("X-XSS-Protection", config.XSSProtection)
	}

	// Referrer-Policy
	if config.ReferrerPolicy != "" {
		c.Header("Referrer-Policy", config.ReferrerPolicy)
	}

	// Permissions-Policy
	if config.PermissionsPolicy != "" {
		c.Header("Permissions-Policy", config.PermissionsPolicy)
	}

	// X-Permitted-Cross-Domain-Policies
	if config.PermittedCrossDomainPolicies != "" {
		c.Header("X-Permitted-Cross-Domain-Policies", config.PermittedCrossDomainPolicies)
	}

	// X-DNS-Prefetch-Control
	if config.DNSPrefetchControl != "" {
		c.Header("X-DNS-Prefetch-Control", config.DNSPrefetchControl)
	}

	// Apply custom headers
	for header, value := range config.CustomHeaders {
		c.Header(header, value)
	}
}

// applyTLSHeaders applies TLS/HTTPS-specific headers
func applyTLSHeaders(c *gin.Context, config *SecurityHeadersConfig) {
	// Strict-Transport-Security (HSTS)
	if config.StrictTransportSecurity != "" {
		c.Header("Strict-Transport-Security", config.StrictTransportSecurity)
	}

	// Expect-CT (Certificate Transparency)
	c.Header("Expect-CT", "max-age=86400, enforce")
}

// applyAPISecurityHeaders applies additional headers for API endpoints
func applyAPISecurityHeaders(c *gin.Context) {
	// Prevent caching of API responses
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate, private")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	// Add API-specific security headers
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")

	// Indicate this is a JSON API
	if c.GetHeader("Content-Type") == "" {
		c.Header("Content-Type", "application/json; charset=utf-8")
	}
}

// isAPIEndpoint checks if the request is for an API endpoint
func isAPIEndpoint(uri string) bool {
	apiPrefixes := []string{"/api/", "/v1/", "/v2/"}

	for _, prefix := range apiPrefixes {
		if strings.HasPrefix(uri, prefix) {
			return true
		}
	}

	return false
}

// DevelopmentSecurityHeadersMiddleware provides a more permissive configuration for development
func DevelopmentSecurityHeadersMiddleware() gin.HandlerFunc {
	config := &SecurityHeadersConfig{
		// More permissive CSP for development
		ContentSecurityPolicy: "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: ws: wss: localhost:* 127.0.0.1:*; object-src 'none'; base-uri 'self';",

		FrameOptions:       "SAMEORIGIN", // Less restrictive for development tools
		ContentTypeOptions: "nosniff",
		XSSProtection:      "1; mode=block",
		ReferrerPolicy:     "no-referrer-when-downgrade",

		// No HSTS in development
		StrictTransportSecurity: "",

		CustomHeaders: map[string]string{
			"X-Development-Mode": "true",
		},

		Development: true,
		TLSEnabled:  false,
	}

	return SecurityHeadersMiddleware(config)
}

// ProductionSecurityHeadersMiddleware provides strict security headers for production
func ProductionSecurityHeadersMiddleware() gin.HandlerFunc {
	config := &SecurityHeadersConfig{
		// Strict CSP for production
		ContentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests;",

		FrameOptions:       "DENY",
		ContentTypeOptions: "nosniff",
		XSSProtection:      "1; mode=block",

		// Strict HSTS with preloading
		StrictTransportSecurity: "max-age=63072000; includeSubDomains; preload",

		ReferrerPolicy:               "strict-origin-when-cross-origin",
		PermissionsPolicy:            buildDefaultPermissionsPolicy(),
		PermittedCrossDomainPolicies: "none",
		DNSPrefetchControl:           "off",

		CustomHeaders: map[string]string{
			"X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet, noimageindex",
			"Server":       "PropGuard", // Hide server information
		},

		Development: false,
		TLSEnabled:  true,
	}

	return SecurityHeadersMiddleware(config)
}

// SecurityHeadersStatus returns current security headers configuration for monitoring
func SecurityHeadersStatus(config *SecurityHeadersConfig) map[string]interface{} {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return map[string]interface{}{
		"csp_enabled":      config.ContentSecurityPolicy != "",
		"hsts_enabled":     config.StrictTransportSecurity != "",
		"frame_protection": config.FrameOptions != "",
		"xss_protection":   config.XSSProtection != "",
		"development_mode": config.Development,
		"tls_enabled":      config.TLSEnabled,
		"custom_headers":   len(config.CustomHeaders),
	}
}

// ValidateSecurityConfig validates security headers configuration
func ValidateSecurityConfig(config *SecurityHeadersConfig) []string {
	var warnings []string

	if config.ContentSecurityPolicy == "" {
		warnings = append(warnings, "Content Security Policy is not set")
	}

	if config.FrameOptions == "" {
		warnings = append(warnings, "X-Frame-Options is not set - clickjacking protection disabled")
	}

	if config.TLSEnabled && config.StrictTransportSecurity == "" {
		warnings = append(warnings, "HSTS is not configured despite TLS being enabled")
	}

	if !config.TLSEnabled && !config.Development {
		warnings = append(warnings, "TLS is not enabled in production environment")
	}

	if strings.Contains(config.ContentSecurityPolicy, "'unsafe-eval'") && !config.Development {
		warnings = append(warnings, "CSP contains 'unsafe-eval' in production - security risk")
	}

	return warnings
}
