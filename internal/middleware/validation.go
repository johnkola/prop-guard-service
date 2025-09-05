package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

// ValidationConfig holds configuration for input validation
type ValidationConfig struct {
	// Maximum request body size in bytes
	MaxBodySize int64

	// Maximum URL length
	MaxURLLength int

	// Maximum parameter value length
	MaxParamLength int

	// Maximum number of form parameters
	MaxFormParams int

	// Enable SQL injection protection
	SQLInjectionProtection bool

	// Enable XSS protection
	XSSProtection bool

	// Enable path traversal protection
	PathTraversalProtection bool

	// Enable command injection protection
	CommandInjectionProtection bool

	// Custom validation patterns
	CustomPatterns map[string]*regexp.Regexp

	// Allowed file extensions for uploads
	AllowedFileExtensions []string

	// Enable strict JSON validation
	StrictJSONValidation bool

	// Custom sanitization functions
	CustomSanitizers map[string]func(string) string
}

// DefaultValidationConfig provides secure validation defaults
func DefaultValidationConfig() *ValidationConfig {
	return &ValidationConfig{
		MaxBodySize:                1024 * 1024, // 1MB
		MaxURLLength:               2048,        // 2KB URL limit
		MaxParamLength:             1000,        // 1KB per parameter
		MaxFormParams:              100,         // Max 100 form parameters
		SQLInjectionProtection:     true,
		XSSProtection:              true,
		PathTraversalProtection:    true,
		CommandInjectionProtection: true,
		StrictJSONValidation:       true,

		// Common malicious patterns
		CustomPatterns: map[string]*regexp.Regexp{
			"email":        regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
			"alphanumeric": regexp.MustCompile(`^[a-zA-Z0-9]+$`),
			"username":     regexp.MustCompile(`^[a-zA-Z0-9_-]{3,50}$`),
			"safe_string":  regexp.MustCompile(`^[a-zA-Z0-9\s\-_.,:;!?()]+$`),
		},

		AllowedFileExtensions: []string{".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".json"},

		// Default sanitizers
		CustomSanitizers: map[string]func(string) string{
			"html": html.EscapeString,
			"url":  url.QueryEscape,
			"trim": strings.TrimSpace,
		},
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// ValidationErrors holds multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

func (ve ValidationErrors) Error() string {
	var messages []string
	for _, err := range ve.Errors {
		messages = append(messages, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return strings.Join(messages, "; ")
}

// InputValidationMiddleware creates a comprehensive input validation middleware
func InputValidationMiddleware(config *ValidationConfig) gin.HandlerFunc {
	if config == nil {
		config = DefaultValidationConfig()
	}

	return func(c *gin.Context) {
		var validationErrors []ValidationError

		// Validate URL length
		if len(c.Request.URL.String()) > config.MaxURLLength {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "url",
				Message: fmt.Sprintf("URL length exceeds maximum of %d characters", config.MaxURLLength),
				Code:    "url_too_long",
			})
		}

		// Validate request method
		if !isAllowedMethod(c.Request.Method) {
			validationErrors = append(validationErrors, ValidationError{
				Field:   "method",
				Value:   c.Request.Method,
				Message: "HTTP method not allowed",
				Code:    "method_not_allowed",
			})
		}

		// Validate query parameters
		if queryErrors := validateQueryParams(c, config); len(queryErrors) > 0 {
			validationErrors = append(validationErrors, queryErrors...)
		}

		// Validate path parameters
		if pathErrors := validatePathParams(c, config); len(pathErrors) > 0 {
			validationErrors = append(validationErrors, pathErrors...)
		}

		// Validate headers
		if headerErrors := validateHeaders(c, config); len(headerErrors) > 0 {
			validationErrors = append(validationErrors, headerErrors...)
		}

		// Validate request body for POST/PUT/PATCH requests
		if hasBody(c.Request.Method) {
			if bodyErrors := validateRequestBody(c, config); len(bodyErrors) > 0 {
				validationErrors = append(validationErrors, bodyErrors...)
			}
		}

		// Return validation errors if any
		if len(validationErrors) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "validation_failed",
				"message": "Request validation failed",
				"details": validationErrors,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// validateQueryParams validates URL query parameters
func validateQueryParams(c *gin.Context, config *ValidationConfig) []ValidationError {
	var errors []ValidationError

	if len(c.Request.URL.Query()) > config.MaxFormParams {
		errors = append(errors, ValidationError{
			Field:   "query_params",
			Message: fmt.Sprintf("Too many query parameters (max %d)", config.MaxFormParams),
			Code:    "too_many_params",
		})
		return errors
	}

	for key, values := range c.Request.URL.Query() {
		// Validate parameter name
		if len(key) > config.MaxParamLength {
			errors = append(errors, ValidationError{
				Field:   key,
				Message: fmt.Sprintf("Parameter name too long (max %d)", config.MaxParamLength),
				Code:    "param_name_too_long",
			})
			continue
		}

		// Check for malicious parameter names
		if containsMaliciousPatterns(key, config) {
			errors = append(errors, ValidationError{
				Field:   key,
				Message: "Parameter name contains potentially malicious content",
				Code:    "malicious_param_name",
			})
			continue
		}

		// Validate parameter values
		for _, value := range values {
			if paramErrors := validateParamValue(key, value, config); len(paramErrors) > 0 {
				errors = append(errors, paramErrors...)
			}
		}
	}

	return errors
}

// validatePathParams validates URL path parameters
func validatePathParams(c *gin.Context, config *ValidationConfig) []ValidationError {
	var errors []ValidationError

	// Get all path parameters from Gin
	for _, param := range c.Params {
		if paramErrors := validateParamValue(param.Key, param.Value, config); len(paramErrors) > 0 {
			errors = append(errors, paramErrors...)
		}

		// Check for path traversal attempts
		if config.PathTraversalProtection && containsPathTraversal(param.Value) {
			errors = append(errors, ValidationError{
				Field:   param.Key,
				Value:   sanitizeForLogging(param.Value),
				Message: "Path traversal attempt detected",
				Code:    "path_traversal",
			})
		}
	}

	return errors
}

// validateHeaders validates HTTP headers
func validateHeaders(c *gin.Context, config *ValidationConfig) []ValidationError {
	var errors []ValidationError

	// Check for suspicious headers
	suspiciousHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"X-Originating-IP",
	}

	for _, header := range suspiciousHeaders {
		if value := c.GetHeader(header); value != "" {
			if containsMaliciousPatterns(value, config) {
				errors = append(errors, ValidationError{
					Field:   header,
					Value:   sanitizeForLogging(value),
					Message: "Suspicious header value detected",
					Code:    "suspicious_header",
				})
			}
		}
	}

	// Validate User-Agent
	userAgent := c.GetHeader("User-Agent")
	if userAgent != "" && len(userAgent) > 500 {
		errors = append(errors, ValidationError{
			Field:   "User-Agent",
			Message: "User-Agent header too long",
			Code:    "header_too_long",
		})
	}

	return errors
}

// validateRequestBody validates the request body
func validateRequestBody(c *gin.Context, config *ValidationConfig) []ValidationError {
	var errors []ValidationError

	// Check content length
	if c.Request.ContentLength > config.MaxBodySize {
		errors = append(errors, ValidationError{
			Field:   "body",
			Message: fmt.Sprintf("Request body too large (max %d bytes)", config.MaxBodySize),
			Code:    "body_too_large",
		})
		return errors
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, config.MaxBodySize+1))
	if err != nil {
		errors = append(errors, ValidationError{
			Field:   "body",
			Message: "Failed to read request body",
			Code:    "body_read_error",
		})
		return errors
	}

	// Check if body exceeds limit
	if int64(len(body)) > config.MaxBodySize {
		errors = append(errors, ValidationError{
			Field:   "body",
			Message: fmt.Sprintf("Request body too large (max %d bytes)", config.MaxBodySize),
			Code:    "body_too_large",
		})
		return errors
	}

	// Restore body for downstream handlers
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	// Validate JSON if Content-Type is JSON
	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") && config.StrictJSONValidation {
		if jsonErrors := validateJSONBody(body, config); len(jsonErrors) > 0 {
			errors = append(errors, jsonErrors...)
		}
	}

	// Check for malicious content in body
	bodyString := string(body)
	if containsMaliciousPatterns(bodyString, config) {
		errors = append(errors, ValidationError{
			Field:   "body",
			Message: "Request body contains potentially malicious content",
			Code:    "malicious_content",
		})
	}

	return errors
}

// validateJSONBody validates JSON request body structure
func validateJSONBody(body []byte, config *ValidationConfig) []ValidationError {
	var errors []ValidationError

	// Check if valid JSON
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		errors = append(errors, ValidationError{
			Field:   "body",
			Message: "Invalid JSON format",
			Code:    "invalid_json",
		})
		return errors
	}

	// Validate JSON depth and size
	if jsonErrors := validateJSONStructure(jsonData, 0, config); len(jsonErrors) > 0 {
		errors = append(errors, jsonErrors...)
	}

	return errors
}

// validateJSONStructure recursively validates JSON structure
func validateJSONStructure(data interface{}, depth int, config *ValidationConfig) []ValidationError {
	var errors []ValidationError
	maxDepth := 10 // Prevent deeply nested JSON attacks

	if depth > maxDepth {
		errors = append(errors, ValidationError{
			Field:   "body",
			Message: fmt.Sprintf("JSON structure too deeply nested (max depth %d)", maxDepth),
			Code:    "json_too_deep",
		})
		return errors
	}

	switch v := data.(type) {
	case map[string]interface{}:
		if len(v) > config.MaxFormParams {
			errors = append(errors, ValidationError{
				Field:   "body",
				Message: fmt.Sprintf("Too many JSON properties (max %d)", config.MaxFormParams),
				Code:    "too_many_json_props",
			})
		}
		for key, value := range v {
			// Validate keys
			if len(key) > config.MaxParamLength {
				errors = append(errors, ValidationError{
					Field:   key,
					Message: fmt.Sprintf("JSON key too long (max %d)", config.MaxParamLength),
					Code:    "json_key_too_long",
				})
			}
			// Recursively validate values
			if subErrors := validateJSONStructure(value, depth+1, config); len(subErrors) > 0 {
				errors = append(errors, subErrors...)
			}
		}
	case []interface{}:
		if len(v) > config.MaxFormParams*2 { // Allow more array elements
			errors = append(errors, ValidationError{
				Field:   "body",
				Message: fmt.Sprintf("JSON array too large (max %d elements)", config.MaxFormParams*2),
				Code:    "json_array_too_large",
			})
		}
		for _, value := range v {
			if subErrors := validateJSONStructure(value, depth+1, config); len(subErrors) > 0 {
				errors = append(errors, subErrors...)
			}
		}
	case string:
		if len(v) > config.MaxParamLength*5 { // Allow longer string values
			errors = append(errors, ValidationError{
				Field:   "body",
				Message: fmt.Sprintf("JSON string value too long (max %d)", config.MaxParamLength*5),
				Code:    "json_string_too_long",
			})
		}
		// Check for malicious content in string values
		if containsMaliciousPatterns(v, config) {
			errors = append(errors, ValidationError{
				Field:   "body",
				Value:   sanitizeForLogging(v),
				Message: "JSON contains potentially malicious string content",
				Code:    "malicious_json_content",
			})
		}
	}

	return errors
}

// validateParamValue validates a parameter value
func validateParamValue(key, value string, config *ValidationConfig) []ValidationError {
	var errors []ValidationError

	// Check parameter value length
	if len(value) > config.MaxParamLength {
		errors = append(errors, ValidationError{
			Field:   key,
			Value:   sanitizeForLogging(value),
			Message: fmt.Sprintf("Parameter value too long (max %d)", config.MaxParamLength),
			Code:    "param_value_too_long",
		})
	}

	// Check for non-UTF8 content
	if !utf8.ValidString(value) {
		errors = append(errors, ValidationError{
			Field:   key,
			Message: "Parameter contains invalid UTF-8",
			Code:    "invalid_utf8",
		})
	}

	// Check for malicious patterns
	if containsMaliciousPatterns(value, config) {
		errors = append(errors, ValidationError{
			Field:   key,
			Value:   sanitizeForLogging(value),
			Message: "Parameter contains potentially malicious content",
			Code:    "malicious_content",
		})
	}

	return errors
}

// containsMaliciousPatterns checks for various malicious patterns
func containsMaliciousPatterns(input string, config *ValidationConfig) bool {
	input = strings.ToLower(input)

	// SQL injection patterns
	if config.SQLInjectionProtection {
		sqlPatterns := []string{
			"'", "\"", "--", "/*", "*/", "xp_", "sp_", "union", "select", "insert",
			"delete", "update", "drop", "create", "alter", "exec", "execute",
			"script", "javascript", "vbscript", "onload", "onerror", "onclick",
		}
		for _, pattern := range sqlPatterns {
			if strings.Contains(input, pattern) {
				return true
			}
		}
	}

	// XSS patterns
	if config.XSSProtection {
		xssPatterns := []string{
			"<script", "</script", "javascript:", "onload=", "onerror=", "onclick=",
			"onmouseover=", "onfocus=", "onblur=", "onchange=", "onsubmit=",
			"<iframe", "<object", "<embed", "<form", "vbscript:", "data:text/html",
		}
		for _, pattern := range xssPatterns {
			if strings.Contains(input, pattern) {
				return true
			}
		}
	}

	// Command injection patterns
	if config.CommandInjectionProtection {
		cmdPatterns := []string{
			";", "|", "&", "`", "$", "(", ")", "&&", "||", "../", "./",
			"cat ", "ls ", "pwd", "whoami", "id ", "ps ", "kill ", "rm ",
			"wget ", "curl ", "nc ", "netcat", "/bin/", "/usr/bin/",
		}
		for _, pattern := range cmdPatterns {
			if strings.Contains(input, pattern) {
				return true
			}
		}
	}

	return false
}

// containsPathTraversal checks for path traversal patterns
func containsPathTraversal(input string) bool {
	// Clean the path first
	cleaned := filepath.Clean(input)

	traversalPatterns := []string{
		"../", "..\\", "..%2f", "..%5c", "%2e%2e%2f", "%2e%2e%5c",
		".%2e%2f", ".%2e%5c", "%2e%2e/", "%2e%2e\\",
	}

	input = strings.ToLower(input)
	for _, pattern := range traversalPatterns {
		if strings.Contains(input, pattern) {
			return true
		}
	}

	// Check if cleaned path tries to go above root
	return strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../")
}

// sanitizeForLogging sanitizes input for safe logging
func sanitizeForLogging(input string) string {
	if len(input) > 100 {
		input = input[:100] + "..."
	}
	// Remove potential log injection patterns
	input = strings.ReplaceAll(input, "\n", "\\n")
	input = strings.ReplaceAll(input, "\r", "\\r")
	input = strings.ReplaceAll(input, "\t", "\\t")
	return input
}

// isAllowedMethod checks if HTTP method is allowed
func isAllowedMethod(method string) bool {
	allowedMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	for _, allowed := range allowedMethods {
		if method == allowed {
			return true
		}
	}
	return false
}

// hasBody checks if request method typically has a body
func hasBody(method string) bool {
	return method == "POST" || method == "PUT" || method == "PATCH"
}

// APIValidationMiddleware provides API-specific validation
func APIValidationMiddleware() gin.HandlerFunc {
	config := DefaultValidationConfig()
	config.MaxBodySize = 2 * 1024 * 1024 // 2MB for API requests
	config.StrictJSONValidation = true

	return InputValidationMiddleware(config)
}

// FileUploadValidationMiddleware provides validation for file uploads
func FileUploadValidationMiddleware(maxFileSize int64, allowedExtensions []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != "POST" && c.Request.Method != "PUT" {
			c.Next()
			return
		}

		contentType := c.GetHeader("Content-Type")
		if !strings.HasPrefix(contentType, "multipart/form-data") {
			c.Next()
			return
		}

		// Validate file uploads
		err := c.Request.ParseMultipartForm(maxFileSize)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "file_upload_error",
				"message": "Failed to parse multipart form",
			})
			c.Abort()
			return
		}

		if c.Request.MultipartForm != nil && c.Request.MultipartForm.File != nil {
			for fieldName, files := range c.Request.MultipartForm.File {
				for _, file := range files {
					// Check file size
					if file.Size > maxFileSize {
						c.JSON(http.StatusBadRequest, gin.H{
							"error":   "file_too_large",
							"message": fmt.Sprintf("File %s exceeds maximum size of %d bytes", file.Filename, maxFileSize),
							"field":   fieldName,
						})
						c.Abort()
						return
					}

					// Check file extension
					ext := strings.ToLower(filepath.Ext(file.Filename))
					allowed := false
					for _, allowedExt := range allowedExtensions {
						if ext == allowedExt {
							allowed = true
							break
						}
					}

					if !allowed {
						c.JSON(http.StatusBadRequest, gin.H{
							"error":   "invalid_file_type",
							"message": fmt.Sprintf("File type %s not allowed", ext),
							"field":   fieldName,
						})
						c.Abort()
						return
					}
				}
			}
		}

		c.Next()
	}
}
