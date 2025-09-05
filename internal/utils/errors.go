package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents a sanitized error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// RespondWithError sends a sanitized error response
func RespondWithError(c *gin.Context, statusCode int, message string, err error) {
	response := ErrorResponse{
		Error:   http.StatusText(statusCode),
		Message: message,
		Code:    statusCode,
	}

	// Only include error details in development mode
	if gin.Mode() == gin.DebugMode && err != nil {
		response.Error = err.Error()
	}

	c.JSON(statusCode, response)
}

// RespondWithValidationError sends a validation error response
func RespondWithValidationError(c *gin.Context, message string) {
	RespondWithError(c, http.StatusBadRequest, message, nil)
}

// RespondWithInternalError sends an internal server error response
func RespondWithInternalError(c *gin.Context, message string, err error) {
	RespondWithError(c, http.StatusInternalServerError, message, err)
}

// RespondWithUnauthorizedError sends an unauthorized error response
func RespondWithUnauthorizedError(c *gin.Context, message string) {
	RespondWithError(c, http.StatusUnauthorized, message, nil)
}

// RespondWithForbiddenError sends a forbidden error response
func RespondWithForbiddenError(c *gin.Context, message string) {
	RespondWithError(c, http.StatusForbidden, message, nil)
}

// RespondWithNotFoundError sends a not found error response
func RespondWithNotFoundError(c *gin.Context, message string) {
	RespondWithError(c, http.StatusNotFound, message, nil)
}
