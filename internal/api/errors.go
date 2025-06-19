package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

// RespondWithError sends a standardized error response
func RespondWithError(c *gin.Context, status int, message string) {
	c.JSON(status, ErrorResponse{
		Error:   http.StatusText(status),
		Code:    status,
		Message: message,
	})
}

// Common error responses
func BadRequest(c *gin.Context, message string) {
	RespondWithError(c, http.StatusBadRequest, message)
}

func NotFound(c *gin.Context, message string) {
	RespondWithError(c, http.StatusNotFound, message)
}

func InternalServerError(c *gin.Context, err error) {
	RespondWithError(c, http.StatusInternalServerError, "Internal server error")
	// Log the actual error for debugging
	c.Error(err)
}

func Unauthorized(c *gin.Context, message string) {
	RespondWithError(c, http.StatusUnauthorized, message)
}
