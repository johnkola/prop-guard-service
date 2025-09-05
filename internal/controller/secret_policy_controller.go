package controller

import (
	"net/http"
	"strconv"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/security"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type SecretPolicyController struct {
	policyService service.SecretPolicyService
	genService    service.SecretGenerationService
	jwtMiddleware *security.JWTMiddleware
}

func NewSecretPolicyController(
	policyService service.SecretPolicyService,
	genService service.SecretGenerationService,
	jwtMiddleware *security.JWTMiddleware,
) *SecretPolicyController {
	return &SecretPolicyController{
		policyService: policyService,
		genService:    genService,
		jwtMiddleware: jwtMiddleware,
	}
}

// RegisterRoutes registers secret policy management routes
func (c *SecretPolicyController) RegisterRoutes(router *gin.RouterGroup) {
	policies := router.Group("/policies")
	policies.Use(c.jwtMiddleware.Authenticate())
	{
		// Policy CRUD operations
		policies.POST("", c.CreatePolicy)
		policies.GET("", c.ListPolicies)
		policies.GET("/:id", c.GetPolicy)
		policies.PUT("/:id", c.UpdatePolicy)
		policies.DELETE("/:id", c.DeletePolicy)

		// Policy enforcement and validation
		policies.POST("/validate", c.ValidateSecret)
		policies.POST("/generate", c.GenerateSecret)
		policies.POST("/preview", c.PreviewGeneration)
		policies.GET("/status", c.GetPolicyStatus)
		policies.GET("/types", c.GetSecretTypes)

		// Path-based operations
		policies.GET("/for-path", c.GetPolicyForPath)
	}
}

// CreatePolicy creates a new secret policy
// @Summary Create secret policy
// @Description Creates a new secret policy for managing secret generation and validation
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param policy body dto.CreateSecretPolicyRequest true "Policy details"
// @Success 201 {object} dto.SecretPolicyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies [post]
func (c *SecretPolicyController) CreatePolicy(ctx *gin.Context) {
	var req dto.CreateSecretPolicyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request format",
			Message: err.Error(),
		})
		return
	}

	username := ctx.GetString("username")
	if username == "" {
		username = "system"
	}

	policy, err := c.policyService.CreatePolicy(ctx.Request.Context(), &req, username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to create policy",
			Message: err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusCreated, policy)
}

// ListPolicies lists all secret policies with pagination
// @Summary List secret policies
// @Description Retrieves a paginated list of secret policies
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Items per page" default(20)
// @Success 200 {object} dto.ListSecretPoliciesResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies [get]
func (c *SecretPolicyController) ListPolicies(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("page_size", "20"))

	result, err := c.policyService.ListPolicies(ctx.Request.Context(), page, pageSize)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to list policies",
			Message: err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, result)
}

// GetPolicy retrieves a secret policy by ID
// @Summary Get secret policy
// @Description Retrieves a secret policy by its ID
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Success 200 {object} dto.SecretPolicyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/{id} [get]
func (c *SecretPolicyController) GetPolicy(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid policy ID",
			Message: "Policy ID must be a valid UUID",
		})
		return
	}

	policy, err := c.policyService.GetPolicy(ctx.Request.Context(), id)
	if err != nil {
		ctx.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:   "Policy not found",
			Message: err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, policy)
}

// UpdatePolicy updates an existing secret policy
// @Summary Update secret policy
// @Description Updates an existing secret policy
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Param policy body dto.UpdateSecretPolicyRequest true "Updated policy details"
// @Success 200 {object} dto.SecretPolicyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/{id} [put]
func (c *SecretPolicyController) UpdatePolicy(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid policy ID",
			Message: "Policy ID must be a valid UUID",
		})
		return
	}

	var req dto.UpdateSecretPolicyRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request format",
			Message: err.Error(),
		})
		return
	}

	username := ctx.GetString("username")
	if username == "" {
		username = "system"
	}

	policy, err := c.policyService.UpdatePolicy(ctx.Request.Context(), id, &req, username)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to update policy",
			Message: err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, policy)
}

// DeletePolicy deletes a secret policy
// @Summary Delete secret policy
// @Description Deletes a secret policy by ID
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param id path string true "Policy ID"
// @Success 204 "No content"
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/{id} [delete]
func (c *SecretPolicyController) DeletePolicy(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid policy ID",
			Message: "Policy ID must be a valid UUID",
		})
		return
	}

	username := ctx.GetString("username")
	if username == "" {
		username = "system"
	}

	if err := c.policyService.DeletePolicy(ctx.Request.Context(), id, username); err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to delete policy",
			Message: err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusNoContent, nil)
}

// ValidateSecret validates a secret value against applicable policies
// @Summary Validate secret against policy
// @Description Validates a secret value against the policy for its path
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param request body dto.ValidateSecretRequest true "Secret validation request"
// @Success 200 {object} dto.ValidateSecretResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/validate [post]
func (c *SecretPolicyController) ValidateSecret(ctx *gin.Context) {
	var req dto.ValidateSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request format",
			Message: err.Error(),
		})
		return
	}

	err := c.policyService.ValidateSecretAgainstPolicy(ctx.Request.Context(), req.Path, req.Value)

	response := dto.ValidateSecretResponse{
		Valid: err == nil,
	}

	if err != nil {
		response.Errors = []string{err.Error()}
	}

	// Try to get policy info for the path
	if policy, pErr := c.policyService.GetPolicyForPath(ctx.Request.Context(), req.Path); pErr == nil {
		response.PolicyID = policy.ID.String()
		response.PolicyName = policy.Name
		response.SecretType = policy.SecretType
	}

	ctx.JSON(http.StatusOK, response)
}

// GenerateSecret generates a secret based on policy for a given path
// @Summary Generate secret based on policy
// @Description Generates a secret value based on the policy for the specified path
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param request body dto.GenerateSecretRequest true "Secret generation request"
// @Success 200 {object} dto.GenerateSecretResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/generate [post]
func (c *SecretPolicyController) GenerateSecret(ctx *gin.Context) {
	var req dto.GenerateSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request format",
			Message: err.Error(),
		})
		return
	}

	generated, err := c.policyService.GenerateSecretForPath(ctx.Request.Context(), req.Path)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Failed to generate secret",
			Message: err.Error(),
		})
		return
	}

	response := dto.GenerateSecretResponse{
		Generated:  generated,
		PolicyID:   generated["policy_id"].(string),
		PolicyName: generated["policy_name"].(string),
		SecretType: generated["secret_type"].(entity.SecretType),
		Message:    "Secret generated successfully based on policy",
	}

	// Remove policy metadata from generated data for cleaner response
	delete(response.Generated, "policy_id")
	delete(response.Generated, "policy_name")
	delete(response.Generated, "secret_type")

	ctx.JSON(http.StatusOK, response)
}

// PreviewGeneration previews what would be generated for given rules
// @Summary Preview secret generation
// @Description Previews what would be generated with the given secret type and rules
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param request body dto.SecretGenerationPreviewRequest true "Generation preview request"
// @Success 200 {object} dto.SecretGenerationPreviewResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/preview [post]
func (c *SecretPolicyController) PreviewGeneration(ctx *gin.Context) {
	var req dto.SecretGenerationPreviewRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Invalid request format",
			Message: err.Error(),
		})
		return
	}

	// Create a temporary policy for preview
	tempPolicy := &entity.SecretPolicy{
		SecretType:        req.SecretType,
		RegenerationRules: req.RegenerationRules,
	}

	preview, err := c.genService.GenerateSecret(tempPolicy, req.RegenerationRules)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Failed to generate preview",
			Message: err.Error(),
		})
		return
	}

	rules, _ := c.genService.ParseGenerationRules(req.RegenerationRules)

	response := dto.SecretGenerationPreviewResponse{
		Preview:    preview,
		Rules:      map[string]interface{}{"parsed": rules},
		SecretType: req.SecretType,
		Message:    "This is a preview of what would be generated",
	}

	ctx.JSON(http.StatusOK, response)
}

// GetPolicyStatus gets the status of policy enforcement system
// @Summary Get policy status
// @Description Retrieves statistics about policy enforcement
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Success 200 {object} dto.SecretPolicyStatusResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/status [get]
func (c *SecretPolicyController) GetPolicyStatus(ctx *gin.Context) {
	// This would require additional methods to gather statistics
	// For now, provide a basic implementation

	policies, err := c.policyService.ListPolicies(ctx.Request.Context(), 1, 1000)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, dto.ErrorResponse{
			Error:   "Failed to get policy status",
			Message: err.Error(),
		})
		return
	}

	enabledCount := 0
	policiesByType := make(map[entity.SecretType]int)

	for _, policy := range policies.Policies {
		if policy.Enabled {
			enabledCount++
		}
		policiesByType[policy.SecretType]++
	}

	response := dto.SecretPolicyStatusResponse{
		TotalPolicies:   int(policies.Total),
		EnabledPolicies: enabledCount,
		PoliciesByType:  policiesByType,
		ExpiredSecrets:  0, // Would need implementation
		RotationNeeded:  0, // Would need implementation
		LastUpdated:     policies.Policies[0].UpdatedAt,
	}

	ctx.JSON(http.StatusOK, response)
}

// GetSecretTypes gets information about supported secret types
// @Summary Get supported secret types
// @Description Retrieves information about all supported secret types
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Success 200 {object} dto.GetSecretTypesResponse
// @Failure 401 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/types [get]
func (c *SecretPolicyController) GetSecretTypes(ctx *gin.Context) {
	secretTypes := []dto.SecretTypeInfo{
		{
			Type:        entity.SecretTypePassword,
			Name:        "Password",
			Description: "Standard password with configurable complexity",
			Examples:    []string{"MyP@ssw0rd123"},
			Rules:       []string{"length", "include_upper", "include_lower", "include_numbers", "include_symbols"},
		},
		{
			Type:        entity.SecretTypeAPIKey,
			Name:        "API Key",
			Description: "API key with customizable format",
			Examples:    []string{"pgs_abc123def456", "sk-abc123def456"},
			Rules:       []string{"api_key_format", "prefix", "suffix"},
		},
		{
			Type:        entity.SecretTypeJWTSecret,
			Name:        "JWT Secret",
			Description: "Secret key for signing JWT tokens",
			Examples:    []string{"base64-encoded-secret"},
			Rules:       []string{"length", "algorithm", "jwt_issuer"},
		},
		{
			Type:        entity.SecretTypeRSAKeyPair,
			Name:        "RSA Key Pair",
			Description: "RSA public/private key pair",
			Examples:    []string{"-----BEGIN RSA PRIVATE KEY-----"},
			Rules:       []string{"key_size", "key_type"},
		},
		{
			Type:        entity.SecretTypeAESKey,
			Name:        "AES Key",
			Description: "AES encryption key",
			Examples:    []string{"base64-encoded-aes-key"},
			Rules:       []string{"key_size"},
		},
		{
			Type:        entity.SecretTypeDatabaseCred,
			Name:        "Database Credentials",
			Description: "Username and password for database access",
			Examples:    []string{`{"username": "dbuser", "password": "dbpass"}`},
			Rules:       []string{"length", "prefix"},
		},
		{
			Type:        entity.SecretTypeSSHKey,
			Name:        "SSH Key Pair",
			Description: "SSH public/private key pair",
			Examples:    []string{"ssh-rsa AAAAB3NzaC1yc2E..."},
			Rules:       []string{"key_size", "key_type"},
		},
	}

	response := dto.GetSecretTypesResponse{
		SecretTypes: secretTypes,
	}

	ctx.JSON(http.StatusOK, response)
}

// GetPolicyForPath gets the policy that applies to a specific path
// @Summary Get policy for path
// @Description Retrieves the policy that applies to a specific secret path
// @Tags Secret Policies
// @Accept json
// @Produce json
// @Param path query string true "Secret path"
// @Success 200 {object} dto.SecretPolicyResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Security BearerAuth
// @Router /policies/for-path [get]
func (c *SecretPolicyController) GetPolicyForPath(ctx *gin.Context) {
	path := ctx.Query("path")
	if path == "" {
		ctx.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:   "Missing path parameter",
			Message: "Path query parameter is required",
		})
		return
	}

	policy, err := c.policyService.GetPolicyForPath(ctx.Request.Context(), path)
	if err != nil {
		ctx.JSON(http.StatusNotFound, dto.ErrorResponse{
			Error:   "No policy found for path",
			Message: err.Error(),
		})
		return
	}

	response := dto.SecretPolicyResponse{
		ID:                   policy.ID,
		Name:                 policy.Name,
		Description:          policy.Description,
		PathPattern:          policy.PathPattern,
		RotationIntervalDays: policy.RotationIntervalDays,
		MaxAgeDays:           policy.MaxAgeDays,
		RequireApproval:      policy.RequireApproval,
		AutoRegenerate:       policy.AutoRegenerate,
		SecretType:           policy.SecretType,
		RegenerationRules:    policy.RegenerationRules,
		Enabled:              policy.Enabled,
		CreatedAt:            policy.CreatedAt,
		UpdatedAt:            policy.UpdatedAt,
		Version:              policy.Version,
	}

	ctx.JSON(http.StatusOK, response)
}
