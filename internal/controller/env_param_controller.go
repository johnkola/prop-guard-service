package controller

import (
	"net/http"
	"strconv"
	"strings"

	"PropGuard/internal/dto"
	"PropGuard/internal/entity"
	"PropGuard/internal/service"

	"github.com/gin-gonic/gin"
)

type EnvParamController struct {
	envParamService service.EnvParamService
}

func NewEnvParamController(envParamService service.EnvParamService) *EnvParamController {
	return &EnvParamController{
		envParamService: envParamService,
	}
}

// GetEnvParam godoc
// @Summary Get environment parameter by key
// @Description Retrieves an environment parameter by key and environment
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Param environment path string true "Environment name"
// @Param key path string true "Parameter key"
// @Security BearerAuth
// @Success 200 {object} entity.EnvParam
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /env-params/{environment}/{key} [get]
func (c *EnvParamController) GetEnvParam(ctx *gin.Context) {
	environment := ctx.Param("environment")
	key := ctx.Param("key")

	if environment == "" || key == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Environment and key are required"})
		return
	}

	param, err := c.envParamService.GetEnvParam(ctx.Request.Context(), key, environment)
	if err != nil {
		if param == nil {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "Environment parameter not found"})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	ctx.JSON(http.StatusOK, param)
}

// GetEnvParams godoc
// @Summary Get multiple environment parameters
// @Description Retrieves multiple environment parameters by keys for a specific environment
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Param environment path string true "Environment name"
// @Param keys body []string true "List of parameter keys"
// @Security BearerAuth
// @Success 200 {object} map[string]entity.EnvParam
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /env-params/{environment}/batch [post]
func (c *EnvParamController) GetEnvParams(ctx *gin.Context) {
	environment := ctx.Param("environment")

	var keys []string
	if err := ctx.ShouldBindJSON(&keys); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid keys format"})
		return
	}

	if environment == "" || len(keys) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Environment and keys are required"})
		return
	}

	params, err := c.envParamService.GetEnvParams(ctx.Request.Context(), keys, environment)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, params)
}

// CreateEnvParam godoc
// @Summary Create environment parameter
// @Description Creates a new environment parameter
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Param param body entity.EnvParam true "Environment parameter to create"
// @Security BearerAuth
// @Success 201 {object} entity.EnvParam
// @Failure 400 {object} gin.H
// @Failure 409 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /env-params [post]
func (c *EnvParamController) CreateEnvParam(ctx *gin.Context) {
	var param entity.EnvParam
	if err := ctx.ShouldBindJSON(&param); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set created by from JWT claims (implement as needed)
	// param.CreatedBy = getUserFromContext(ctx)

	if err := c.envParamService.CreateEnvParam(ctx.Request.Context(), &param); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			ctx.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		return
	}

	ctx.JSON(http.StatusCreated, param)
}

// UpdateEnvParam godoc
// @Summary Update environment parameter
// @Description Updates an environment parameter's value
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Param environment path string true "Environment name"
// @Param key path string true "Parameter key"
// @Param request body dto.UpdateEnvParamRequest true "Update request"
// @Security BearerAuth
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /env-params/{environment}/{key} [put]
func (c *EnvParamController) UpdateEnvParam(ctx *gin.Context) {
	environment := ctx.Param("environment")
	key := ctx.Param("key")

	var request dto.UpdateEnvParamRequest
	if err := ctx.ShouldBindJSON(&request); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if environment == "" || key == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Environment and key are required"})
		return
	}

	if err := c.envParamService.UpdateEnvParam(ctx.Request.Context(), key, environment, request.Value); err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Environment parameter updated successfully"})
}

// DeleteEnvParam godoc
// @Summary Delete environment parameter
// @Description Deletes an environment parameter
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Param environment path string true "Environment name"
// @Param key path string true "Parameter key"
// @Security BearerAuth
// @Success 200 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 404 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /env-params/{environment}/{key} [delete]
func (c *EnvParamController) DeleteEnvParam(ctx *gin.Context) {
	environment := ctx.Param("environment")
	key := ctx.Param("key")

	if environment == "" || key == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Environment and key are required"})
		return
	}

	if err := c.envParamService.DeleteEnvParam(ctx.Request.Context(), key, environment); err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		} else {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Environment parameter deleted successfully"})
}

// ListEnvParams godoc
// @Summary List environment parameters
// @Description Lists environment parameters for a specific environment with pagination
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Param environment path string true "Environment name"
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(20)
// @Security BearerAuth
// @Success 200 {object} dto.PaginatedEnvParamsResponse
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /env-params/{environment} [get]
func (c *EnvParamController) ListEnvParams(ctx *gin.Context) {
	environment := ctx.Param("environment")

	if environment == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Environment is required"})
		return
	}

	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("pageSize", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	params, err := c.envParamService.ListEnvParams(ctx.Request.Context(), environment, pageSize, offset)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total, err := c.envParamService.CountEnvParams(ctx.Request.Context(), environment)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := dto.PaginatedEnvParamsResponse{
		Data:     params,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		HasNext:  offset+pageSize < total,
		HasPrev:  page > 1,
	}

	ctx.JSON(http.StatusOK, response)
}

// ListAllEnvParams godoc
// @Summary List all environment parameters
// @Description Lists all environment parameters across all environments with pagination
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param pageSize query int false "Page size" default(20)
// @Security BearerAuth
// @Success 200 {object} dto.PaginatedEnvParamsResponse
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /env-params [get]
func (c *EnvParamController) ListAllEnvParams(ctx *gin.Context) {
	page, _ := strconv.Atoi(ctx.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(ctx.DefaultQuery("pageSize", "20"))

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	params, err := c.envParamService.ListAllEnvParams(ctx.Request.Context(), pageSize, offset)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	total, err := c.envParamService.CountAllEnvParams(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	response := dto.PaginatedEnvParamsResponse{
		Data:     params,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		HasNext:  offset+pageSize < total,
		HasPrev:  page > 1,
	}

	ctx.JSON(http.StatusOK, response)
}

// GetEnvironments godoc
// @Summary Get environments
// @Description Returns all environments that have parameters
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} []string
// @Failure 500 {object} gin.H
// @Router /env-params/environments [get]
func (c *EnvParamController) GetEnvironments(ctx *gin.Context) {
	environments, err := c.envParamService.GetEnvironments(ctx.Request.Context())
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, environments)
}

// BulkCreateEnvParams godoc
// @Summary Bulk create environment parameters
// @Description Creates multiple environment parameters at once
// @Tags environment-parameters
// @Accept json
// @Produce json
// @Param params body []entity.EnvParam true "List of environment parameters to create"
// @Security BearerAuth
// @Success 201 {object} gin.H
// @Failure 400 {object} gin.H
// @Failure 500 {object} gin.H
// @Router /env-params/bulk [post]
func (c *EnvParamController) BulkCreateEnvParams(ctx *gin.Context) {
	var params []*entity.EnvParam
	if err := ctx.ShouldBindJSON(&params); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(params) == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "No parameters provided"})
		return
	}

	if err := c.envParamService.BulkCreateEnvParams(ctx.Request.Context(), params); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"message": "Environment parameters created successfully", "count": len(params)})
}
