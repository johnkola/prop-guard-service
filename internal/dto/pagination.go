package dto

// PaginatedResponse represents a paginated API response
type PaginatedResponse[T any] struct {
	Data       []T  `json:"data"`
	Total      int  `json:"total"`
	Page       int  `json:"page"`
	PageSize   int  `json:"pageSize"`
	TotalPages int  `json:"totalPages"`
	HasNext    bool `json:"hasNext"`
	HasPrev    bool `json:"hasPrev"`
}

// NewPaginatedResponse creates a new paginated response
func NewPaginatedResponse[T any](data []T, total, page, pageSize int) *PaginatedResponse[T] {
	totalPages := (total + pageSize - 1) / pageSize // Ceiling division
	if totalPages == 0 {
		totalPages = 1
	}

	return &PaginatedResponse[T]{
		Data:       data,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}
}

// PaginatedSecretsResponse represents paginated secrets
type PaginatedSecretsResponse struct {
	Secrets    []*SecretResponse `json:"secrets"`
	Total      int               `json:"total"`
	Page       int               `json:"page"`
	PageSize   int               `json:"pageSize"`
	TotalPages int               `json:"totalPages"`
	HasNext    bool              `json:"hasNext"`
	HasPrev    bool              `json:"hasPrev"`
}

// PaginatedUsersResponse represents paginated users
type PaginatedUsersResponse struct {
	Users      []*UserResponse `json:"users"`
	Total      int             `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"pageSize"`
	TotalPages int             `json:"totalPages"`
	HasNext    bool            `json:"hasNext"`
	HasPrev    bool            `json:"hasPrev"`
}

// PaginatedRolesResponse represents paginated roles
type PaginatedRolesResponse struct {
	Roles      interface{} `json:"roles"` // Using interface{} to match existing role structure
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"pageSize"`
	TotalPages int         `json:"totalPages"`
	HasNext    bool        `json:"hasNext"`
	HasPrev    bool        `json:"hasPrev"`
}

// PaginatedAuditLogsResponse represents paginated audit logs
type PaginatedAuditLogsResponse struct {
	Logs       interface{} `json:"logs"` // Using interface{} to match existing audit structure
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"pageSize"`
	TotalPages int         `json:"totalPages"`
	HasNext    bool        `json:"hasNext"`
	HasPrev    bool        `json:"hasPrev"`
}
