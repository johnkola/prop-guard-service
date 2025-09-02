package dto

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	Token     string   `json:"token"`
	Username  string   `json:"username"`
	Roles     []string `json:"roles"`
	ExpiresIn int64    `json:"expiresIn"`
}
