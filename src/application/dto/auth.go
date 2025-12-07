package dto

import (
	"time"
)

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Device   string `json:"device,omitempty"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	Device       string `json:"device,omitempty"`
}
