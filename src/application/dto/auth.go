package dto

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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
