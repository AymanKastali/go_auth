package application

var (
	ZeroLoginResponse = LoginResponse{}
)

// RegisterUserCommand
type RegisterUserCommand struct {
	Email    string
	Password string
}

// LoginCommand
type LoginCommand struct {
	Email       string
	Password    string
	Fingerprint string
	UserAgent   string
	IPAddress   string
}

// RefreshTokenCommand
type RefreshTokenCommand struct {
	UserID       string
	RefreshToken string
	Fingerprint  string
}

// LogoutCommand
type LogoutCommand struct {
	UserID    string
	SessionID string
}

// ValidateAccessQuery
type ValidateAccessQuery struct {
	AccessToken string
	Fingerprint string // Optional: check if you embed FP in the JWT
}

type ValidateAccessResponse struct {
	UserID    string
	SessionID string
	Roles     []string
}

// LoginResponse (The Dual-Token DTO)
type LoginResponse struct {
	AccessToken      string
	AccessExpiredAt  string
	RefreshToken     string
	RefreshExpiresAt string
}
