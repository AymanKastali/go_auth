package jwt

import "github.com/golang-jwt/jwt/v5"

type AccessTokenClaims struct {
	UserID         string  `json:"sub"`
	OrganizationID *string `json:"org_id"`
	Type           string  `json:"typ"`
	// Roles  []string `json:"roles"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"sub"`
	Type   string `json:"typ"`
	jwt.RegisteredClaims
}
