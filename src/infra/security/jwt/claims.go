package jwt

import "github.com/golang-jwt/jwt/v5"

type AccessTokenClaims struct {
	Type  string   `json:"typ"`
	Roles []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	Type string `json:"typ"`
	jwt.RegisteredClaims
}
