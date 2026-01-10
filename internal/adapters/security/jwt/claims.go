package jwt

import "github.com/golang-jwt/jwt/v5"

type AccessTokenClaims struct {
	Type     string   `json:"typ"`
	Roles    []string `json:"roles,omitempty"`
	DeviceID string   `json:"did"`
	jwt.RegisteredClaims
}

func (c AccessTokenClaims) GetType() string { return c.Type }

type RefreshTokenClaims struct {
	Type     string `json:"typ"`
	DeviceID string `json:"did"`
	jwt.RegisteredClaims
}

func (c RefreshTokenClaims) GetType() string { return c.Type }
