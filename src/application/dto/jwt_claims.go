package dto

import "time"

type AccessTokenClaims struct {
	// Standard Registered Claims
	Issuer    string    // iss
	Subject   string    // sub
	Audience  []string  // aud
	ExpiresAt time.Time // exp
	NotBefore time.Time // nbf
	IssuedAt  time.Time // iat
	JTI       string    // jti
	UserID    string    // maps to sub (optional duplicate for clarity)
	Type      string    // typ: access / refresh
	Roles     []string  // roles (only for access tokens)
}

type RefreshTokenClaims struct {
	Issuer    string    // iss
	Subject   string    // sub
	Audience  []string  // aud
	ExpiresAt time.Time // exp
	NotBefore time.Time // nbf
	IssuedAt  time.Time // iat
	JTI       string    // jti
	UserID    string    // maps to sub (optional duplicate for clarity)
	Type      string    // typ: access / refresh
}
