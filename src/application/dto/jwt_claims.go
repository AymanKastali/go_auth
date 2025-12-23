package dto

import "time"

type AccessTokenClaimsDto struct {
	// Standard Registered Claims
	Issuer    string    // iss
	Subject   string    // sub
	Audience  []string  // aud
	ExpiresAt time.Time // exp
	NotBefore time.Time // nbf
	IssuedAt  time.Time // iat
	JTI       string    // jti
	Type      string    // typ: access / refresh
	Roles     []string  // roles (only for access tokens)
}

type RefreshTokenClaimsDto struct {
	Issuer    string    // iss
	Subject   string    // sub
	Audience  []string  // aud
	ExpiresAt time.Time // exp
	NotBefore time.Time // nbf
	IssuedAt  time.Time // iat
	JTI       string    // jti
	Type      string    // typ: access / refresh
}
