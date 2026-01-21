package dto

import "time"

type SessionTokenMetadata struct {
	TokenID   string
	SessionID string
	UserID    string
	DeviceID  string
	Roles     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type IssuedSessionToken struct {
	Raw string
}
