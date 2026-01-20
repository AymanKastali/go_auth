package dto

import "time"

type IssueSessionToken struct {
	TokenID   string
	UserID    string
	DeviceID  string
	Roles     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type IssuedSessionToken struct {
	Raw string
}

type SessionTokenMetadata struct {
	TokenID   string
	UserID    string
	DeviceID  string
	Roles     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type IssueRenewalToken struct {
	TokenID   string
	UserID    string
	DeviceID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type IssuedRenewalToken struct {
	Raw       string
	TokenID   string
	UserID    string
	DeviceID  string
	ExpiresAt time.Time
}
