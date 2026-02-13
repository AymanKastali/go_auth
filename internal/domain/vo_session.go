package domain

import "time"

var (
	ZeroSessionID      = SessionID{}
	ZeroHashedToken    = HashedToken{}
	ZeroAccessToken    = AccessToken{}
	ZeroAccessIdentity = AccessIdentity{}
	ZeroSessionExpiry  = SessionExpiry{}
)

// --- SessionExpiry ---
type SessionExpiry struct{ value time.Time }

func NewSessionExpiry(expiresAt, now time.Time) (SessionExpiry, error) {
	if !expiresAt.After(now) {
		return ZeroSessionExpiry, ErrSessionExpiryInvalid
	}
	return SessionExpiry{value: expiresAt}, nil
}
func ReconstituteSessionExpiry(t time.Time) SessionExpiry { return SessionExpiry{value: t} }

func (e SessionExpiry) Time() time.Time            { return e.value }
func (e SessionExpiry) IsZero() bool               { return e.value.IsZero() }
func (e SessionExpiry) IsExpired(now time.Time) bool { return !e.value.After(now) }

// --- SessionID ---
type SessionID struct{ value string }

func NewSessionID(value string) (SessionID, error) {
	if value == "" {
		return ZeroSessionID, ErrSessionIDRequired
	}
	return SessionID{value: value}, nil
}
func ReconstituteSessionID(value string) SessionID { return SessionID{value: value} }
func (vo SessionID) String() string                { return vo.value }
func (vo SessionID) IsEmpty() bool                 { return vo.value == "" }
func (vo SessionID) Equal(other SessionID) bool    { return vo.value == other.value }

// --- HashedToken ---
type HashedToken struct{ value string }

func NewHashedToken(value string) (HashedToken, error) {
	if value == "" {
		return ZeroHashedToken, ErrTokenInvalid
	}
	return HashedToken{value: value}, nil
}
func ReconstituteHashedToken(value string) HashedToken { return HashedToken{value: value} }

func (vo HashedToken) String() string               { return vo.value }
func (vo HashedToken) IsEmpty() bool                { return vo.value == "" }
func (vo HashedToken) Equal(other HashedToken) bool { return vo.value == other.value }

// --- AccessToken ---
type AccessToken struct{ value string }

func NewAccessToken(value string) (AccessToken, error) {
	if value == "" {
		return ZeroAccessToken, ErrTokenInvalid
	}
	return AccessToken{value: value}, nil
}
func (vo AccessToken) String() string { return vo.value }

// --- AccessIdentity ---
type AccessIdentity struct {
	userID      UserID
	sessionID   SessionID
	email       Email
	roles       []RoleName
	permissions []Permission
}

func NewAccessIdentity(userID UserID, sessionID SessionID, email Email, roles []RoleName, permissions []Permission) (AccessIdentity, error) {
	if userID.IsEmpty() || sessionID.IsEmpty() || email.IsEmpty() || len(roles) == 0 {
		return ZeroAccessIdentity, ErrAccessIdentityIncomplete
	}
	return AccessIdentity{
		userID:      userID,
		sessionID:   sessionID,
		email:       email,
		roles:       roles,
		permissions: permissions,
	}, nil
}

func (vo AccessIdentity) UserID() UserID           { return vo.userID }
func (vo AccessIdentity) SessionID() SessionID     { return vo.sessionID }
func (vo AccessIdentity) Email() Email             { return vo.email }
func (vo AccessIdentity) Roles() []RoleName        { return vo.roles }
func (vo AccessIdentity) Permissions() []Permission { return vo.permissions }
