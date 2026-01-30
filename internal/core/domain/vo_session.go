package domain

var (
	ZeroSessionID      = SessionID{}
	ZeroHashedToken    = HashedToken{}
	ZeroRawToken       = RawToken{}
	ZeroAccessToken    = AccessToken{}
	ZeroAccessIdentity = AccessIdentity{}
)

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

// --- RawToken ---
type RawToken struct{ value string }

func NewRawToken(value string) (RawToken, error) {
	if value == "" {
		return ZeroRawToken, ErrTokenInvalid
	}
	return RawToken{value: value}, nil
}
func (vo RawToken) String() string { return vo.value }
func (vo RawToken) IsEmpty() bool  { return vo.value == "" }

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
	userID    UserID
	sessionID SessionID
	email     Email
	roles     []Role
}

func NewAccessIdentity(userID UserID, sessionID SessionID, email Email, roles []Role) (AccessIdentity, error) {
	if userID.IsEmpty() || sessionID.IsEmpty() || email.IsEmpty() || len(roles) == 0 {
		return ZeroAccessIdentity, ErrAccessIdentityIncomplete
	}
	return AccessIdentity{
		userID:    userID,
		sessionID: sessionID,
		email:     email,
		roles:     roles,
	}, nil
}

func (vo AccessIdentity) UserID() UserID       { return vo.userID }
func (vo AccessIdentity) SessionID() SessionID { return vo.sessionID }
func (vo AccessIdentity) Email() Email         { return vo.email }
func (vo AccessIdentity) Roles() []Role        { return vo.roles }
