package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ZeroUserID            = UserID{}
	ZeroEmail             = Email{}
	ZeroHashedPassword    = HashedPassword{}
	ZeroRawPassword       = RawPassword{}
	ZeroTimepoint         = Timepoint{}
	ZeroSessionID         = SessionID{}
	ZeroHashedToken       = HashedToken{}
	ZeroRawToken          = RawToken{}
	ZeroAccessToken       = AccessToken{}
	ZeroAccessIdentity    = AccessIdentity{}
	ZeroRole              = Role{}
	ZeroDeviceIdentity    = DeviceIdentity{}
	ZeroDeviceFingerprint = DeviceFingerprint{}
	ZeroRecoveryTokenRaw  = RecoveryTokenRaw{}
	ZeroRecoveryTokenID   = RecoveryTokenID{}
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// --- UserID ---
type UserID struct{ value string }

func NewUserID(value string) (UserID, error) {
	if value == "" {
		return ZeroUserID, ErrUserIDRequired
	}
	return UserID{value: value}, nil
}
func ReconstituteUserID(value string) UserID { return UserID{value: value} }
func (vo UserID) String() string             { return vo.value }
func (vo UserID) IsEmpty() bool              { return vo.value == "" }
func (vo UserID) Equal(other UserID) bool    { return vo.value == other.value }

// --- Email ---
type Email struct{ value string }

func NewEmail(value string) (Email, error) {
	if value == "" {
		return ZeroEmail, ErrUserEmailRequired
	}
	if !emailRegex.MatchString(value) {
		return ZeroEmail, ErrUserEmailInvalid
	}
	return Email{value: value}, nil
}
func ReconstituteEmail(email string) Email { return Email{value: email} }
func (vo Email) String() string            { return vo.value }
func (vo Email) IsEmpty() bool             { return vo.value == "" }
func (vo Email) Equal(other Email) bool    { return vo.value == other.value }

// --- HashedPassword ---
type HashedPassword struct{ value string }

func NewHashedPassword(value string) (HashedPassword, error) {
	if value == "" {
		return ZeroHashedPassword, ErrUserPasswordRequired
	}
	return HashedPassword{value: value}, nil
}
func ReconstituteHashedPassword(value string) HashedPassword { return HashedPassword{value: value} }
func (vo HashedPassword) String() string                     { return vo.value }
func (vo HashedPassword) IsEmpty() bool                      { return vo.value == "" }

// --- RawPassword ---
type RawPassword struct{ value string }

func NewRawPassword(value string) (RawPassword, error) {
	if value == "" {
		return ZeroRawPassword, ErrUserPasswordRequired
	}
	return RawPassword{value: value}, nil
}
func (vo RawPassword) String() string { return vo.value }
func (vo RawPassword) IsEmpty() bool  { return vo.value == "" }

// --- Timepoint ---
type Timepoint struct{ time time.Time }

func NewTimepoint(t time.Time) Timepoint           { return Timepoint{time: t.UTC()} }
func ReconstituteTimepoint(t time.Time) Timepoint  { return Timepoint{time: t.UTC()} }
func (vo Timepoint) Time() time.Time               { return vo.time }
func (vo Timepoint) IsBefore(other Timepoint) bool { return vo.time.Before(other.time) }
func (vo Timepoint) IsAfter(other Timepoint) bool  { return vo.time.After(other.time) }
func (vo Timepoint) Add(d time.Duration) Timepoint { return Timepoint{time: vo.time.Add(d)} }
func (vo Timepoint) Equal(other Timepoint) bool    { return vo.time.Equal(other.time) }
func (vo Timepoint) String() string                { return vo.time.Format(time.RFC3339) }
func (vo Timepoint) IsZero() bool                  { return vo.time.IsZero() }

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

// --- Role ---
type Role struct{ name string }

var (
	RoleSuperAdmin = Role{name: "super_admin"}
	RoleAdmin      = Role{name: "admin"}
	RoleEditor     = Role{name: "editor"}
	RoleModerator  = Role{name: "moderator"}
	RoleMember     = Role{name: "member"}
	RolePremium    = Role{name: "premium"}
	RoleGuest      = Role{name: "guest"}
	RolePartner    = Role{name: "partner"}
)

var nameToRole = map[string]Role{
	"super_admin": RoleSuperAdmin,
	"admin":       RoleAdmin,
	"editor":      RoleEditor,
	"moderator":   RoleModerator,
	"member":      RoleMember,
	"premium":     RolePremium,
	"guest":       RoleGuest,
	"partner":     RolePartner,
}

func NewRole(name string) (Role, error) {
	canonicalName := strings.ToLower(strings.TrimSpace(name))
	role, exists := nameToRole[canonicalName]
	if !exists {
		return ZeroRole, ErrRoleNotRecognized
	}
	return role, nil
}
func ReconstituteRole(name string) Role {
	role, exists := nameToRole[name]
	if !exists {
		return Role{name: name}
	}
	return role
}
func (r Role) Name() string          { return r.name }
func (r Role) Equal(other Role) bool { return r.name == other.name }

// --- DeviceIdentity ---
type DeviceIdentity struct {
	ipAddress string
	os        string
	browser   string
	model     string
	language  string
	userAgent string
	isMobile  bool
}

func NewDeviceIdentity(ip, os, browser, model, lang, ua string, isMobile bool) (DeviceIdentity, error) {
	if ip == "" {
		return ZeroDeviceIdentity, ErrDeviceIPRequired
	}
	if ua == "" {
		return ZeroDeviceIdentity, ErrDeviceUARequired
	}
	return DeviceIdentity{
		ipAddress: ip,
		os:        os,
		browser:   browser,
		model:     model,
		language:  lang,
		userAgent: ua,
		isMobile:  isMobile,
	}, nil
}

func ReconstituteDeviceIdentity(ip, os, browser, model, lang, ua string, isMobile bool) DeviceIdentity {
	return DeviceIdentity{
		ipAddress: ip,
		os:        os,
		browser:   browser,
		model:     model,
		language:  lang,
		userAgent: ua,
		isMobile:  isMobile,
	}
}

func (d DeviceIdentity) Fingerprint() DeviceFingerprint {
	return NewDeviceFingerprintFromIdentity(d.userAgent, d.ipAddress, d.language)
}

func (d DeviceIdentity) DisplayName() string {
	// If it's a mobile device and we have a specific model name, use it.
	if d.isMobile && d.model != "" && d.model != "Generic" {
		return fmt.Sprintf("%s (%s)", d.model, d.browser)
	}

	// Default to the browser and OS (e.g., "Chrome on Windows")
	return fmt.Sprintf("%s on %s", d.browser, d.os)
}
func (d DeviceIdentity) IPAddress() string { return d.ipAddress }
func (d DeviceIdentity) OS() string        { return d.os }
func (d DeviceIdentity) Browser() string   { return d.browser }
func (d DeviceIdentity) Model() string     { return d.model }
func (d DeviceIdentity) Language() string  { return d.language }
func (d DeviceIdentity) UserAgent() string { return d.userAgent }
func (d DeviceIdentity) IsMobile() bool    { return d.isMobile }

// --- DeviceFingerprint ---
type DeviceFingerprint struct{ value string }

func NewDeviceFingerprintFromIdentity(ua, ip, lang string) DeviceFingerprint {
	val := fmt.Sprintf("%s|%s|%s", ua, ip, lang)
	return DeviceFingerprint{value: val}
}

func NewDeviceFingerprint(value string) (DeviceFingerprint, error) {
	if value == "" {
		return ZeroDeviceFingerprint, ErrDeviceFingerprintRequired
	}
	return DeviceFingerprint{value: value}, nil
}

func (vo DeviceFingerprint) String() string                     { return vo.value }
func (vo DeviceFingerprint) Equal(other DeviceFingerprint) bool { return vo.value == other.value }

// RecoveryTokenID is a unique identifier for the recovery record.
type RecoveryTokenID struct{ value string }

func NewRecoveryTokenID(v string) (RecoveryTokenID, error) {
	if v == "" {
		return RecoveryTokenID{}, ErrRecoveryTokenIDRequired
	}
	return RecoveryTokenID{value: v}, nil
}

func ReconstituteRecoveryTokenID(v string) RecoveryTokenID {
	return RecoveryTokenID{value: v}
}

func (vo RecoveryTokenID) String() string { return vo.value }

// RecoveryTokenHash represents the one-way hash of the token stored in the DB.
type RecoveryTokenHash struct{ value string }

func (vo RecoveryTokenHash) String() string { return vo.value }

func NewRecoveryTokenHash(v string) (RecoveryTokenHash, error) {
	if v == "" {
		return RecoveryTokenHash{}, ErrRecoveryTokenInvalid
	}
	return RecoveryTokenHash{value: v}, nil
}

func ReconstituteRecoveryTokenHash(v string) RecoveryTokenHash {
	return RecoveryTokenHash{value: v}
}

type RecoveryTokenRaw struct{ value string }

func NewRecoveryTokenRaw(v string) (RecoveryTokenRaw, error) {
	if v == "" {
		return ZeroRecoveryTokenRaw, ErrRecoveryTokenInvalid
	}
	return RecoveryTokenRaw{value: v}, nil
}

func (vo RecoveryTokenRaw) String() string { return vo.value }
