package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ZeroUserID         = UserID{}
	ZeroEmail          = Email{}
	ZeroHashedPassword = HashedPassword{}
	ZeroRawPassword    = RawPassword{}
	ZeroTimepoint      = Timepoint{}
	ZeroSessionID      = SessionID{}
	ZeroHashedToken    = HashedToken{}
	ZeroRawToken       = RawToken{}
	ZeroAccessToken    = AccessToken{}
	ZeroAccessIdentity = AccessIdentity{}
	ZeroRole           = Role{}
)
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// UserID
type UserID struct{ value string }

func NewUserID(value string) (UserID, error) {
	if value == "" {
		return ZeroUserID, NewRequiredAttributeError("UserID", "value")
	}
	return UserID{value: value}, nil
}
func ReconstituteUserID(value string) UserID { return UserID{value: value} }

func (vo UserID) String() string          { return vo.value }
func (vo UserID) IsEmpty() bool           { return vo.value == "" }
func (vo UserID) Equal(other UserID) bool { return vo.value == other.value }

// Email
type Email struct{ value string }

func NewEmail(value string) (Email, error) {
	if value == "" {
		return ZeroEmail, NewRequiredAttributeError("Email", "value")
	}

	if !emailRegex.MatchString(value) {
		return ZeroEmail, NewInvalidAttributeError("Email", "value")
	}

	return Email{value: value}, nil
}

func ReconstituteEmail(email string) Email { return Email{value: email} }

func (vo Email) String() string         { return vo.value }
func (vo Email) IsEmpty() bool          { return vo.value == "" }
func (vo Email) Equal(other Email) bool { return vo.value == other.value }

// Hashed Password
type HashedPassword struct{ value string }

func NewHashedPassword(value string) (HashedPassword, error) {
	if value == "" {
		return ZeroHashedPassword, NewRequiredAttributeError("HashedPassword", "value")
	}
	return HashedPassword{value: value}, nil
}

func ReconstituteHashedPassword(value string) HashedPassword { return HashedPassword{value: value} }

func (vo HashedPassword) String() string                  { return vo.value }
func (vo HashedPassword) IsEmpty() bool                   { return vo.value == "" }
func (vo HashedPassword) Equal(other HashedPassword) bool { return vo.value == other.value }

// RawPassword
type RawPassword struct{ value string }

func NewRawPassword(value string) (RawPassword, error) {
	if value == "" {
		return ZeroRawPassword, NewRequiredAttributeError("RawPassword", "value")
	}
	return RawPassword{value: value}, nil
}

func (vo RawPassword) String() string               { return vo.value }
func (vo RawPassword) IsEmpty() bool                { return vo.value == "" }
func (vo RawPassword) Equal(other RawPassword) bool { return vo.value == other.value }

// Timepoint
type Timepoint struct{ time time.Time }

func NewTimepoint(time time.Time) Timepoint          { return Timepoint{time: time.UTC()} }
func ReconstituteTimepoint(time time.Time) Timepoint { return Timepoint{time: time.UTC()} }

func (vo Timepoint) Time() time.Time               { return vo.time }
func (vo Timepoint) IsBefore(other Timepoint) bool { return vo.time.Before(other.time) }
func (vo Timepoint) IsAfter(other Timepoint) bool  { return vo.time.After(other.time) }
func (vo Timepoint) IsFuture(other Timepoint) bool { return vo.time.After(other.time) }
func (vo Timepoint) Add(d time.Duration) Timepoint { return Timepoint{time: vo.time.Add(d)} }
func (vo Timepoint) Equal(other Timepoint) bool    { return vo.time.Equal(other.time) }
func (vo Timepoint) String() string                { return vo.time.Format(time.RFC3339) }
func (vo Timepoint) IsZero() bool                  { return vo.time.IsZero() }
func (vo Timepoint) Unix() int64                   { return vo.time.Unix() }

// SessionID
type SessionID struct{ value string }

func NewSessionID(value string) (SessionID, error) {
	if value == "" {
		return ZeroSessionID, NewRequiredAttributeError("SessionID", "value")
	}
	return SessionID{value: value}, nil
}
func ReconstituteSessionID(value string) SessionID { return SessionID{value: value} }

func (vo SessionID) String() string             { return vo.value }
func (vo SessionID) IsEmpty() bool              { return vo.value == "" }
func (vo SessionID) Equal(other SessionID) bool { return vo.value == other.value }

// HashedToken
type HashedToken struct{ value string }

func NewHashedToken(value string) (HashedToken, error) {
	if value == "" {
		return ZeroHashedToken, NewRequiredAttributeError("HashedToken", "value")
	}
	return HashedToken{value: value}, nil
}
func (vo HashedToken) String() string               { return vo.value }
func (vo HashedToken) IsEmpty() bool                { return vo.value == "" }
func (vo HashedToken) Equal(other HashedToken) bool { return vo.value == other.value }

// RawToken
type RawToken struct{ value string }

func NewRawToken(value string) (RawToken, error) {
	if value == "" {
		return ZeroRawToken, NewRequiredAttributeError("RawToken", "value")
	}
	return RawToken{value: value}, nil
}

func (vo RawToken) String() string            { return vo.value }
func (vo RawToken) IsEmpty() bool             { return vo.value == "" }
func (vo RawToken) Equal(other RawToken) bool { return vo.value == other.value }

// AccessToken
type AccessToken struct{ value string }

func NewAccessToken(value string) (AccessToken, error) {
	if value == "" {
		return ZeroAccessToken, NewRequiredAttributeError("AccessToken", "value")
	}
	return AccessToken{value: value}, nil
}
func (vo AccessToken) String() string { return vo.value }

// AccessIdentity is the result of a successful token validation.
// It contains only the data the domain actually needs.
type AccessIdentity struct {
	userID    UserID
	sessionID SessionID
	email     Email
	roles     []Role
}

func NewAccessIdentity(userID UserID, sessionID SessionID, email Email, roles []Role) (AccessIdentity, error) {
	if userID.IsEmpty() {
		return ZeroAccessIdentity, NewRequiredAttributeError("AccessIdentity", "userID")
	}
	if sessionID.IsEmpty() {
		return ZeroAccessIdentity, NewRequiredAttributeError("AccessIdentity", "sessionID")
	}
	if email.IsEmpty() {
		return ZeroAccessIdentity, NewRequiredAttributeError("AccessIdentity", "email")
	}
	if len(roles) == 0 {
		return ZeroAccessIdentity, NewRequiredAttributeError("AccessIdentity", "roles")
	}
	return AccessIdentity{
		userID: userID,
		email:  email,
		roles:  roles,
	}, nil
}

// Getter methods (since fields are private)
func (vo AccessIdentity) UserID() UserID       { return vo.userID }
func (vo AccessIdentity) SessionID() SessionID { return vo.sessionID }
func (vo AccessIdentity) Email() Email         { return vo.email }
func (vo AccessIdentity) Roles() []Role        { return vo.roles }

// Role
type Role struct {
	name string
}

var (
	// Administrative Roles
	RoleSuperAdmin = Role{name: "super_admin"} // System-wide control
	RoleAdmin      = Role{name: "admin"}       // Organization/Department control
	// Staff/Internal Roles
	RoleEditor    = Role{name: "editor"}    // Content management
	RoleModerator = Role{name: "moderator"} // Community/Support management
	// Standard User Roles
	RoleMember  = Role{name: "member"}  // Standard authenticated user
	RolePremium = Role{name: "premium"} // Paid/Upgraded user
	// External/Limited Roles
	RoleGuest   = Role{name: "guest"}   // Read-only/Limited access
	RolePartner = Role{name: "partner"} // Third-party API/Integration access
)

var nameToRole = map[string]Role{
	RoleSuperAdmin.name: RoleSuperAdmin,
	RoleAdmin.name:      RoleAdmin,
	RoleEditor.name:     RoleEditor,
	RoleModerator.name:  RoleModerator,
	RoleMember.name:     RoleMember,
	RolePremium.name:    RolePremium,
	RoleGuest.name:      RoleGuest,
	RolePartner.name:    RolePartner,
}

func NewRole(name string) (Role, error) {
	canonicalName := strings.ToLower(strings.TrimSpace(name))
	role, exists := nameToRole[canonicalName]
	if !exists {
		return ZeroRole, NewInvalidRoleError(name)
	}
	return role, nil
}
func (r Role) Name() string          { return r.name }
func (r Role) Equal(other Role) bool { return r.name == other.name }

// DeviceIdentity
type DeviceIdentity struct {
	ipAddress string
	os        string
	browser   string
	model     string
	isMobile  bool
	language  string
	userAgent string
}

func NewDeviceIdentity(
	ip, os, browser, model, lang, ua string,
	isMobile bool,
) (DeviceIdentity, error) {
	if ip == "" {
		return DeviceIdentity{}, NewRequiredAttributeError("DeviceIdentity", "ipAddress")
	}
	if ua == "" {
		return DeviceIdentity{}, NewRequiredAttributeError("DeviceIdentity", "userAgent")
	}

	return DeviceIdentity{
		ipAddress: ip,
		os:        os,
		browser:   browser,
		model:     model,
		isMobile:  isMobile,
		language:  lang,
		userAgent: ua,
	}, nil
}

func ReconstituteDeviceIdentity(
	ip, os, browser, model, lang, ua string,
	isMobile bool,
) DeviceIdentity {
	return DeviceIdentity{
		ipAddress: ip,
		os:        os,
		browser:   browser,
		model:     model,
		isMobile:  isMobile,
		language:  lang,
		userAgent: ua,
	}
}

func (d DeviceIdentity) Fingerprint() DeviceFingerprint {
	return NewDeviceFingerprintFromIdentity(d.userAgent, d.ipAddress, d.language)
}

func (d DeviceIdentity) DisplayName() string {
	if d.isMobile && d.model != "" && d.model != "Generic" {
		return fmt.Sprintf("%s (%s)", d.model, d.browser)
	}

	return fmt.Sprintf("%s on %s", d.browser, d.os)
}

func (d DeviceIdentity) IsSameDevice(other DeviceIdentity) bool {
	return d.Fingerprint() == other.Fingerprint()
}

func (d DeviceIdentity) IPAddress() string { return d.ipAddress }
func (d DeviceIdentity) OS() string        { return d.os }
func (d DeviceIdentity) Browser() string   { return d.browser }
func (d DeviceIdentity) Model() string     { return d.model }
func (d DeviceIdentity) IsMobile() bool    { return d.isMobile }
func (d DeviceIdentity) Language() string  { return d.language }
func (d DeviceIdentity) UserAgent() string { return d.userAgent }

// DeviceFingerprint
type DeviceFingerprint struct{ value string }

func NewDeviceFingerprintFromIdentity(ua, ip, lang string) DeviceFingerprint {
	val := fmt.Sprintf("%s|%s|%s", ua, ip, lang)
	return DeviceFingerprint{value: val}
}

func NewDeviceFingerprint(value string) (DeviceFingerprint, error) {
	if value == "" {
		return DeviceFingerprint{}, NewRequiredAttributeError("DeviceFingerprint", "value")
	}
	return DeviceFingerprint{value: value}, nil
}

func ReconstituteDeviceFingerprint(value string) DeviceFingerprint {
	return DeviceFingerprint{value: value}
}

func (vo DeviceFingerprint) String() string                     { return vo.value }
func (vo DeviceFingerprint) Equal(other DeviceFingerprint) bool { return vo.value == other.value }
