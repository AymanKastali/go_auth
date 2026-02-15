package domain

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------
// Shared time constants
// ---------------------------------------------------------------

var (
	testNow       = time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	testPast      = time.Date(2025, 6, 14, 12, 0, 0, 0, time.UTC)
	testFuture    = time.Date(2025, 6, 16, 12, 0, 0, 0, time.UTC)
	testFarFuture = time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
)

// ---------------------------------------------------------------
// VO factories
// ---------------------------------------------------------------

func validUserID() UserID       { return ReconstituteUserID("user-001") }
func validEmail() Email         { return ReconstituteEmail("test@example.com") }
func validHashedPassword() HashedPassword {
	return ReconstituteHashedPassword("$2a$10$hashedvalue")
}
func validSessionID() SessionID   { return ReconstituteSessionID("sess-001") }
func validHashedToken() HashedToken { return ReconstituteHashedToken("hashed-tok-001") }
func validRawToken() string         { return "raw-tok-001" }
func validDeviceIdentity() DeviceIdentity {
	return ReconstituteDeviceIdentity("192.168.1.1", "Linux", "Chrome", "Desktop", "en-US", "Mozilla/5.0", false)
}
func differentDeviceIdentity() DeviceIdentity {
	return ReconstituteDeviceIdentity("10.0.0.1", "Windows", "Firefox", "Laptop", "fr-FR", "Mozilla/6.0", false)
}

// ---------------------------------------------------------------
// Aggregate builders
// ---------------------------------------------------------------

func newActiveUser() *User {
	return ReconstituteUser(
		validUserID(),
		validEmail(),
		validHashedPassword(),
		true,
		[]RoleName{ReconstituteRoleName("member")},
		false,
		testNow,
		0,
		nil,
	)
}

func newActiveSession() *Session {
	return ReconstituteSession(
		validSessionID(),
		validUserID(),
		validHashedToken(),
		ZeroHashedToken,
		validDeviceIdentity(),
		testFuture,
		testNow,
		false,
	)
}

func newDeletedUser() *User {
	return ReconstituteUser(
		validUserID(),
		validEmail(),
		validHashedPassword(),
		true,
		[]RoleName{ReconstituteRoleName("member")},
		true,
		testNow,
		0,
		nil,
	)
}

func newInactiveUser() *User {
	return ReconstituteUser(
		validUserID(),
		validEmail(),
		validHashedPassword(),
		false,
		nil,
		false,
		testNow,
		0,
		nil,
	)
}

// ---------------------------------------------------------------
// Event helpers
// ---------------------------------------------------------------

func assertEventRecorded(t *testing.T, events []DomainEvent, name string) {
	t.Helper()
	for _, e := range events {
		if e.EventName() == name {
			return
		}
	}
	t.Errorf("expected event %q to be recorded, but it was not; got %v", name, eventNames(events))
}

func assertEventNotRecorded(t *testing.T, events []DomainEvent, name string) {
	t.Helper()
	for _, e := range events {
		if e.EventName() == name {
			t.Errorf("expected event %q NOT to be recorded, but it was", name)
			return
		}
	}
}

func assertEventCount(t *testing.T, events []DomainEvent, expected int) {
	t.Helper()
	if len(events) != expected {
		t.Errorf("expected %d events, got %d: %v", expected, len(events), eventNames(events))
	}
}

func eventNames(events []DomainEvent) []string {
	names := make([]string, len(events))
	for i, e := range events {
		names[i] = e.EventName()
	}
	return names
}

// ---------------------------------------------------------------
// Port stubs
// ---------------------------------------------------------------

type stubPasswordService struct {
	hashResult HashedPassword
	hashErr    error
	compareOut bool
}

func (s *stubPasswordService) Hash(_ ValidatedPassword) (HashedPassword, error) {
	return s.hashResult, s.hashErr
}
func (s *stubPasswordService) Compare(_ string, _ HashedPassword) bool {
	return s.compareOut
}

type stubIDGenerator struct {
	userID        UserID
	userIDErr     error
	sessionID     SessionID
	sessionIDErr  error
	recoveryID    RecoveryTokenID
	recoveryIDErr error
	roleID        RoleID
	roleIDErr     error
}

func (s *stubIDGenerator) GenerateUserID() (UserID, error) {
	return s.userID, s.userIDErr
}
func (s *stubIDGenerator) GenerateSessionID() (SessionID, error) {
	return s.sessionID, s.sessionIDErr
}
func (s *stubIDGenerator) GenerateRecoveryTokenID() (RecoveryTokenID, error) {
	return s.recoveryID, s.recoveryIDErr
}
func (s *stubIDGenerator) GenerateActivationTokenID() (ActivationTokenID, error) {
	return ReconstituteActivationTokenID("act-001"), nil
}
func (s *stubIDGenerator) GenerateRoleID() (RoleID, error) {
	return s.roleID, s.roleIDErr
}

type stubTokenService struct {
	generateToken     string
	generateErr       error
	hashSessionOut    HashedToken
	hashSessionErr    error
	hashRecoveryOut   RecoveryTokenHash
	hashRecoveryErr   error
	compareSessionOut bool
	compareRecOut     bool
}

func (s *stubTokenService) Generate() (string, error) {
	return s.generateToken, s.generateErr
}
func (s *stubTokenService) HashSessionToken(_ string) (HashedToken, error) {
	return s.hashSessionOut, s.hashSessionErr
}
func (s *stubTokenService) HashRecoveryToken(_ string) (RecoveryTokenHash, error) {
	return s.hashRecoveryOut, s.hashRecoveryErr
}
func (s *stubTokenService) CompareSession(_ string, _ HashedToken) bool {
	return s.compareSessionOut
}
func (s *stubTokenService) CompareRecovery(_ string, _ RecoveryTokenHash) bool {
	return s.compareRecOut
}
func (s *stubTokenService) HashActivationToken(_ string) (ActivationTokenHash, error) {
	return ReconstituteActivationTokenHash("hashed-activation"), nil
}
func (s *stubTokenService) CompareActivation(_ string, _ ActivationTokenHash) bool {
	return false
}

type stubAccessService struct {
	issueToken   AccessToken
	issueExpiry  time.Time
	issueErr     error
	validateID   AccessIdentity
	validateErr  error
}

func (s *stubAccessService) Issue(_ UserID, _ Email, _ SessionID, _ []RoleName, _ []Permission, _ time.Time, _ time.Time, _ time.Time) (AccessToken, time.Time, error) {
	return s.issueToken, s.issueExpiry, s.issueErr
}
func (s *stubAccessService) Validate(_ AccessToken) (AccessIdentity, error) {
	return s.validateID, s.validateErr
}

type stubRegisterPolicy struct {
	err error
}

func (p *stubRegisterPolicy) Validate(_ Email) error { return p.err }

type stubSessionPolicy struct {
	lifetime   time.Duration
	maxActive  int
}

func (p *stubSessionPolicy) GetSessionLifetime() time.Duration { return p.lifetime }
func (p *stubSessionPolicy) GetMaxActiveSessions() int         { return p.maxActive }

type stubRecoveryPolicy struct {
	lifetime time.Duration
}

func (p *stubRecoveryPolicy) GetRecoveryTokenLifetime() time.Duration { return p.lifetime }

type stubActivationPolicy struct {
	requireEmail  bool
	tokenLifetime time.Duration
}

func (p *stubActivationPolicy) RequiresEmailActivation() bool       { return p.requireEmail }
func (p *stubActivationPolicy) GetActivationTokenLifetime() time.Duration { return p.tokenLifetime }
