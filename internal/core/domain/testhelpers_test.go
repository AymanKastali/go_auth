package domain

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------
// Shared time constants
// ---------------------------------------------------------------

var (
	testNow       = NewTimepoint(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC))
	testPast      = NewTimepoint(time.Date(2025, 6, 14, 12, 0, 0, 0, time.UTC))
	testFuture    = NewTimepoint(time.Date(2025, 6, 16, 12, 0, 0, 0, time.UTC))
	testFarFuture = NewTimepoint(time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC))
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
func validRawToken() RawToken {
	t, _ := NewRawToken("raw-tok-001")
	return t
}
func validDeviceIdentity() DeviceIdentity {
	return ReconstituteDeviceIdentity("192.168.1.1", "Linux", "Chrome", "Desktop", "en-US", "Mozilla/5.0", false)
}
func differentDeviceIdentity() DeviceIdentity {
	return ReconstituteDeviceIdentity("10.0.0.1", "Windows", "Firefox", "Laptop", "fr-FR", "Mozilla/6.0", false)
}

// ---------------------------------------------------------------
// Aggregate builders
// ---------------------------------------------------------------

func newActiveUserWithSession() *User {
	u := ReconstituteUser(
		validUserID(),
		validEmail(),
		validHashedPassword(),
		true,
		[]Role{RoleMember},
		[]Session{
			ReconstituteSession(
				validSessionID(),
				validHashedToken(),
				validDeviceIdentity(),
				testFuture,
				testNow,
				false,
			),
		},
		false,
		testNow,
	)
	return u
}

func newDeletedUser() *User {
	return ReconstituteUser(
		validUserID(),
		validEmail(),
		validHashedPassword(),
		true,
		[]Role{RoleMember},
		nil,
		true,
		testNow,
	)
}

func newInactiveUser() *User {
	return ReconstituteUser(
		validUserID(),
		validEmail(),
		validHashedPassword(),
		false,
		nil,
		nil,
		false,
		testNow,
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

func (s *stubPasswordService) Hash(_ RawPassword) (HashedPassword, error) {
	return s.hashResult, s.hashErr
}
func (s *stubPasswordService) Compare(_ RawPassword, _ HashedPassword) bool {
	return s.compareOut
}

type stubIDGenerator struct {
	userID        UserID
	userIDErr     error
	sessionID     SessionID
	sessionIDErr  error
	recoveryID    RecoveryTokenID
	recoveryIDErr error
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

type stubTokenService struct {
	generateToken     RawToken
	generateErr       error
	hashSessionOut    HashedToken
	hashSessionErr    error
	hashRecoveryOut   RecoveryTokenHash
	hashRecoveryErr   error
	compareSessionOut bool
	compareRecOut     bool
}

func (s *stubTokenService) Generate() (RawToken, error) {
	return s.generateToken, s.generateErr
}
func (s *stubTokenService) HashSessionToken(_ RawToken) (HashedToken, error) {
	return s.hashSessionOut, s.hashSessionErr
}
func (s *stubTokenService) HashRecoveryToken(_ RawToken) (RecoveryTokenHash, error) {
	return s.hashRecoveryOut, s.hashRecoveryErr
}
func (s *stubTokenService) CompareSession(_ RawToken, _ HashedToken) bool {
	return s.compareSessionOut
}
func (s *stubTokenService) CompareRecovery(_ RawToken, _ RecoveryTokenHash) bool {
	return s.compareRecOut
}

type stubAccessService struct {
	issueToken   AccessToken
	issueExpiry  Timepoint
	issueErr     error
	validateID   AccessIdentity
	validateErr  error
}

func (s *stubAccessService) Issue(_ UserID, _ Email, _ SessionID, _ []Role, _ Timepoint, _ Timepoint, _ Timepoint) (AccessToken, Timepoint, error) {
	return s.issueToken, s.issueExpiry, s.issueErr
}
func (s *stubAccessService) Validate(_ AccessToken) (AccessIdentity, error) {
	return s.validateID, s.validateErr
}

type stubUserRepository struct {
	findByIDResult    *User
	findByIDErr       error
	findByEmailResult *User
	findByEmailErr    error
	findByTokenResult *User
	findByTokenErr    error
	saveErr           error
	deleteErr         error
}

func (r *stubUserRepository) FindByID(_ context.Context, _ UserID) (*User, error) {
	return r.findByIDResult, r.findByIDErr
}
func (r *stubUserRepository) FindByEmail(_ context.Context, _ Email) (*User, error) {
	return r.findByEmailResult, r.findByEmailErr
}
func (r *stubUserRepository) FindBySessionToken(_ context.Context, _ HashedToken) (*User, error) {
	return r.findByTokenResult, r.findByTokenErr
}
func (r *stubUserRepository) Save(_ context.Context, _ *User) error {
	return r.saveErr
}
func (r *stubUserRepository) Delete(_ context.Context, _ UserID) error {
	return r.deleteErr
}

type stubPasswordManager struct {
	validateHashResult HashedPassword
	validateHashErr    error
	compareOut         bool
}

func (s *stubPasswordManager) ValidateAndHashNewPassword(_ RawPassword) (HashedPassword, error) {
	return s.validateHashResult, s.validateHashErr
}
func (s *stubPasswordManager) Compare(_ RawPassword, _ HashedPassword) bool {
	return s.compareOut
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
