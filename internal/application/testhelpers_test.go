package application

import (
	"context"
	"errors"
	"go_auth/internal/domain"
	"log/slog"
	"time"
)

// ---------------------------------------------------------------
// Shared time/VO constants
// ---------------------------------------------------------------

var (
	appTestNow    = domain.NewTimepoint(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC))
	appTestFuture = domain.NewTimepoint(time.Date(2025, 6, 16, 12, 0, 0, 0, time.UTC))
)

var errTest = errors.New("test error")

func testUserID() domain.UserID       { return domain.ReconstituteUserID("user-001") }
func testEmail() domain.Email         { return domain.ReconstituteEmail("test@example.com") }
func testSessionID() domain.SessionID { return domain.ReconstituteSessionID("sess-001") }
func testHashedPassword() domain.HashedPassword {
	return domain.ReconstituteHashedPassword("$2a$10$hash")
}
func testDeviceIdentity() domain.DeviceIdentity {
	return domain.ReconstituteDeviceIdentity("192.168.1.1", "Linux", "Chrome", "Desktop", "en-US", "Mozilla/5.0", false)
}

func testActiveUser() *domain.User {
	return domain.ReconstituteUser(
		testUserID(),
		testEmail(),
		testHashedPassword(),
		true,
		[]domain.RoleName{domain.RoleMember},
		false,
		appTestNow,
	)
}

func testActiveSession() *domain.Session {
	return domain.ReconstituteSession(
		testSessionID(),
		testUserID(),
		domain.ReconstituteHashedToken("hashed-tok"),
		testDeviceIdentity(),
		appTestFuture,
		appTestNow,
		false,
	)
}

// ---------------------------------------------------------------
// Context builders
// ---------------------------------------------------------------

func authenticatedCtx(userID, sessionID string) context.Context {
	appCtx := &AppContext{
		User: &UserContext{
			UserID:    domain.ReconstituteUserID(userID),
			SessionID: domain.ReconstituteSessionID(sessionID),
		},
		Client: ClientContext{Identity: testDeviceIdentity()},
		Logger: slog.Default(),
	}
	return WithAppContext(context.Background(), appCtx)
}

func unauthenticatedCtx() context.Context {
	appCtx := &AppContext{
		Client: ClientContext{Identity: testDeviceIdentity()},
		Logger: slog.Default(),
	}
	return WithAppContext(context.Background(), appCtx)
}

// ---------------------------------------------------------------
// Domain service mocks
// ---------------------------------------------------------------

type mockRegistrationService struct {
	registerMemberResult *domain.User
	registerMemberErr    error
	registerAdminResult  *domain.User
	registerAdminErr     error
}

func (m *mockRegistrationService) RegisterNewMember(_ context.Context, _ domain.UserID, _ domain.Email, _ domain.HashedPassword, _ domain.Timepoint) (*domain.User, error) {
	return m.registerMemberResult, m.registerMemberErr
}
func (m *mockRegistrationService) RegisterNewSuperAdmin(_ context.Context, _ domain.UserID, _ domain.Email, _ domain.HashedPassword, _ domain.Timepoint) (*domain.User, error) {
	return m.registerAdminResult, m.registerAdminErr
}

type mockAuthenticationService struct {
	authRawToken domain.RawToken
	authSession  *domain.Session
	authErr      error

	refreshUser    *domain.User
	refreshSession *domain.Session
	refreshErr     error
}

func (m *mockAuthenticationService) AuthenticateAndEstablishSession(_ context.Context, _ *domain.User, _ domain.RawPassword, _ domain.DeviceIdentity, _ domain.Timepoint) (domain.RawToken, *domain.Session, error) {
	return m.authRawToken, m.authSession, m.authErr
}
func (m *mockAuthenticationService) RefreshSession(_ context.Context, _ domain.RawToken, _ domain.DeviceFingerprint, _ domain.Timepoint) (*domain.User, *domain.Session, error) {
	return m.refreshUser, m.refreshSession, m.refreshErr
}

type mockAccessManager struct {
	grantToken   domain.AccessToken
	grantExpiry  domain.Timepoint
	grantErr     error
	verifyUser   *domain.User
	verifySID    domain.SessionID
	verifyErr    error
}

func (m *mockAccessManager) GrantImmediateAccess(_ context.Context, _ *domain.User, _ domain.SessionID, _ domain.Timepoint) (domain.AccessToken, domain.Timepoint, error) {
	return m.grantToken, m.grantExpiry, m.grantErr
}
func (m *mockAccessManager) VerifyAccess(_ context.Context, _ domain.AccessToken, _ domain.Timepoint) (*domain.User, domain.SessionID, error) {
	return m.verifyUser, m.verifySID, m.verifyErr
}

type mockAccountManager struct {
	initiateRawToken domain.RawToken
	initiateRecovery *domain.RecoveryToken
	initiateErr      error
	changeErr        error
	resetErr         error
}

func (m *mockAccountManager) InitiatePasswordReset(_ *domain.User, _ domain.Timepoint) (domain.RawToken, *domain.RecoveryToken, error) {
	return m.initiateRawToken, m.initiateRecovery, m.initiateErr
}
func (m *mockAccountManager) ChangePassword(_ *domain.User, _ domain.RawPassword, _ domain.RawPassword, _ domain.Timepoint) error {
	return m.changeErr
}
func (m *mockAccountManager) ResetPasswordByToken(_ *domain.User, _ *domain.RecoveryToken, _ domain.RawPassword, _ domain.Timepoint) error {
	return m.resetErr
}

type mockTokenService struct {
	hashRecoveryOut domain.RecoveryTokenHash
	hashRecoveryErr error
}

func (m *mockTokenService) Generate() (domain.RawToken, error) {
	return domain.RawToken{}, nil
}
func (m *mockTokenService) HashSessionToken(_ domain.RawToken) (domain.HashedToken, error) {
	return domain.HashedToken{}, nil
}
func (m *mockTokenService) HashRecoveryToken(_ domain.RawToken) (domain.RecoveryTokenHash, error) {
	return m.hashRecoveryOut, m.hashRecoveryErr
}
func (m *mockTokenService) CompareSession(_ domain.RawToken, _ domain.HashedToken) bool {
	return false
}
func (m *mockTokenService) CompareRecovery(_ domain.RawToken, _ domain.RecoveryTokenHash) bool {
	return false
}

type mockPasswordManager struct {
	validateHashResult domain.HashedPassword
	validateHashErr    error
	compareOut         bool
}

func (m *mockPasswordManager) ValidateAndHashNewPassword(_ domain.RawPassword) (domain.HashedPassword, error) {
	return m.validateHashResult, m.validateHashErr
}
func (m *mockPasswordManager) Compare(_ domain.RawPassword, _ domain.HashedPassword) bool {
	return m.compareOut
}

// ---------------------------------------------------------------
// Application port mocks
// ---------------------------------------------------------------

type mockTransactionManager struct{}

func (m *mockTransactionManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

type mockEventDispatcher struct {
	events []domain.DomainEvent
}

func (m *mockEventDispatcher) Dispatch(_ context.Context, events []domain.DomainEvent) {
	m.events = append(m.events, events...)
}

type mockEmailService struct {
	sentTo    string
	sentToken string
	err       error
}

func (m *mockEmailService) SendResetLink(toEmail, rawToken string) error {
	m.sentTo = toEmail
	m.sentToken = rawToken
	return m.err
}

// ---------------------------------------------------------------
// Infrastructure stubs
// ---------------------------------------------------------------

type stubClock struct {
	now domain.Timepoint
}

func (c *stubClock) Now() domain.Timepoint { return c.now }

type stubAppIDGenerator struct {
	userID    domain.UserID
	userIDErr error
}

func (g *stubAppIDGenerator) GenerateUserID() (domain.UserID, error) {
	return g.userID, g.userIDErr
}
func (g *stubAppIDGenerator) GenerateSessionID() (domain.SessionID, error) {
	return testSessionID(), nil
}
func (g *stubAppIDGenerator) GenerateRecoveryTokenID() (domain.RecoveryTokenID, error) {
	return domain.ReconstituteRecoveryTokenID("rec-001"), nil
}
func (g *stubAppIDGenerator) GenerateRoleID() (domain.RoleID, error) {
	return domain.ReconstituteRoleID("role-001"), nil
}

type stubAppUserRepository struct {
	findByIDResult    *domain.User
	findByIDErr       error
	findByEmailResult *domain.User
	findByEmailErr    error
	saveErr           error
	deleteErr         error
}

func (r *stubAppUserRepository) FindByID(_ context.Context, _ domain.UserID) (*domain.User, error) {
	return r.findByIDResult, r.findByIDErr
}
func (r *stubAppUserRepository) FindByEmail(_ context.Context, _ domain.Email) (*domain.User, error) {
	return r.findByEmailResult, r.findByEmailErr
}
func (r *stubAppUserRepository) Save(_ context.Context, _ *domain.User) error {
	return r.saveErr
}
func (r *stubAppUserRepository) Delete(_ context.Context, _ domain.UserID) error {
	return r.deleteErr
}

type stubAppSessionRepository struct {
	findByIDResult   *domain.Session
	findByIDErr      error
	findByTokenResult *domain.Session
	findByTokenErr   error
	findByFPResult   *domain.Session
	findByFPErr      error
	findActiveResult []*domain.Session
	findActiveErr    error
	saveErr          error
	revokeAllErr     error
}

func (r *stubAppSessionRepository) FindByID(_ context.Context, _ domain.SessionID) (*domain.Session, error) {
	return r.findByIDResult, r.findByIDErr
}
func (r *stubAppSessionRepository) FindByToken(_ context.Context, _ domain.HashedToken) (*domain.Session, error) {
	return r.findByTokenResult, r.findByTokenErr
}
func (r *stubAppSessionRepository) FindActiveByUserAndFingerprint(_ context.Context, _ domain.UserID, _ domain.DeviceFingerprint) (*domain.Session, error) {
	return r.findByFPResult, r.findByFPErr
}
func (r *stubAppSessionRepository) FindActiveByUserID(_ context.Context, _ domain.UserID) ([]*domain.Session, error) {
	return r.findActiveResult, r.findActiveErr
}
func (r *stubAppSessionRepository) Save(_ context.Context, _ *domain.Session) error {
	return r.saveErr
}
func (r *stubAppSessionRepository) RevokeAllForUser(_ context.Context, _ domain.UserID, _ domain.Timepoint) error {
	return r.revokeAllErr
}

type stubUserQueryPort struct {
	findByIDResult    UserReadModel
	findByIDErr       error
	findByEmailResult UserReadModel
	findByEmailErr    error
}

func (s *stubUserQueryPort) FindByID(_ context.Context, _ string) (UserReadModel, error) {
	return s.findByIDResult, s.findByIDErr
}
func (s *stubUserQueryPort) FindByEmail(_ context.Context, _ string) (UserReadModel, error) {
	return s.findByEmailResult, s.findByEmailErr
}

type stubAppRecoveryTokenRepository struct {
	findByHashResult *domain.RecoveryToken
	findByHashErr    error
	saveErr          error
	revokeAllErr     error
}

func (r *stubAppRecoveryTokenRepository) FindByHash(_ context.Context, _ domain.RecoveryTokenHash) (*domain.RecoveryToken, error) {
	return r.findByHashResult, r.findByHashErr
}
func (r *stubAppRecoveryTokenRepository) Save(_ context.Context, _ *domain.RecoveryToken) error {
	return r.saveErr
}
func (r *stubAppRecoveryTokenRepository) RevokeAllForUser(_ context.Context, _ domain.UserID, _ domain.Timepoint) error {
	return r.revokeAllErr
}
