package command

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

// ---------------------------------------------------------------
// Shared time/VO constants
// ---------------------------------------------------------------

var (
	appTestNow    = time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	appTestFuture = time.Date(2025, 6, 16, 12, 0, 0, 0, time.UTC)
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
		[]domain.RoleName{domain.ReconstituteRoleName("member")},
		false,
		appTestNow,
	)
}

func testActiveSession() *domain.Session {
	return domain.ReconstituteSession(
		testSessionID(),
		testUserID(),
		domain.ReconstituteHashedToken("hashed-tok"),
		domain.ZeroHashedToken,
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
	appCtx := &application.AppContext{
		User: &application.UserContext{
			UserID:    domain.ReconstituteUserID(userID),
			SessionID: domain.ReconstituteSessionID(sessionID),
		},
		Client: application.ClientContext{Identity: testDeviceIdentity()},
		Logger: slog.Default(),
	}
	return application.WithAppContext(context.Background(), appCtx)
}

func unauthenticatedCtx() context.Context {
	appCtx := &application.AppContext{
		Client: application.ClientContext{Identity: testDeviceIdentity()},
		Logger: slog.Default(),
	}
	return application.WithAppContext(context.Background(), appCtx)
}

// ---------------------------------------------------------------
// Domain service mocks
// ---------------------------------------------------------------

type mockRegisterMember struct {
	registerResult *domain.User
	registerErr    error
}

func (m *mockRegisterMember) Register(_ context.Context, _ domain.UserID, _ domain.Email, _ domain.HashedPassword, _ time.Time) (*domain.User, error) {
	return m.registerResult, m.registerErr
}

type mockRegisterAdmin struct {
	registerResult *domain.User
	registerErr    error
}

func (m *mockRegisterAdmin) Register(_ context.Context, _ domain.UserID, _ domain.Email, _ domain.HashedPassword, _ time.Time) (*domain.User, error) {
	return m.registerResult, m.registerErr
}

type mockVerifyCredentials struct {
	verifyErr error
}

func (m *mockVerifyCredentials) Verify(_ *domain.User, _ string) error {
	return m.verifyErr
}

type mockOpenSession struct {
	rawToken       string
	session        *domain.Session
	revokedSession *domain.Session
	err            error
}

func (m *mockOpenSession) Open(_ context.Context, _ domain.UserID, _ domain.DeviceIdentity, _ time.Time) (string, *domain.Session, *domain.Session, error) {
	return m.rawToken, m.session, m.revokedSession, m.err
}

type mockRefreshSession struct {
	user     *domain.User
	session  *domain.Session
	rawToken string
	err      error
}

func (m *mockRefreshSession) Refresh(_ context.Context, _ string, _ domain.DeviceFingerprint, _ time.Time) (*domain.User, *domain.Session, string, error) {
	return m.user, m.session, m.rawToken, m.err
}

type mockGrantAccess struct {
	grantToken  domain.AccessToken
	grantExpiry time.Time
	grantErr    error
}

func (m *mockGrantAccess) Grant(_ context.Context, _ *domain.User, _ domain.SessionID, _ time.Time) (domain.AccessToken, time.Time, error) {
	return m.grantToken, m.grantExpiry, m.grantErr
}

type mockInitiateRecovery struct {
	rawToken string
	recovery *domain.RecoveryToken
	err      error
}

func (m *mockInitiateRecovery) Initiate(_ *domain.User, _ time.Time) (string, *domain.RecoveryToken, error) {
	return m.rawToken, m.recovery, m.err
}

type mockChangePassword struct {
	err error
}

func (m *mockChangePassword) Change(_ *domain.User, _ string, _ domain.ValidatedPassword, _ time.Time) error {
	return m.err
}

type mockResetPassword struct {
	err error
}

func (m *mockResetPassword) Reset(_ *domain.User, _ *domain.RecoveryToken, _ domain.ValidatedPassword, _ time.Time) error {
	return m.err
}

type mockInitiateActivation struct {
	rawToken   string
	activation *domain.ActivationToken
	err        error
}

func (m *mockInitiateActivation) Initiate(_ *domain.User, _ time.Time) (string, *domain.ActivationToken, error) {
	return m.rawToken, m.activation, m.err
}

type mockPasswordPolicy struct {
	validateResult domain.ValidatedPassword
	validateErr    error
}

func (m *mockPasswordPolicy) Validate(_ string) (domain.ValidatedPassword, error) {
	return m.validateResult, m.validateErr
}

type mockPasswordService struct {
	hashResult domain.HashedPassword
	hashErr    error
	compareOut bool
}

func (m *mockPasswordService) Hash(_ domain.ValidatedPassword) (domain.HashedPassword, error) {
	return m.hashResult, m.hashErr
}
func (m *mockPasswordService) Compare(_ string, _ domain.HashedPassword) bool {
	return m.compareOut
}

type mockTokenService struct {
	hashRecoveryOut    domain.RecoveryTokenHash
	hashRecoveryErr    error
	hashActivationOut  domain.ActivationTokenHash
	hashActivationErr  error
}

func (m *mockTokenService) Generate() (string, error) {
	return "", nil
}
func (m *mockTokenService) HashSessionToken(_ string) (domain.HashedToken, error) {
	return domain.HashedToken{}, nil
}
func (m *mockTokenService) HashRecoveryToken(_ string) (domain.RecoveryTokenHash, error) {
	return m.hashRecoveryOut, m.hashRecoveryErr
}
func (m *mockTokenService) CompareSession(_ string, _ domain.HashedToken) bool {
	return false
}
func (m *mockTokenService) CompareRecovery(_ string, _ domain.RecoveryTokenHash) bool {
	return false
}
func (m *mockTokenService) HashActivationToken(_ string) (domain.ActivationTokenHash, error) {
	return m.hashActivationOut, m.hashActivationErr
}
func (m *mockTokenService) CompareActivation(_ string, _ domain.ActivationTokenHash) bool {
	return false
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
func (m *mockEmailService) SendActivationLink(toEmail, rawToken string) error {
	return m.err
}

// ---------------------------------------------------------------
// Infrastructure stubs
// ---------------------------------------------------------------

type stubClock struct {
	now time.Time
}

func (c *stubClock) Now() time.Time { return c.now }

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
func (g *stubAppIDGenerator) GenerateActivationTokenID() (domain.ActivationTokenID, error) {
	return domain.ReconstituteActivationTokenID("act-001"), nil
}
func (g *stubAppIDGenerator) GenerateRoleID() (domain.RoleID, error) {
	return domain.ReconstituteRoleID("role-001"), nil
}

type stubAppUserRepository struct {
	findByIDResult    *domain.User
	findByIDErr       error
	findByEmailResult *domain.User
	findByEmailErr    error
	findAllResult     []*domain.User
	findAllErr        error
	countResult       int64
	countErr          error
	saveErr           error
	deleteErr         error
}

func (r *stubAppUserRepository) FindByID(_ context.Context, _ domain.UserID) (*domain.User, error) {
	return r.findByIDResult, r.findByIDErr
}
func (r *stubAppUserRepository) FindByEmail(_ context.Context, _ domain.Email) (*domain.User, error) {
	return r.findByEmailResult, r.findByEmailErr
}
func (r *stubAppUserRepository) FindAll(_ context.Context, _, _ int) ([]*domain.User, error) {
	return r.findAllResult, r.findAllErr
}
func (r *stubAppUserRepository) Count(_ context.Context) (int64, error) {
	return r.countResult, r.countErr
}
func (r *stubAppUserRepository) Save(_ context.Context, _ *domain.User) error {
	return r.saveErr
}
func (r *stubAppUserRepository) Delete(_ context.Context, _ domain.UserID) error {
	return r.deleteErr
}

type stubAppSessionRepository struct {
	findByIDResult            *domain.Session
	findByIDErr               error
	findByTokenResult         *domain.Session
	findByTokenErr            error
	findByPreviousTokenResult *domain.Session
	findByPreviousTokenErr    error
	findByFPResult            *domain.Session
	findByFPErr               error
	findActiveResult          []*domain.Session
	findActiveErr             error
	saveErr                   error
	revokeAllErr              error
}

func (r *stubAppSessionRepository) FindByID(_ context.Context, _ domain.SessionID) (*domain.Session, error) {
	return r.findByIDResult, r.findByIDErr
}
func (r *stubAppSessionRepository) FindByToken(_ context.Context, _ domain.HashedToken) (*domain.Session, error) {
	return r.findByTokenResult, r.findByTokenErr
}
func (r *stubAppSessionRepository) FindByPreviousToken(_ context.Context, _ domain.HashedToken) (*domain.Session, error) {
	return r.findByPreviousTokenResult, r.findByPreviousTokenErr
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
func (r *stubAppSessionRepository) RevokeAllForUser(_ context.Context, _ domain.UserID, _ time.Time) error {
	return r.revokeAllErr
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
func (r *stubAppRecoveryTokenRepository) RevokeAllForUser(_ context.Context, _ domain.UserID) error {
	return r.revokeAllErr
}


