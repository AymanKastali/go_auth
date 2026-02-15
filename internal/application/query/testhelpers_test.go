package query

import (
	"context"
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

func testUserID() domain.UserID       { return domain.ReconstituteUserID("user-001") }
func testSessionID() domain.SessionID { return domain.ReconstituteSessionID("sess-001") }
func testDeviceIdentity() domain.DeviceIdentity {
	return domain.ReconstituteDeviceIdentity("192.168.1.1", "Linux", "Chrome", "Desktop", "en-US", "Mozilla/5.0", false)
}

func testActiveUser() *domain.User {
	return domain.ReconstituteUser(
		testUserID(),
		domain.ReconstituteEmail("test@example.com"),
		domain.ReconstituteHashedPassword("$2a$10$hash"),
		true,
		[]domain.RoleName{domain.ReconstituteRoleName("member")},
		false,
		appTestNow,
		0,
		nil,
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

func unauthenticatedCtx() context.Context {
	appCtx := &application.AppContext{
		Client: application.ClientContext{Identity: testDeviceIdentity()},
		Logger: slog.Default(),
	}
	return application.WithAppContext(context.Background(), appCtx)
}

// ---------------------------------------------------------------
// Query port stubs
// ---------------------------------------------------------------

type stubUserQueryPort struct {
	findByIDResult    application.UserReadModel
	findByIDErr       error
	findByEmailResult application.UserReadModel
	findByEmailErr    error
	findAllResult     []application.UserReadModel
	findAllTotal      int64
	findAllErr        error
}

func (s *stubUserQueryPort) FindByID(_ context.Context, _ string) (application.UserReadModel, error) {
	return s.findByIDResult, s.findByIDErr
}
func (s *stubUserQueryPort) FindByEmail(_ context.Context, _ string) (application.UserReadModel, error) {
	return s.findByEmailResult, s.findByEmailErr
}
func (s *stubUserQueryPort) FindAll(_ context.Context, _, _ int) ([]application.UserReadModel, int64, error) {
	return s.findAllResult, s.findAllTotal, s.findAllErr
}

// ---------------------------------------------------------------
// Domain service mocks
// ---------------------------------------------------------------

type mockAccessService struct {
	validateID  domain.AccessIdentity
	validateErr error
}

func (m *mockAccessService) Issue(_ domain.UserID, _ domain.Email, _ domain.SessionID, _ []domain.RoleName, _ []domain.Permission, _, _, _ time.Time) (domain.AccessToken, time.Time, error) {
	return domain.ZeroAccessToken, time.Time{}, nil
}
func (m *mockAccessService) Validate(_ domain.AccessToken) (domain.AccessIdentity, error) {
	return m.validateID, m.validateErr
}

type mockResolvePermissions struct {
	resolveResult []domain.Permission
}

func (m *mockResolvePermissions) Resolve(_ []*domain.Role) []domain.Permission {
	return m.resolveResult
}

// ---------------------------------------------------------------
// Repository stubs
// ---------------------------------------------------------------

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

type stubAppRoleRepository struct {
	findByIDResult   *domain.Role
	findByIDErr      error
	findByNameResult *domain.Role
	findByNameErr    error
	findAllResult    []*domain.Role
	findAllErr       error
	saveErr          error
}

func (r *stubAppRoleRepository) FindByID(_ context.Context, _ domain.RoleID) (*domain.Role, error) {
	return r.findByIDResult, r.findByIDErr
}
func (r *stubAppRoleRepository) FindByName(_ context.Context, _ domain.RoleName) (*domain.Role, error) {
	return r.findByNameResult, r.findByNameErr
}
func (r *stubAppRoleRepository) FindAll(_ context.Context) ([]*domain.Role, error) {
	return r.findAllResult, r.findAllErr
}
func (r *stubAppRoleRepository) Save(_ context.Context, _ *domain.Role) error {
	return r.saveErr
}

// ---------------------------------------------------------------
// Infrastructure stubs
// ---------------------------------------------------------------

type stubClock struct {
	now time.Time
}

func (c *stubClock) Now() time.Time { return c.now }
