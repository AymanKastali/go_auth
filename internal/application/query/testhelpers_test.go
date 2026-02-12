package query

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

type stubRoleQueryPort struct {
	findByIDResult application.RoleReadModel
	findByIDErr    error
	findAllResult  []application.RoleReadModel
	findAllErr     error
}

func (s *stubRoleQueryPort) FindByID(_ context.Context, _ string) (application.RoleReadModel, error) {
	return s.findByIDResult, s.findByIDErr
}
func (s *stubRoleQueryPort) FindAll(_ context.Context) ([]application.RoleReadModel, error) {
	return s.findAllResult, s.findAllErr
}

// ---------------------------------------------------------------
// Domain service mocks
// ---------------------------------------------------------------

type mockAccessManager struct {
	grantToken         domain.AccessToken
	grantExpiry        time.Time
	grantErr           error
	verifyUser         *domain.User
	verifySess         *domain.Session
	verifyErr          error
	resolvePermsResult []domain.Permission
	resolvePermsErr    error
}

func (m *mockAccessManager) GrantImmediateAccess(_ context.Context, _ *domain.User, _ domain.SessionID, _ time.Time) (domain.AccessToken, time.Time, error) {
	return m.grantToken, m.grantExpiry, m.grantErr
}
func (m *mockAccessManager) VerifyAccess(_ context.Context, _ domain.AccessToken, _ time.Time) (*domain.User, *domain.Session, error) {
	return m.verifyUser, m.verifySess, m.verifyErr
}
func (m *mockAccessManager) ResolvePermissions(_ context.Context, _ []domain.RoleName) ([]domain.Permission, error) {
	return m.resolvePermsResult, m.resolvePermsErr
}

// ---------------------------------------------------------------
// Infrastructure stubs
// ---------------------------------------------------------------

type stubClock struct {
	now time.Time
}

func (c *stubClock) Now() time.Time { return c.now }
