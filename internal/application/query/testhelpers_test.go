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

type mockVerifyAccess struct {
	verifyUser *domain.User
	verifySess *domain.Session
	verifyErr  error
}

func (m *mockVerifyAccess) Verify(_ context.Context, _ domain.AccessToken, _ time.Time) (*domain.User, *domain.Session, error) {
	return m.verifyUser, m.verifySess, m.verifyErr
}

type mockResolvePermissions struct {
	resolveResult []domain.Permission
	resolveErr    error
}

func (m *mockResolvePermissions) Resolve(_ context.Context, _ []domain.RoleName) ([]domain.Permission, error) {
	return m.resolveResult, m.resolveErr
}

// ---------------------------------------------------------------
// Infrastructure stubs
// ---------------------------------------------------------------

type stubClock struct {
	now time.Time
}

func (c *stubClock) Now() time.Time { return c.now }
