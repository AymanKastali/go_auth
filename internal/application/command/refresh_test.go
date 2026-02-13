package command

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenHandler(t *testing.T) {
	validCmd := RefreshTokenCommand{
		UserID:       "user-001",
		RefreshToken: "raw-tok",
		Fingerprint:  testDeviceIdentity().Fingerprint().String(),
	}

	accessTok, _ := domain.NewAccessToken("access-tok")
	sess := testActiveSession()
	refreshRawToken := "new-refresh-tok"

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		h := NewRefreshTokenHandler(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByTokenResult: sess},
			&stubAppRoleRepository{},
			&mockRefreshSession{rawToken: refreshRawToken},
			&mockGrantAccess{grantToken: accessTok, grantExpiry: appTestFuture},
			&mockTokenService{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		resp, err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", resp.AccessToken)
		assert.Equal(t, "new-refresh-tok", resp.RefreshToken)
	})

	t.Run("invalid_token", func(t *testing.T) {
		h := NewRefreshTokenHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockRefreshSession{},
			&mockGrantAccess{},
			&mockTokenService{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), RefreshTokenCommand{RefreshToken: "", Fingerprint: "fp"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("invalid_fingerprint", func(t *testing.T) {
		h := NewRefreshTokenHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockRefreshSession{},
			&mockGrantAccess{},
			&mockTokenService{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), RefreshTokenCommand{RefreshToken: "tok", Fingerprint: ""})
		assert.ErrorIs(t, err, domain.ErrDeviceFingerprintRequired)
	})

	t.Run("session_not_found", func(t *testing.T) {
		h := NewRefreshTokenHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockRefreshSession{},
			&mockGrantAccess{},
			&mockTokenService{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrSessionNotFound)
	})

	t.Run("user_inactive", func(t *testing.T) {
		h := NewRefreshTokenHandler(
			&stubAppUserRepository{findByIDResult: nil},
			&stubAppSessionRepository{findByTokenResult: sess},
			&stubAppRoleRepository{},
			&mockRefreshSession{},
			&mockGrantAccess{},
			&mockTokenService{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrUserInactive)
	})

	t.Run("refresh_fails_hijack", func(t *testing.T) {
		user := testActiveUser()
		h := NewRefreshTokenHandler(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByTokenResult: sess},
			&stubAppRoleRepository{},
			&mockRefreshSession{err: domain.ErrSessionFingerprintMiss},
			&mockGrantAccess{},
			&mockTokenService{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrSessionFingerprintMiss)
	})

	t.Run("access_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewRefreshTokenHandler(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByTokenResult: sess},
			&stubAppRoleRepository{},
			&mockRefreshSession{rawToken: refreshRawToken},
			&mockGrantAccess{grantErr: errTest},
			&mockTokenService{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("session_save_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewRefreshTokenHandler(
			&stubAppUserRepository{findByIDResult: user},
			&stubAppSessionRepository{findByTokenResult: sess, saveErr: errTest},
			&stubAppRoleRepository{},
			&mockRefreshSession{rawToken: refreshRawToken},
			&mockGrantAccess{grantToken: accessTok, grantExpiry: appTestFuture},
			&mockTokenService{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
