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
			&stubAppSessionRepository{},
			&mockRefreshSession{user: user, session: sess, rawToken: refreshRawToken},
			&mockGrantAccess{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		resp, err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", resp.AccessToken)
		assert.Equal(t, "new-refresh-tok", resp.RefreshToken) // rotated token
	})

	t.Run("invalid_token", func(t *testing.T) {
		h := NewRefreshTokenHandler(
			&stubAppSessionRepository{},
			&mockRefreshSession{},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), RefreshTokenCommand{RefreshToken: "", Fingerprint: "fp"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("invalid_fingerprint", func(t *testing.T) {
		h := NewRefreshTokenHandler(
			&stubAppSessionRepository{},
			&mockRefreshSession{},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), RefreshTokenCommand{RefreshToken: "tok", Fingerprint: ""})
		assert.ErrorIs(t, err, domain.ErrDeviceFingerprintRequired)
	})

	t.Run("refresh_fails_hijack", func(t *testing.T) {
		h := NewRefreshTokenHandler(
			&stubAppSessionRepository{},
			&mockRefreshSession{err: domain.ErrSessionFingerprintMiss},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrSessionFingerprintMiss)
	})

	t.Run("refresh_fails_token_reuse_saves_revoked_session", func(t *testing.T) {
		revokedSession := testActiveSession()
		dispatcher := &mockEventDispatcher{}
		h := NewRefreshTokenHandler(
			&stubAppSessionRepository{},
			&mockRefreshSession{session: revokedSession, err: domain.ErrSessionTokenReuse},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			dispatcher,
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrSessionTokenReuse)
	})

	t.Run("access_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewRefreshTokenHandler(
			&stubAppSessionRepository{},
			&mockRefreshSession{user: user, session: sess, rawToken: refreshRawToken},
			&mockGrantAccess{grantErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("session_save_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewRefreshTokenHandler(
			&stubAppSessionRepository{saveErr: errTest},
			&mockRefreshSession{user: user, session: sess, rawToken: refreshRawToken},
			&mockGrantAccess{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
