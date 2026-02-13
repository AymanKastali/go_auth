package command

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginHandler(t *testing.T) {
	validCmd := LoginCommand{
		Email: "test@example.com", Password: "Str0ng!Pass",
		IPAddress: "192.168.1.1", OS: "Linux", Browser: "Chrome",
		Model: "Desktop", AcceptLanguage: "en-US", UserAgent: "Mozilla/5.0",
	}

	rawTok := "refresh-tok"
	accessTok, _ := domain.NewAccessToken("access-tok")
	sess := testActiveSession()

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{rawToken: rawTok, session: sess},
			&mockGrantAccess{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		resp, err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", resp.AccessToken)
		assert.Equal(t, "refresh-tok", resp.RefreshToken)
		assert.NotEmpty(t, resp.AccessTokenExpiry)
		assert.NotEmpty(t, resp.RefreshTokenExpiry)
	})

	t.Run("session_limit_revoked_session_persisted", func(t *testing.T) {
		user := testActiveUser()
		revokedSess := testActiveSession()
		dispatcher := &mockEventDispatcher{}
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{rawToken: rawTok, session: sess, revokedSession: revokedSess},
			&mockGrantAccess{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			dispatcher,
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		resp, err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.AccessToken)
	})

	t.Run("invalid_email", func(t *testing.T) {
		h := NewLoginHandler(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), LoginCommand{Email: "bad", Password: "pass"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: nil},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrAuthenticationFailed)
	})

	t.Run("auth_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{verifyErr: domain.ErrAuthenticationFailed},
			&mockOpenSession{},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrAuthenticationFailed)
	})

	t.Run("establish_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{err: errTest},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("access_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{rawToken: rawTok, session: sess},
			&mockGrantAccess{grantErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("session_save_fails", func(t *testing.T) {
		user := testActiveUser()
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{saveErr: errTest},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{rawToken: rawTok, session: sess},
			&mockGrantAccess{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("locked_user_rejected", func(t *testing.T) {
		lockTime := appTestFuture
		user := domain.ReconstituteUser(
			testUserID(), testEmail(), testHashedPassword(),
			true, []domain.RoleName{domain.ReconstituteRoleName("member")},
			false, appTestNow, 5, &lockTime,
		)
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrAccountLocked)
	})

	t.Run("failed_login_increments_counter", func(t *testing.T) {
		user := testActiveUser()
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{verifyErr: domain.ErrAuthenticationFailed},
			&mockOpenSession{},
			&mockGrantAccess{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrAuthenticationFailed)
		assert.Equal(t, 1, user.FailedLoginAttempts())
	})

	t.Run("successful_login_resets_counter", func(t *testing.T) {
		user := domain.ReconstituteUser(
			testUserID(), testEmail(), testHashedPassword(),
			true, []domain.RoleName{domain.ReconstituteRoleName("member")},
			false, appTestNow, 3, nil,
		)
		h := NewLoginHandler(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&stubAppRoleRepository{},
			&mockVerifyCredentials{},
			&mockOpenSession{rawToken: rawTok, session: sess},
			&mockGrantAccess{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
			&mockTransactionManager{},
			defaultLoginPolicy(),
		)

		_, err := h.Handle(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.Equal(t, 0, user.FailedLoginAttempts())
	})
}
