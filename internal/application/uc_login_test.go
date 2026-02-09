package application

import (
	"testing"

	"go_auth/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginUseCase(t *testing.T) {
	validCmd := LoginCommand{
		Email: "test@example.com", Password: "Str0ng!Pass",
		IPAddress: "192.168.1.1", OS: "Linux", Browser: "Chrome",
		Model: "Desktop", AcceptLanguage: "en-US", UserAgent: "Mozilla/5.0",
	}

	rawTok, _ := domain.NewRawToken("refresh-tok")
	accessTok, _ := domain.NewAccessToken("access-tok")
	sess := testActiveSession()

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewLoginUseCase(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&mockAuthenticationService{authRawToken: rawTok, authSession: sess},
			&mockAccessManager{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		resp, err := uc.Execute(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", resp.AccessToken)
		assert.Equal(t, "refresh-tok", resp.RefreshToken)
		assert.NotEmpty(t, resp.AccessTokenExpiry)
		assert.NotEmpty(t, resp.RefreshTokenExpiry)
	})

	t.Run("invalid_email", func(t *testing.T) {
		uc := NewLoginUseCase(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&mockAuthenticationService{},
			&mockAccessManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), LoginCommand{Email: "bad", Password: "pass"})
		assert.ErrorIs(t, err, domain.ErrUserEmailInvalid)
	})

	t.Run("empty_password", func(t *testing.T) {
		uc := NewLoginUseCase(
			&stubAppUserRepository{},
			&stubAppSessionRepository{},
			&mockAuthenticationService{},
			&mockAccessManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), LoginCommand{Email: "a@b.com", Password: ""})
		assert.ErrorIs(t, err, domain.ErrUserPasswordRequired)
	})

	t.Run("user_not_found", func(t *testing.T) {
		uc := NewLoginUseCase(
			&stubAppUserRepository{findByEmailResult: nil},
			&stubAppSessionRepository{},
			&mockAuthenticationService{},
			&mockAccessManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrAuthenticationFailed)
	})

	t.Run("auth_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewLoginUseCase(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&mockAuthenticationService{authErr: domain.ErrAuthenticationFailed},
			&mockAccessManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrAuthenticationFailed)
	})

	t.Run("access_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewLoginUseCase(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{},
			&mockAuthenticationService{authRawToken: rawTok, authSession: sess},
			&mockAccessManager{grantErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("session_save_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewLoginUseCase(
			&stubAppUserRepository{findByEmailResult: user},
			&stubAppSessionRepository{saveErr: errTest},
			&mockAuthenticationService{authRawToken: rawTok, authSession: sess},
			&mockAccessManager{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
