package application

import (
	"testing"

	"go_auth/internal/core/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenUseCase(t *testing.T) {
	validCmd := RefreshTokenCommand{
		UserID:       "user-001",
		RefreshToken: "raw-tok",
		Fingerprint:  "Mozilla/5.0|192.168.1.1|en-US",
	}

	accessTok, _ := domain.NewAccessToken("access-tok")
	sess := domain.ReconstituteSession(
		testSessionID(), domain.ReconstituteHashedToken("h"),
		testDeviceIdentity(), appTestFuture, appTestNow, nil,
	)

	t.Run("happy_path", func(t *testing.T) {
		user := testActiveUser()
		uc := NewRefreshTokenUseCase(
			&stubAppUserRepository{},
			&mockAuthenticationService{refreshUser: user, refreshSession: sess},
			&mockAccessManager{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		resp, err := uc.Execute(unauthenticatedCtx(), validCmd)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", resp.AccessToken)
		assert.Equal(t, "raw-tok", resp.RefreshToken) // echoed back
	})

	t.Run("invalid_token", func(t *testing.T) {
		uc := NewRefreshTokenUseCase(
			&stubAppUserRepository{},
			&mockAuthenticationService{},
			&mockAccessManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), RefreshTokenCommand{RefreshToken: "", Fingerprint: "fp"})
		assert.ErrorIs(t, err, domain.ErrTokenInvalid)
	})

	t.Run("invalid_fingerprint", func(t *testing.T) {
		uc := NewRefreshTokenUseCase(
			&stubAppUserRepository{},
			&mockAuthenticationService{},
			&mockAccessManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), RefreshTokenCommand{RefreshToken: "tok", Fingerprint: ""})
		assert.ErrorIs(t, err, domain.ErrDeviceFingerprintRequired)
	})

	t.Run("refresh_fails_hijack", func(t *testing.T) {
		uc := NewRefreshTokenUseCase(
			&stubAppUserRepository{},
			&mockAuthenticationService{refreshErr: domain.ErrSessionFingerprintMiss},
			&mockAccessManager{},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, domain.ErrSessionFingerprintMiss)
	})

	t.Run("access_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewRefreshTokenUseCase(
			&stubAppUserRepository{},
			&mockAuthenticationService{refreshUser: user, refreshSession: sess},
			&mockAccessManager{grantErr: errTest},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})

	t.Run("save_fails", func(t *testing.T) {
		user := testActiveUser()
		uc := NewRefreshTokenUseCase(
			&stubAppUserRepository{saveErr: errTest},
			&mockAuthenticationService{refreshUser: user, refreshSession: sess},
			&mockAccessManager{grantToken: accessTok, grantExpiry: appTestFuture},
			&stubClock{now: appTestNow},
			&mockEventDispatcher{},
		)

		_, err := uc.Execute(unauthenticatedCtx(), validCmd)
		assert.ErrorIs(t, err, errTest)
	})
}
