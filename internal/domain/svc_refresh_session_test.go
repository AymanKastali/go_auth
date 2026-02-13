package domain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshSession_Refresh(t *testing.T) {
	ctx := context.Background()
	newGeneratedToken := "new-generated-token"
	newHashedTokenVal := ReconstituteHashedToken("new-hashed-token")

	t.Run("happy_path", func(t *testing.T) {
		user := newActiveUser()
		session := newActiveSession()
		svc := NewRefreshSession(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByTokenResult: session},
			&stubTokenService{
				hashSessionOut: validHashedToken(),
				generateToken:  newGeneratedToken,
			},
			&stubSessionPolicy{lifetime: 24 * time.Hour, maxActive: 5},
		)

		fp := validDeviceIdentity().Fingerprint()
		u, sess, rawTok, err := svc.Refresh(ctx, validRawToken(), fp, testNow)
		require.NoError(t, err)
		assert.NotNil(t, u)
		assert.Equal(t, validSessionID(), sess.ID())
		assert.NotEmpty(t, rawTok)
	})

	t.Run("hash_fails", func(t *testing.T) {
		svc := NewRefreshSession(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubTokenService{hashSessionErr: errors.New("hash err")},
			&stubSessionPolicy{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, _, _, err := svc.Refresh(ctx, validRawToken(), fp, testNow)
		assert.Error(t, err)
	})

	t.Run("session_not_found", func(t *testing.T) {
		svc := NewRefreshSession(
			&stubUserRepository{},
			&stubSessionRepository{findByTokenResult: nil, findByPreviousTokenResult: nil},
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubSessionPolicy{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, _, _, err := svc.Refresh(ctx, validRawToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("token_reuse_detected", func(t *testing.T) {
		session := newActiveSession()
		svc := NewRefreshSession(
			&stubUserRepository{},
			&stubSessionRepository{
				findByTokenResult:         nil,
				findByPreviousTokenResult: session,
			},
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubSessionPolicy{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, revokedSession, _, err := svc.Refresh(ctx, validRawToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrSessionTokenReuse)
		assert.NotNil(t, revokedSession)
		assert.True(t, revokedSession.IsRevoked())
	})

	t.Run("user_not_found", func(t *testing.T) {
		session := newActiveSession()
		svc := NewRefreshSession(
			&stubUserRepository{findByIDResult: nil},
			&stubSessionRepository{findByTokenResult: session},
			&stubTokenService{
				hashSessionOut: validHashedToken(),
				generateToken:  newGeneratedToken,
			},
			&stubSessionPolicy{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, _, _, err := svc.Refresh(ctx, validRawToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("fingerprint_mismatch_propagated", func(t *testing.T) {
		user := newActiveUser()
		session := newActiveSession()
		svc := NewRefreshSession(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByTokenResult: session},
			&stubTokenService{
				hashSessionOut: newHashedTokenVal,
				generateToken:  newGeneratedToken,
			},
			&stubSessionPolicy{lifetime: 24 * time.Hour},
		)

		wrongFP := differentDeviceIdentity().Fingerprint()
		_, _, _, err := svc.Refresh(ctx, validRawToken(), wrongFP, testNow)
		assert.ErrorIs(t, err, ErrSessionFingerprintMiss)
	})
}
