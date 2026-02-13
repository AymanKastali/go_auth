package domain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyAccess_Verify(t *testing.T) {
	ctx := context.Background()

	t.Run("happy_path", func(t *testing.T) {
		user := newActiveUser()
		session := newActiveSession()
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		verifier := NewVerifyAccess(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByIDResult: session},
			&stubAccessService{validateID: ai},
		)

		at, _ := NewAccessToken("tok")
		u, sess, err := verifier.Verify(ctx, at, testNow)
		require.NoError(t, err)
		assert.Equal(t, validUserID(), u.ID())
		assert.Equal(t, validSessionID(), sess.ID())
	})

	t.Run("token_invalid", func(t *testing.T) {
		verifier := NewVerifyAccess(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubAccessService{validateErr: ErrTokenInvalid},
		)

		at, _ := NewAccessToken("bad")
		_, _, err := verifier.Verify(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrTokenInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		verifier := NewVerifyAccess(
			&stubUserRepository{findByIDResult: nil},
			&stubSessionRepository{},
			&stubAccessService{validateID: ai},
		)

		at, _ := NewAccessToken("tok")
		_, _, err := verifier.Verify(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("session_not_found", func(t *testing.T) {
		user := newActiveUser()
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		verifier := NewVerifyAccess(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByIDResult: nil},
			&stubAccessService{validateID: ai},
		)

		at, _ := NewAccessToken("tok")
		_, _, err := verifier.Verify(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("session_revoked", func(t *testing.T) {
		user := newActiveUser()
		revokedSession := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, true)
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		verifier := NewVerifyAccess(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByIDResult: revokedSession},
			&stubAccessService{validateID: ai},
		)

		at, _ := NewAccessToken("tok")
		_, _, err := verifier.Verify(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrSessionExpired)
	})

	t.Run("session_expired", func(t *testing.T) {
		user := newActiveUser()
		expiredSession := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testPast, testPast, false)
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []RoleName{ReconstituteRoleName("member")}, nil)
		verifier := NewVerifyAccess(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByIDResult: expiredSession},
			&stubAccessService{validateID: ai},
		)

		at, _ := NewAccessToken("tok")
		_, _, err := verifier.Verify(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrSessionExpired)
	})
}
