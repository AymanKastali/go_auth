package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshSession_Refresh(t *testing.T) {
	newGeneratedToken := "new-generated-token"

	t.Run("happy_path", func(t *testing.T) {
		session := newActiveSession()
		svc := NewRefreshSession(
			&stubTokenService{
				generateToken: newGeneratedToken,
				hashSessionOut: ReconstituteHashedToken("new-hashed-token"),
			},
			&stubSessionPolicy{lifetime: 24 * time.Hour, maxActive: 5},
		)

		fp := validDeviceIdentity().Fingerprint()
		rawTok, err := svc.Refresh(session, false, fp, testNow)
		require.NoError(t, err)
		assert.NotEmpty(t, rawTok)
	})

	t.Run("token_reuse_detected", func(t *testing.T) {
		session := newActiveSession()
		svc := NewRefreshSession(
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubSessionPolicy{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, err := svc.Refresh(session, true, fp, testNow)
		assert.ErrorIs(t, err, ErrSessionTokenReuse)
		assert.True(t, session.IsRevoked())
	})

	t.Run("token_reuse_already_revoked_returns_not_found", func(t *testing.T) {
		session := ReconstituteSession(validSessionID(), validUserID(), validHashedToken(), ZeroHashedToken, validDeviceIdentity(), testFuture, testNow, true)
		svc := NewRefreshSession(
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubSessionPolicy{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, err := svc.Refresh(session, true, fp, testNow)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("fingerprint_mismatch_propagated", func(t *testing.T) {
		session := newActiveSession()
		svc := NewRefreshSession(
			&stubTokenService{
				generateToken:  newGeneratedToken,
				hashSessionOut: ReconstituteHashedToken("new-hashed-token"),
			},
			&stubSessionPolicy{lifetime: 24 * time.Hour},
		)

		wrongFP := differentDeviceIdentity().Fingerprint()
		_, err := svc.Refresh(session, false, wrongFP, testNow)
		assert.ErrorIs(t, err, ErrSessionFingerprintMiss)
	})
}
