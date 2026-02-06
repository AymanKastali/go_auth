package domain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessManager_GrantImmediateAccess(t *testing.T) {
	user := newActiveUserWithSession()
	sid := validSessionID()

	t.Run("happy_path", func(t *testing.T) {
		at, _ := NewAccessToken("access-tok")
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubAccessService{issueToken: at, issueExpiry: testFuture},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		tok, exp, err := mgr.GrantImmediateAccess(user, sid, testNow)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", tok.String())
		assert.True(t, exp.Equal(testFuture))
	})

	t.Run("issue_fails", func(t *testing.T) {
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubAccessService{issueErr: errors.New("jwt error")},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		_, _, err := mgr.GrantImmediateAccess(user, sid, testNow)
		assert.Error(t, err)
	})

	t.Run("ttl_calculation_correct", func(t *testing.T) {
		lifetime := 30 * time.Minute
		var capturedIssuedAt, capturedExpiresAt Timepoint

		accessSvc := &captureAccessService{}
		mgr := NewAccessManager(
			&stubUserRepository{},
			accessSvc,
			NewAccessPolicy(AccessPolicyConfig{Lifetime: lifetime}),
		)

		_, _, _ = mgr.GrantImmediateAccess(user, sid, testNow)
		capturedIssuedAt = accessSvc.capturedIssuedAt
		capturedExpiresAt = accessSvc.capturedExpiresAt
		expectedExpiry := testNow.Add(lifetime)
		assert.True(t, capturedIssuedAt.Equal(testNow))
		assert.True(t, capturedExpiresAt.Equal(expectedExpiry))
	})
}

// captureAccessService records arguments passed to Issue for inspection.
type captureAccessService struct {
	capturedIssuedAt  Timepoint
	capturedExpiresAt Timepoint
}

func (s *captureAccessService) Issue(_ UserID, _ Email, _ SessionID, _ []Role, issuedAt, expiresAt, _ Timepoint) (AccessToken, Timepoint, error) {
	s.capturedIssuedAt = issuedAt
	s.capturedExpiresAt = expiresAt
	at, _ := NewAccessToken("tok")
	return at, expiresAt, nil
}

func (s *captureAccessService) Validate(_ AccessToken) (AccessIdentity, error) {
	return ZeroAccessIdentity, nil
}

func TestAccessManager_VerifyAccess(t *testing.T) {
	ctx := context.Background()
	user := newActiveUserWithSession()

	t.Run("happy_path", func(t *testing.T) {
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []Role{RoleMember})
		mgr := NewAccessManager(
			&stubUserRepository{findByIDResult: user},
			&stubAccessService{validateID: ai},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("tok")
		u, sid, err := mgr.VerifyAccess(ctx, at, testNow)
		require.NoError(t, err)
		assert.Equal(t, validUserID(), u.ID())
		assert.Equal(t, validSessionID(), sid)
	})

	t.Run("token_invalid", func(t *testing.T) {
		mgr := NewAccessManager(
			&stubUserRepository{},
			&stubAccessService{validateErr: ErrTokenInvalid},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("bad")
		_, _, err := mgr.VerifyAccess(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrTokenInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []Role{RoleMember})
		mgr := NewAccessManager(
			&stubUserRepository{findByIDResult: nil},
			&stubAccessService{validateID: ai},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("tok")
		_, _, err := mgr.VerifyAccess(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("integrity_fails", func(t *testing.T) {
		// User with revoked session
		revokedAt := testPast
		revokedUser := ReconstituteUser(
			validUserID(), validEmail(), validHashedPassword(),
			true, []Role{RoleMember},
			[]Session{
				ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, &revokedAt),
			},
			false,
		)
		ai, _ := NewAccessIdentity(validUserID(), validSessionID(), validEmail(), []Role{RoleMember})
		mgr := NewAccessManager(
			&stubUserRepository{findByIDResult: revokedUser},
			&stubAccessService{validateID: ai},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		at, _ := NewAccessToken("tok")
		_, _, err := mgr.VerifyAccess(ctx, at, testNow)
		assert.ErrorIs(t, err, ErrSessionAlreadyRevoked)
	})
}
