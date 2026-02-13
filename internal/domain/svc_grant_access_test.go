package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubResolvePermissions struct {
	result []Permission
}

func (s *stubResolvePermissions) Resolve(_ []*Role) []Permission {
	return s.result
}

func TestGrantAccess_Grant(t *testing.T) {
	user := newActiveUser()
	sid := validSessionID()
	var roles []*Role

	t.Run("happy_path", func(t *testing.T) {
		at, _ := NewAccessToken("access-tok")
		granter := NewGrantAccess(
			&stubResolvePermissions{},
			&stubAccessService{issueToken: at, issueExpiry: testFuture},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		tok, exp, err := granter.Grant(user, sid, roles, testNow)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", tok.String())
		assert.True(t, exp.Equal(testFuture))
	})

	t.Run("issue_fails", func(t *testing.T) {
		granter := NewGrantAccess(
			&stubResolvePermissions{},
			&stubAccessService{issueErr: errors.New("jwt error")},
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		_, _, err := granter.Grant(user, sid, roles, testNow)
		assert.Error(t, err)
	})

	t.Run("ttl_calculation_correct", func(t *testing.T) {
		lifetime := 30 * time.Minute

		accessSvc := &captureAccessService{}
		granter := NewGrantAccess(
			&stubResolvePermissions{},
			accessSvc,
			NewAccessPolicy(AccessPolicyConfig{Lifetime: lifetime}),
		)

		_, _, _ = granter.Grant(user, sid, roles, testNow)
		capturedIssuedAt := accessSvc.capturedIssuedAt
		capturedExpiresAt := accessSvc.capturedExpiresAt
		expectedExpiry := testNow.Add(lifetime)
		assert.True(t, capturedIssuedAt.Equal(testNow))
		assert.True(t, capturedExpiresAt.Equal(expectedExpiry))
	})

	t.Run("permissions_resolved_from_roles", func(t *testing.T) {
		accessSvc := &captureAccessService{}
		granter := NewGrantAccess(
			&stubResolvePermissions{result: []Permission{
				ReconstitutePermission("users", "read_self"),
				ReconstitutePermission("content", "read"),
			}},
			accessSvc,
			NewAccessPolicy(AccessPolicyConfig{Lifetime: 15 * time.Minute}),
		)

		_, _, _ = granter.Grant(user, sid, roles, testNow)
		assert.Len(t, accessSvc.capturedPermissions, 2)
		assert.Equal(t, "users:read_self", accessSvc.capturedPermissions[0].String())
		assert.Equal(t, "content:read", accessSvc.capturedPermissions[1].String())
	})
}

type captureAccessService struct {
	capturedIssuedAt    time.Time
	capturedExpiresAt   time.Time
	capturedPermissions []Permission
}

func (s *captureAccessService) Issue(_ UserID, _ Email, _ SessionID, _ []RoleName, permissions []Permission, issuedAt, expiresAt, _ time.Time) (AccessToken, time.Time, error) {
	s.capturedIssuedAt = issuedAt
	s.capturedExpiresAt = expiresAt
	s.capturedPermissions = permissions
	at, _ := NewAccessToken("tok")
	return at, expiresAt, nil
}

func (s *captureAccessService) Validate(_ AccessToken) (AccessIdentity, error) {
	return ZeroAccessIdentity, nil
}
