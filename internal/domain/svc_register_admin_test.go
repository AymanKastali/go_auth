package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAdmin_Register(t *testing.T) {
	uid := validUserID()
	email := validEmail()
	hash := validHashedPassword()
	defaultRole := ReconstituteRoleName("super_admin")

	t.Run("happy_path", func(t *testing.T) {
		policy := &stubRegisterPolicy{}
		svc := NewRegisterAdmin(policy)

		user, err := svc.Register(uid, email, hash, defaultRole, testNow)
		require.NoError(t, err)
		assert.True(t, user.IsActive())
		assert.Contains(t, user.RoleNames(), "super_admin")
	})

	t.Run("policy_rejects", func(t *testing.T) {
		policy := &stubRegisterPolicy{err: ErrRegistrationDisabled}
		svc := NewRegisterAdmin(policy)

		_, err := svc.Register(uid, email, hash, defaultRole, testNow)
		assert.ErrorIs(t, err, ErrRegistrationDisabled)
	})
}
