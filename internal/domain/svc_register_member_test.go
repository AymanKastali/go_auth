package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterMember_Register(t *testing.T) {
	uid := validUserID()
	email := validEmail()
	hash := validHashedPassword()
	defaultRole := ReconstituteRoleName("member")

	t.Run("happy_path", func(t *testing.T) {
		policy := &stubRegisterPolicy{}
		svc := NewRegisterMember(policy, &stubActivationPolicy{})

		user, err := svc.Register(uid, email, hash, defaultRole, testNow)
		require.NoError(t, err)
		assert.True(t, user.IsActive())
		assert.Contains(t, user.RoleNames(), "member")

		events := user.CollectEvents()
		assertEventRecorded(t, events, "UserRegistered")
		assertEventRecorded(t, events, "RoleAssigned")
		assertEventNotRecorded(t, events, "UserActivated")
	})

	t.Run("policy_rejects", func(t *testing.T) {
		policy := &stubRegisterPolicy{err: ErrRegistrationDisabled}
		svc := NewRegisterMember(policy, &stubActivationPolicy{})

		_, err := svc.Register(uid, email, hash, defaultRole, testNow)
		assert.ErrorIs(t, err, ErrRegistrationDisabled)
	})

	t.Run("activation_required_deactivates_user", func(t *testing.T) {
		policy := &stubRegisterPolicy{}
		svc := NewRegisterMember(policy, &stubActivationPolicy{requireEmail: true})

		user, err := svc.Register(uid, email, hash, defaultRole, testNow)
		require.NoError(t, err)
		assert.False(t, user.IsActive())
	})
}
