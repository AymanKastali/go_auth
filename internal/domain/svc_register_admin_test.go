package domain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterAdmin_Register(t *testing.T) {
	ctx := context.Background()
	uid := validUserID()
	email := validEmail()
	hash := validHashedPassword()

	t.Run("happy_path", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: nil}
		policy := &stubRegisterPolicy{}
		svc := NewRegisterAdmin(repo, defaultRoleProvider(), policy)

		user, err := svc.Register(ctx, uid, email, hash, testNow)
		require.NoError(t, err)
		assert.True(t, user.IsActive())
		assert.Contains(t, user.RoleNames(), "super_admin")
	})

	t.Run("email_taken", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: newActiveUser()}
		policy := &stubRegisterPolicy{}
		svc := NewRegisterAdmin(repo, defaultRoleProvider(), policy)

		_, err := svc.Register(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrUserEmailTaken)
	})

	t.Run("role_provider_error_propagates", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: nil}
		policy := &stubRegisterPolicy{}
		provider := &stubRegistrationRoleProvider{
			memberRole:   ReconstituteRoleName("member"),
			adminRoleErr: ErrRoleNotFound,
		}
		svc := NewRegisterAdmin(repo, provider, policy)

		_, err := svc.Register(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrRoleNotFound)
	})
}
