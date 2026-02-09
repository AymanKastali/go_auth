package domain

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubRegistrationRoleProvider struct {
	memberRole    RoleName
	memberRoleErr error
	adminRole     RoleName
	adminRoleErr  error
}

func (s *stubRegistrationRoleProvider) DefaultMemberRole(_ context.Context) (RoleName, error) {
	return s.memberRole, s.memberRoleErr
}
func (s *stubRegistrationRoleProvider) DefaultAdminRole(_ context.Context) (RoleName, error) {
	return s.adminRole, s.adminRoleErr
}

func defaultRoleProvider() *stubRegistrationRoleProvider {
	return &stubRegistrationRoleProvider{
		memberRole: ReconstituteRoleName("member"),
		adminRole:  ReconstituteRoleName("super_admin"),
	}
}

func TestRegistrationService_RegisterNewMember(t *testing.T) {
	ctx := context.Background()
	uid := validUserID()
	email := validEmail()
	hash := validHashedPassword()

	t.Run("happy_path", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: nil}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, defaultRoleProvider(), policy, &stubActivationPolicy{})

		user, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		require.NoError(t, err)
		assert.True(t, user.IsActive())
		assert.Contains(t, user.RoleNames(), "member")

		events := user.CollectEvents()
		assertEventRecorded(t, events, "UserRegistered")
		assertEventRecorded(t, events, "RoleAssigned")
		assertEventNotRecorded(t, events, "UserActivated")
	})

	t.Run("policy_rejects", func(t *testing.T) {
		repo := &stubUserRepository{}
		policy := &stubRegisterPolicy{err: ErrRegistrationDisabled}
		svc := NewRegistrationService(repo, defaultRoleProvider(), policy, &stubActivationPolicy{})

		_, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrRegistrationDisabled)
	})

	t.Run("email_taken", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: newActiveUser()}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, defaultRoleProvider(), policy, &stubActivationPolicy{})

		_, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrUserEmailTaken)
	})

	t.Run("repo_error", func(t *testing.T) {
		repoErr := errors.New("db down")
		repo := &stubUserRepository{findByEmailErr: repoErr}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, defaultRoleProvider(), policy, &stubActivationPolicy{})

		_, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, repoErr)
	})

	t.Run("role_provider_error_propagates", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: nil}
		policy := &stubRegisterPolicy{}
		provider := &stubRegistrationRoleProvider{memberRoleErr: ErrRoleNotFound}
		svc := NewRegistrationService(repo, provider, policy, &stubActivationPolicy{})

		_, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrRoleNotFound)
	})
}

func TestRegistrationService_RegisterNewSuperAdmin(t *testing.T) {
	ctx := context.Background()
	uid := validUserID()
	email := validEmail()
	hash := validHashedPassword()

	t.Run("happy_path", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: nil}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, defaultRoleProvider(), policy, &stubActivationPolicy{})

		user, err := svc.RegisterNewSuperAdmin(ctx, uid, email, hash, testNow)
		require.NoError(t, err)
		assert.True(t, user.IsActive())
		assert.Contains(t, user.RoleNames(), "super_admin")
	})

	t.Run("email_taken", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: newActiveUser()}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, defaultRoleProvider(), policy, &stubActivationPolicy{})

		_, err := svc.RegisterNewSuperAdmin(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrUserEmailTaken)
	})

	t.Run("role_provider_error_propagates", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: nil}
		policy := &stubRegisterPolicy{}
		provider := &stubRegistrationRoleProvider{
			memberRole:   ReconstituteRoleName("member"),
			adminRoleErr: ErrRoleNotFound,
		}
		svc := NewRegistrationService(repo, provider, policy, &stubActivationPolicy{})

		_, err := svc.RegisterNewSuperAdmin(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrRoleNotFound)
	})
}
