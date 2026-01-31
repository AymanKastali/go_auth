package domain

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistrationService_RegisterNewMember(t *testing.T) {
	ctx := context.Background()
	uid := validUserID()
	email := validEmail()
	hash := validHashedPassword()

	t.Run("happy_path", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: nil}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, policy)

		user, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		require.NoError(t, err)
		assert.True(t, user.IsActive())
		assert.Contains(t, user.RoleNames(), "member")

		events := user.CollectEvents()
		assertEventRecorded(t, events, "UserRegistered")
		assertEventRecorded(t, events, "RoleAssigned")
		assertEventRecorded(t, events, "UserActivated")
	})

	t.Run("policy_rejects", func(t *testing.T) {
		repo := &stubUserRepository{}
		policy := &stubRegisterPolicy{err: ErrRegistrationDisabled}
		svc := NewRegistrationService(repo, policy)

		_, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrRegistrationDisabled)
	})

	t.Run("email_taken", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: newActiveUserWithSession()}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, policy)

		_, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrUserEmailTaken)
	})

	t.Run("repo_error", func(t *testing.T) {
		repoErr := errors.New("db down")
		repo := &stubUserRepository{findByEmailErr: repoErr}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, policy)

		_, err := svc.RegisterNewMember(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, repoErr)
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
		svc := NewRegistrationService(repo, policy)

		user, err := svc.RegisterNewSuperAdmin(ctx, uid, email, hash, testNow)
		require.NoError(t, err)
		assert.True(t, user.IsActive())
		assert.Contains(t, user.RoleNames(), "admin")
	})

	t.Run("email_taken", func(t *testing.T) {
		repo := &stubUserRepository{findByEmailResult: newActiveUserWithSession()}
		policy := &stubRegisterPolicy{}
		svc := NewRegistrationService(repo, policy)

		_, err := svc.RegisterNewSuperAdmin(ctx, uid, email, hash, testNow)
		assert.ErrorIs(t, err, ErrUserEmailTaken)
	})
}
