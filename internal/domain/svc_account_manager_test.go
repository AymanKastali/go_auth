package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserAccountManager_InitiatePasswordReset(t *testing.T) {
	makeManager := func(tokenGenErr, hashErr, idGenErr error) IUserAccountManager {
		return NewUserAccountManager(
			&stubTokenService{
				generateToken:   validRawToken(),
				generateErr:     tokenGenErr,
				hashRecoveryOut: ReconstituteRecoveryTokenHash("recovery-hash"),
				hashRecoveryErr: hashErr,
			},
			&stubPasswordManager{},
			&stubIDGenerator{
				recoveryID:    ReconstituteRecoveryTokenID("rec-001"),
				recoveryIDErr: idGenErr,
			},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		mgr := makeManager(nil, nil, nil)
		user := newActiveUser()

		rawTok, recovery, err := mgr.InitiatePasswordReset(user, testNow)
		require.NoError(t, err)
		assert.False(t, rawTok.IsEmpty())
		assert.NotNil(t, recovery)
		assert.Equal(t, user.ID(), recovery.UserID())

		events := recovery.CollectEvents()
		assertEventRecorded(t, events, "PasswordResetRequested")
	})

	t.Run("user_inactive", func(t *testing.T) {
		mgr := makeManager(nil, nil, nil)
		user := newInactiveUser()

		_, _, err := mgr.InitiatePasswordReset(user, testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("token_gen_fails", func(t *testing.T) {
		mgr := makeManager(errors.New("token gen"), nil, nil)
		user := newActiveUser()

		_, _, err := mgr.InitiatePasswordReset(user, testNow)
		assert.Error(t, err)
	})

	t.Run("hash_fails", func(t *testing.T) {
		mgr := makeManager(nil, errors.New("hash err"), nil)
		user := newActiveUser()

		_, _, err := mgr.InitiatePasswordReset(user, testNow)
		assert.Error(t, err)
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		mgr := makeManager(nil, nil, errors.New("id gen"))
		user := newActiveUser()

		_, _, err := mgr.InitiatePasswordReset(user, testNow)
		assert.Error(t, err)
	})
}

func TestUserAccountManager_ChangePassword(t *testing.T) {
	makeManager := func(compareOut bool, validateErr error) IUserAccountManager {
		return NewUserAccountManager(
			&stubTokenService{},
			&stubPasswordManager{
				compareOut:         compareOut,
				validateHashResult: ReconstituteHashedPassword("new-hash"),
				validateHashErr:    validateErr,
			},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		mgr := makeManager(true, nil)
		user := newActiveUser()
		old, _ := NewRawPassword("oldpass")
		new_, _ := NewRawPassword("newpass")

		err := mgr.ChangePassword(user, old, new_, testNow)
		require.NoError(t, err)
		assert.Equal(t, "new-hash", user.HashedPassword().String())
	})

	t.Run("wrong_old_password", func(t *testing.T) {
		mgr := makeManager(false, nil)
		user := newActiveUser()
		old, _ := NewRawPassword("wrong")
		new_, _ := NewRawPassword("newpass")

		err := mgr.ChangePassword(user, old, new_, testNow)
		assert.ErrorIs(t, err, ErrAuthenticationFailed)
	})

	t.Run("new_password_policy_fails", func(t *testing.T) {
		mgr := makeManager(true, ErrPasswordTooShort)
		user := newActiveUser()
		old, _ := NewRawPassword("oldpass")
		new_, _ := NewRawPassword("s")

		err := mgr.ChangePassword(user, old, new_, testNow)
		assert.ErrorIs(t, err, ErrPasswordTooShort)
	})
}

func TestUserAccountManager_ResetPasswordByToken(t *testing.T) {
	recID := ReconstituteRecoveryTokenID("rec-001")
	recHash := ReconstituteRecoveryTokenHash("recovery-hash")

	t.Run("happy_path", func(t *testing.T) {
		user := newActiveUser()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, false)

		mgr := NewUserAccountManager(
			&stubTokenService{},
			&stubPasswordManager{
				validateHashResult: ReconstituteHashedPassword("new-hash"),
			},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		newPwd, _ := NewRawPassword("NewPass1!")
		err := mgr.ResetPasswordByToken(user, recovery, newPwd, testNow)
		require.NoError(t, err)
		assert.True(t, recovery.IsUsed())
		assert.Equal(t, "new-hash", user.HashedPassword().String())
	})

	t.Run("recovery_expired", func(t *testing.T) {
		user := newActiveUser()
		// Token expired in the past
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testPast, false)

		mgr := NewUserAccountManager(
			&stubTokenService{},
			&stubPasswordManager{},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(user, recovery, newPwd, testNow)
		assert.ErrorIs(t, err, ErrRecoveryTokenInvalid)
	})

	t.Run("recovery_already_used", func(t *testing.T) {
		user := newActiveUser()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, true)

		mgr := NewUserAccountManager(
			&stubTokenService{},
			&stubPasswordManager{},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(user, recovery, newPwd, testNow)
		assert.ErrorIs(t, err, ErrRecoveryTokenInvalid)
	})

	t.Run("user_id_mismatch", func(t *testing.T) {
		user := newActiveUser()
		otherUserID := ReconstituteUserID("other-user")
		recovery := ReconstituteRecoveryToken(recID, otherUserID, recHash, testFuture, false)

		mgr := NewUserAccountManager(
			&stubTokenService{},
			&stubPasswordManager{},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(user, recovery, newPwd, testNow)
		assert.ErrorIs(t, err, ErrInvalidRecoveryAttempt)
	})

	t.Run("password_policy_fails", func(t *testing.T) {
		user := newActiveUser()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, false)

		mgr := NewUserAccountManager(
			&stubTokenService{},
			&stubPasswordManager{validateHashErr: ErrPasswordTooShort},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		newPwd, _ := NewRawPassword("s")
		err := mgr.ResetPasswordByToken(user, recovery, newPwd, testNow)
		assert.ErrorIs(t, err, ErrPasswordTooShort)
	})
}
