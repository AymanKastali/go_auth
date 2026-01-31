package domain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserAccountManager_InitiatePasswordReset(t *testing.T) {
	ctx := context.Background()

	makeManager := func(tokenGenErr, hashErr, idGenErr error) IUserAccountManager {
		return NewUserAccountManager(
			&stubUserRepository{},
			&stubRecoveryTokenRepository{},
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
		user := newActiveUserWithSession()

		rawTok, recovery, err := mgr.InitiatePasswordReset(ctx, user, testNow)
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

		_, _, err := mgr.InitiatePasswordReset(ctx, user, testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("token_gen_fails", func(t *testing.T) {
		mgr := makeManager(errors.New("token gen"), nil, nil)
		user := newActiveUserWithSession()

		_, _, err := mgr.InitiatePasswordReset(ctx, user, testNow)
		assert.Error(t, err)
	})

	t.Run("hash_fails", func(t *testing.T) {
		mgr := makeManager(nil, errors.New("hash err"), nil)
		user := newActiveUserWithSession()

		_, _, err := mgr.InitiatePasswordReset(ctx, user, testNow)
		assert.Error(t, err)
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		mgr := makeManager(nil, nil, errors.New("id gen"))
		user := newActiveUserWithSession()

		_, _, err := mgr.InitiatePasswordReset(ctx, user, testNow)
		assert.Error(t, err)
	})
}

func TestUserAccountManager_ChangePassword(t *testing.T) {
	ctx := context.Background()

	makeManager := func(compareOut bool, validateErr error) IUserAccountManager {
		return NewUserAccountManager(
			&stubUserRepository{},
			&stubRecoveryTokenRepository{},
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
		user := newActiveUserWithSession()
		old, _ := NewRawPassword("oldpass")
		new_, _ := NewRawPassword("newpass")

		err := mgr.ChangePassword(ctx, user, old, new_, testNow)
		require.NoError(t, err)
		assert.Equal(t, "new-hash", user.HashedPassword().String())
	})

	t.Run("wrong_old_password", func(t *testing.T) {
		mgr := makeManager(false, nil)
		user := newActiveUserWithSession()
		old, _ := NewRawPassword("wrong")
		new_, _ := NewRawPassword("newpass")

		err := mgr.ChangePassword(ctx, user, old, new_, testNow)
		assert.ErrorIs(t, err, ErrAuthenticationFailed)
	})

	t.Run("new_password_policy_fails", func(t *testing.T) {
		mgr := makeManager(true, ErrPasswordTooShort)
		user := newActiveUserWithSession()
		old, _ := NewRawPassword("oldpass")
		new_, _ := NewRawPassword("s")

		err := mgr.ChangePassword(ctx, user, old, new_, testNow)
		assert.ErrorIs(t, err, ErrPasswordTooShort)
	})
}

func TestUserAccountManager_ResetPasswordByToken(t *testing.T) {
	ctx := context.Background()
	recID := ReconstituteRecoveryTokenID("rec-001")
	recHash := ReconstituteRecoveryTokenHash("recovery-hash")

	t.Run("happy_path", func(t *testing.T) {
		user := newActiveUserWithSession()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, testPast, nil)

		mgr := NewUserAccountManager(
			&stubUserRepository{findByIDResult: user},
			&stubRecoveryTokenRepository{findByHashResult: recovery},
			&stubTokenService{hashRecoveryOut: recHash},
			&stubPasswordManager{
				validateHashResult: ReconstituteHashedPassword("new-hash"),
			},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		raw, _ := NewRawToken("tok")
		newPwd, _ := NewRawPassword("NewPass1!")
		err := mgr.ResetPasswordByToken(ctx, raw, newPwd, testNow)
		require.NoError(t, err)
		assert.True(t, recovery.IsUsed())
		assert.Equal(t, "new-hash", user.HashedPassword().String())
	})

	t.Run("hash_fails", func(t *testing.T) {
		mgr := NewUserAccountManager(
			&stubUserRepository{},
			&stubRecoveryTokenRepository{},
			&stubTokenService{hashRecoveryErr: errors.New("hash err")},
			&stubPasswordManager{},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		raw, _ := NewRawToken("tok")
		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(ctx, raw, newPwd, testNow)
		assert.Error(t, err)
	})

	t.Run("recovery_not_found", func(t *testing.T) {
		mgr := NewUserAccountManager(
			&stubUserRepository{},
			&stubRecoveryTokenRepository{findByHashResult: nil},
			&stubTokenService{hashRecoveryOut: recHash},
			&stubPasswordManager{},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		raw, _ := NewRawToken("tok")
		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(ctx, raw, newPwd, testNow)
		assert.ErrorIs(t, err, ErrRecoveryTokenInvalid)
	})

	t.Run("recovery_invalid_used", func(t *testing.T) {
		usedAt := testPast
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, testPast, &usedAt)

		mgr := NewUserAccountManager(
			&stubUserRepository{},
			&stubRecoveryTokenRepository{findByHashResult: recovery},
			&stubTokenService{hashRecoveryOut: recHash},
			&stubPasswordManager{},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		raw, _ := NewRawToken("tok")
		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(ctx, raw, newPwd, testNow)
		assert.ErrorIs(t, err, ErrRecoveryTokenInvalid)
	})

	t.Run("user_not_found", func(t *testing.T) {
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, testPast, nil)

		mgr := NewUserAccountManager(
			&stubUserRepository{findByIDResult: nil},
			&stubRecoveryTokenRepository{findByHashResult: recovery},
			&stubTokenService{hashRecoveryOut: recHash},
			&stubPasswordManager{},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		raw, _ := NewRawToken("tok")
		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(ctx, raw, newPwd, testNow)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("password_policy_fails", func(t *testing.T) {
		user := newActiveUserWithSession()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, testPast, nil)

		mgr := NewUserAccountManager(
			&stubUserRepository{findByIDResult: user},
			&stubRecoveryTokenRepository{findByHashResult: recovery},
			&stubTokenService{hashRecoveryOut: recHash},
			&stubPasswordManager{validateHashErr: ErrPasswordTooShort},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		raw, _ := NewRawToken("tok")
		newPwd, _ := NewRawPassword("s")
		err := mgr.ResetPasswordByToken(ctx, raw, newPwd, testNow)
		assert.ErrorIs(t, err, ErrPasswordTooShort)
	})

	t.Run("user_save_fails", func(t *testing.T) {
		user := newActiveUserWithSession()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, testPast, nil)

		mgr := NewUserAccountManager(
			&stubUserRepository{findByIDResult: user, saveErr: errors.New("save err")},
			&stubRecoveryTokenRepository{findByHashResult: recovery},
			&stubTokenService{hashRecoveryOut: recHash},
			&stubPasswordManager{validateHashResult: ReconstituteHashedPassword("new")},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		raw, _ := NewRawToken("tok")
		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(ctx, raw, newPwd, testNow)
		assert.Error(t, err)
	})

	t.Run("recovery_save_fails", func(t *testing.T) {
		user := newActiveUserWithSession()
		recovery := ReconstituteRecoveryToken(recID, validUserID(), recHash, testFuture, testPast, nil)

		mgr := NewUserAccountManager(
			&stubUserRepository{findByIDResult: user},
			&stubRecoveryTokenRepository{findByHashResult: recovery, saveErr: errors.New("save err")},
			&stubTokenService{hashRecoveryOut: recHash},
			&stubPasswordManager{validateHashResult: ReconstituteHashedPassword("new")},
			&stubIDGenerator{},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)

		raw, _ := NewRawToken("tok")
		newPwd, _ := NewRawPassword("pass")
		err := mgr.ResetPasswordByToken(ctx, raw, newPwd, testNow)
		assert.Error(t, err)
	})
}
