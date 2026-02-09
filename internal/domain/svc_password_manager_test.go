package domain

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordManager_ValidateAndHash(t *testing.T) {
	validRaw, _ := NewRawPassword("Str0ng!Pass")

	t.Run("policy_passes_hash_ok", func(t *testing.T) {
		policy := NewPasswordPolicy(PasswordPolicyConfig{MinLength: 1, MaxLength: 255})
		svc := &stubPasswordService{hashResult: ReconstituteHashedPassword("hashed"), hashErr: nil}
		mgr := NewPasswordManager(svc, policy)

		h, err := mgr.ValidateAndHashNewPassword(validRaw)
		require.NoError(t, err)
		assert.Equal(t, "hashed", h.String())
	})

	t.Run("policy_fails", func(t *testing.T) {
		policy := NewPasswordPolicy(PasswordPolicyConfig{MinLength: 100, MaxLength: 255})
		svc := &stubPasswordService{}
		mgr := NewPasswordManager(svc, policy)

		_, err := mgr.ValidateAndHashNewPassword(validRaw)
		assert.ErrorIs(t, err, ErrPasswordTooShort)
	})

	t.Run("hash_fails", func(t *testing.T) {
		policy := NewPasswordPolicy(PasswordPolicyConfig{MinLength: 1, MaxLength: 255})
		hashErr := errors.New("hash failure")
		svc := &stubPasswordService{hashErr: hashErr}
		mgr := NewPasswordManager(svc, policy)

		_, err := mgr.ValidateAndHashNewPassword(validRaw)
		assert.ErrorIs(t, err, hashErr)
	})
}

func TestPasswordManager_Compare(t *testing.T) {
	t.Run("delegates", func(t *testing.T) {
		svc := &stubPasswordService{compareOut: true}
		policy := NewPasswordPolicy(PasswordPolicyConfig{MinLength: 1, MaxLength: 255})
		mgr := NewPasswordManager(svc, policy)

		raw, _ := NewRawPassword("any")
		assert.True(t, mgr.Compare(raw, validHashedPassword()))
	})

	t.Run("mismatch", func(t *testing.T) {
		svc := &stubPasswordService{compareOut: false}
		policy := NewPasswordPolicy(PasswordPolicyConfig{MinLength: 1, MaxLength: 255})
		mgr := NewPasswordManager(svc, policy)

		raw, _ := NewRawPassword("any")
		assert.False(t, mgr.Compare(raw, validHashedPassword()))
	})
}
