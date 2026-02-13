package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChangePassword_Change(t *testing.T) {
	makeChanger := func(compareOut bool, hashResult HashedPassword, hashErr error) IChangePassword {
		return NewChangePassword(
			&stubPasswordService{
				compareOut: compareOut,
				hashResult: hashResult,
				hashErr:    hashErr,
			},
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		changer := makeChanger(true, ReconstituteHashedPassword("new-hash"), nil)
		user := newActiveUser()

		err := changer.Change(user, "oldpass", ReconstituteValidatedPassword("newpass"), testNow)
		require.NoError(t, err)
		assert.Equal(t, "new-hash", user.HashedPassword().String())
	})

	t.Run("wrong_old_password", func(t *testing.T) {
		changer := makeChanger(false, ZeroHashedPassword, nil)
		user := newActiveUser()

		err := changer.Change(user, "wrong", ReconstituteValidatedPassword("newpass"), testNow)
		assert.ErrorIs(t, err, ErrAuthenticationFailed)
	})

	t.Run("hash_fails", func(t *testing.T) {
		changer := makeChanger(true, ZeroHashedPassword, ErrInternal)
		user := newActiveUser()

		err := changer.Change(user, "oldpass", ReconstituteValidatedPassword("newpass"), testNow)
		assert.ErrorIs(t, err, ErrInternal)
	})
}
