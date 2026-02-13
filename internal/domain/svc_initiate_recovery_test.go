package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitiateRecovery_Initiate(t *testing.T) {
	makeInitiator := func(tokenGenErr, hashErr, idGenErr error) IInitiateRecovery {
		return NewInitiateRecovery(
			&stubTokenService{
				generateToken:   validRawToken(),
				generateErr:     tokenGenErr,
				hashRecoveryOut: ReconstituteRecoveryTokenHash("recovery-hash"),
				hashRecoveryErr: hashErr,
			},
			&stubIDGenerator{
				recoveryID:    ReconstituteRecoveryTokenID("rec-001"),
				recoveryIDErr: idGenErr,
			},
			&stubRecoveryPolicy{lifetime: 15 * time.Minute},
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		initiator := makeInitiator(nil, nil, nil)
		user := newActiveUser()

		rawTok, recovery, err := initiator.Initiate(user, testNow)
		require.NoError(t, err)
		assert.NotEmpty(t, rawTok)
		assert.NotNil(t, recovery)
		assert.Equal(t, user.ID(), recovery.UserID())

		events := recovery.CollectEvents()
		assertEventRecorded(t, events, "PasswordResetRequested")
	})

	t.Run("user_inactive", func(t *testing.T) {
		initiator := makeInitiator(nil, nil, nil)
		user := newInactiveUser()

		_, _, err := initiator.Initiate(user, testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("token_gen_fails", func(t *testing.T) {
		initiator := makeInitiator(errors.New("token gen"), nil, nil)
		user := newActiveUser()

		_, _, err := initiator.Initiate(user, testNow)
		assert.Error(t, err)
	})

	t.Run("hash_fails", func(t *testing.T) {
		initiator := makeInitiator(nil, errors.New("hash err"), nil)
		user := newActiveUser()

		_, _, err := initiator.Initiate(user, testNow)
		assert.Error(t, err)
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		initiator := makeInitiator(nil, nil, errors.New("id gen"))
		user := newActiveUser()

		_, _, err := initiator.Initiate(user, testNow)
		assert.Error(t, err)
	})
}
