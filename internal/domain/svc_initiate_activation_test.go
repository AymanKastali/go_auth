package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitiateActivation_Initiate(t *testing.T) {
	makeInitiator := func(tokenGenErr, hashErr, idGenErr error) IInitiateActivation {
		ts := &stubTokenService{
			generateToken: validRawToken(),
			generateErr:   tokenGenErr,
		}
		idGen := &stubIDGenerator{}
		if hashErr != nil {
			ts = &stubTokenService{
				generateToken: validRawToken(),
				generateErr:   tokenGenErr,
			}
		}
		if idGenErr != nil {
			idGen = &stubIDGenerator{}
		}
		return NewInitiateActivation(
			ts,
			idGen,
			&stubActivationPolicy{tokenLifetime: 24 * time.Hour},
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		initiator := makeInitiator(nil, nil, nil)
		user := newActiveUser()

		rawTok, activation, err := initiator.Initiate(user, testNow)
		require.NoError(t, err)
		assert.NotEmpty(t, rawTok)
		assert.NotNil(t, activation)
		assert.Equal(t, user.ID(), activation.UserID())
	})

	t.Run("token_gen_fails", func(t *testing.T) {
		initiator := makeInitiator(errors.New("token gen"), nil, nil)
		user := newActiveUser()

		_, _, err := initiator.Initiate(user, testNow)
		assert.Error(t, err)
	})
}
