package domain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenSession_Open(t *testing.T) {
	ctx := context.Background()

	makeOpener := func(sessionRepo *stubSessionRepository, idGenErr, tokenGenErr, hashErr error) IOpenSession {
		if sessionRepo == nil {
			sessionRepo = &stubSessionRepository{}
		}
		return NewOpenSession(
			sessionRepo,
			&stubTokenService{
				generateToken:  validRawToken(),
				generateErr:    tokenGenErr,
				hashSessionOut: validHashedToken(),
				hashSessionErr: hashErr,
			},
			&stubIDGenerator{
				sessionID:    ReconstituteSessionID("new-sess"),
				sessionIDErr: idGenErr,
			},
			&stubSessionPolicy{lifetime: 24 * time.Hour, maxActive: 5},
		)
	}

	t.Run("happy_path_new_session", func(t *testing.T) {
		svc := makeOpener(&stubSessionRepository{}, nil, nil, nil)
		userID := validUserID()

		rawTok, sess, revokedSess, err := svc.Open(ctx, userID, differentDeviceIdentity(), testNow)
		require.NoError(t, err)
		assert.NotEmpty(t, rawTok)
		assert.False(t, sess.ID().IsEmpty())
		assert.Equal(t, userID, sess.UserID())
		assert.Nil(t, revokedSess)
	})

	t.Run("existing_fingerprint_session_updated", func(t *testing.T) {
		existingSession := newActiveSession()
		svc := makeOpener(&stubSessionRepository{findByFPResult: existingSession}, nil, nil, nil)
		userID := validUserID()

		_, sess, revokedSess, err := svc.Open(ctx, userID, validDeviceIdentity(), testNow)
		require.NoError(t, err)
		assert.Equal(t, existingSession.ID(), sess.ID())
		assert.Nil(t, revokedSess)
	})

	t.Run("session_limit_exceeded_revokes_oldest", func(t *testing.T) {
		oldestSession := newActiveSession()
		svc := NewOpenSession(
			&stubSessionRepository{findActiveResult: []*Session{oldestSession}},
			&stubTokenService{
				generateToken:  validRawToken(),
				hashSessionOut: validHashedToken(),
			},
			&stubIDGenerator{sessionID: ReconstituteSessionID("new-sess")},
			&stubSessionPolicy{lifetime: 24 * time.Hour, maxActive: 1},
		)

		_, sess, revokedSess, err := svc.Open(ctx, validUserID(), differentDeviceIdentity(), testNow)
		require.NoError(t, err)
		assert.NotNil(t, sess)
		assert.NotNil(t, revokedSess)
		assert.True(t, revokedSess.IsRevoked())
		assert.Equal(t, oldestSession.ID(), revokedSess.ID())
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		svc := makeOpener(&stubSessionRepository{}, errors.New("id gen failed"), nil, nil)

		_, _, _, err := svc.Open(ctx, validUserID(), differentDeviceIdentity(), testNow)
		assert.Error(t, err)
	})

	t.Run("token_gen_fails", func(t *testing.T) {
		svc := makeOpener(nil, nil, errors.New("token gen failed"), nil)

		_, _, _, err := svc.Open(ctx, validUserID(), validDeviceIdentity(), testNow)
		assert.Error(t, err)
	})

	t.Run("hash_fails", func(t *testing.T) {
		svc := makeOpener(nil, nil, nil, errors.New("hash failed"))

		_, _, _, err := svc.Open(ctx, validUserID(), validDeviceIdentity(), testNow)
		assert.Error(t, err)
	})
}
