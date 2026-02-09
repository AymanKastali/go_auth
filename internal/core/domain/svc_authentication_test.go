package domain

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationService_AuthenticateAndEstablishSession(t *testing.T) {
	ctx := context.Background()
	identity := validDeviceIdentity()

	makeService := func(pwdMatch bool, sessionRepo *stubSessionRepository, idGenErr, tokenGenErr, hashErr error) IAuthenticationService {
		if sessionRepo == nil {
			sessionRepo = &stubSessionRepository{}
		}
		return NewAuthenticationService(
			&stubUserRepository{},
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
			&stubPasswordManager{compareOut: pwdMatch},
		)
	}

	t.Run("happy_path", func(t *testing.T) {
		svc := makeService(true, &stubSessionRepository{}, nil, nil, nil)
		user := newActiveUser()
		raw, _ := NewRawPassword("pass")

		rawTok, sess, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, differentDeviceIdentity(), testNow)
		require.NoError(t, err)
		assert.False(t, rawTok.IsEmpty())
		assert.False(t, sess.ID().IsEmpty())
		assert.Equal(t, user.ID(), sess.UserID())
	})

	t.Run("wrong_password", func(t *testing.T) {
		svc := makeService(false, nil, nil, nil, nil)
		user := newActiveUser()
		raw, _ := NewRawPassword("wrong")

		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, identity, testNow)
		assert.ErrorIs(t, err, ErrAuthenticationFailed)
	})

	t.Run("existing_fingerprint_session_updated", func(t *testing.T) {
		existingSession := newActiveSession()
		svc := makeService(true, &stubSessionRepository{findByFPResult: existingSession}, nil, nil, nil)
		user := newActiveUser()
		raw, _ := NewRawPassword("pass")

		// Same device -> existing session gets updated
		_, sess, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, identity, testNow)
		require.NoError(t, err)
		assert.Equal(t, existingSession.ID(), sess.ID())
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		svc := makeService(true, &stubSessionRepository{}, errors.New("id gen failed"), nil, nil)
		user := newActiveUser()
		raw, _ := NewRawPassword("pass")

		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, differentDeviceIdentity(), testNow)
		assert.Error(t, err)
	})

	t.Run("token_gen_fails", func(t *testing.T) {
		svc := makeService(true, nil, nil, errors.New("token gen failed"), nil)
		user := newActiveUser()
		raw, _ := NewRawPassword("pass")

		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, identity, testNow)
		assert.Error(t, err)
	})

	t.Run("hash_fails", func(t *testing.T) {
		svc := makeService(true, nil, nil, nil, errors.New("hash failed"))
		user := newActiveUser()
		raw, _ := NewRawPassword("pass")

		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, identity, testNow)
		assert.Error(t, err)
	})
}

func TestAuthenticationService_RefreshSession(t *testing.T) {
	ctx := context.Background()

	t.Run("happy_path", func(t *testing.T) {
		user := newActiveUser()
		session := newActiveSession()
		svc := NewAuthenticationService(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByTokenResult: session},
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubIDGenerator{},
			&stubSessionPolicy{lifetime: 24 * time.Hour, maxActive: 5},
			&stubPasswordManager{},
		)

		fp := validDeviceIdentity().Fingerprint()
		u, sess, err := svc.RefreshSession(ctx, validRawToken(), fp, testNow)
		require.NoError(t, err)
		assert.NotNil(t, u)
		assert.Equal(t, validSessionID(), sess.ID())
	})

	t.Run("hash_fails", func(t *testing.T) {
		svc := NewAuthenticationService(
			&stubUserRepository{},
			&stubSessionRepository{},
			&stubTokenService{hashSessionErr: errors.New("hash err")},
			&stubIDGenerator{},
			&stubSessionPolicy{},
			&stubPasswordManager{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, _, err := svc.RefreshSession(ctx, validRawToken(), fp, testNow)
		assert.Error(t, err)
	})

	t.Run("session_not_found", func(t *testing.T) {
		svc := NewAuthenticationService(
			&stubUserRepository{},
			&stubSessionRepository{findByTokenResult: nil},
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubIDGenerator{},
			&stubSessionPolicy{},
			&stubPasswordManager{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, _, err := svc.RefreshSession(ctx, validRawToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("user_not_found", func(t *testing.T) {
		session := newActiveSession()
		svc := NewAuthenticationService(
			&stubUserRepository{findByIDResult: nil},
			&stubSessionRepository{findByTokenResult: session},
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubIDGenerator{},
			&stubSessionPolicy{},
			&stubPasswordManager{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, _, err := svc.RefreshSession(ctx, validRawToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("fingerprint_mismatch_propagated", func(t *testing.T) {
		user := newActiveUser()
		session := newActiveSession()
		svc := NewAuthenticationService(
			&stubUserRepository{findByIDResult: user},
			&stubSessionRepository{findByTokenResult: session},
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubIDGenerator{},
			&stubSessionPolicy{},
			&stubPasswordManager{},
		)

		wrongFP := differentDeviceIdentity().Fingerprint()
		_, _, err := svc.RefreshSession(ctx, validRawToken(), wrongFP, testNow)
		assert.ErrorIs(t, err, ErrSessionFingerprintMiss)
	})
}
