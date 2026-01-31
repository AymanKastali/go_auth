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

	makeService := func(pwdMatch bool, idGenErr, tokenGenErr, hashErr error) IAuthenticationService {
		return NewAuthenticationService(
			&stubUserRepository{},
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
		svc := makeService(true, nil, nil, nil)
		user := newActiveUserWithSession()
		raw, _ := NewRawPassword("pass")

		rawTok, sess, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, differentDeviceIdentity(), testNow)
		require.NoError(t, err)
		assert.False(t, rawTok.IsEmpty())
		assert.False(t, sess.ID().IsEmpty())
	})

	t.Run("wrong_password", func(t *testing.T) {
		svc := makeService(false, nil, nil, nil)
		user := newActiveUserWithSession()
		raw, _ := NewRawPassword("wrong")

		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, identity, testNow)
		assert.ErrorIs(t, err, ErrAuthenticationFailed)
	})

	t.Run("existing_fingerprint_session_updated", func(t *testing.T) {
		svc := makeService(true, nil, nil, nil)
		user := newActiveUserWithSession()
		raw, _ := NewRawPassword("pass")

		// Same device -> existing session gets updated
		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, identity, testNow)
		require.NoError(t, err)
		assert.Len(t, user.Sessions(), 1)
	})

	t.Run("id_gen_fails", func(t *testing.T) {
		svc := makeService(true, errors.New("id gen failed"), nil, nil)
		user := newActiveUserWithSession()
		raw, _ := NewRawPassword("pass")

		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, differentDeviceIdentity(), testNow)
		assert.Error(t, err)
	})

	t.Run("token_gen_fails", func(t *testing.T) {
		svc := makeService(true, nil, errors.New("token gen failed"), nil)
		user := newActiveUserWithSession()
		raw, _ := NewRawPassword("pass")

		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, identity, testNow)
		assert.Error(t, err)
	})

	t.Run("hash_fails", func(t *testing.T) {
		svc := makeService(true, nil, nil, errors.New("hash failed"))
		user := newActiveUserWithSession()
		raw, _ := NewRawPassword("pass")

		_, _, err := svc.AuthenticateAndEstablishSession(ctx, user, raw, identity, testNow)
		assert.Error(t, err)
	})
}

func TestAuthenticationService_RefreshSession(t *testing.T) {
	ctx := context.Background()

	t.Run("happy_path", func(t *testing.T) {
		user := newActiveUserWithSession()
		svc := NewAuthenticationService(
			&stubUserRepository{findByTokenResult: user},
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
			&stubTokenService{hashSessionErr: errors.New("hash err")},
			&stubIDGenerator{},
			&stubSessionPolicy{},
			&stubPasswordManager{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, _, err := svc.RefreshSession(ctx, validRawToken(), fp, testNow)
		assert.Error(t, err)
	})

	t.Run("user_not_found", func(t *testing.T) {
		svc := NewAuthenticationService(
			&stubUserRepository{findByTokenResult: nil},
			&stubTokenService{hashSessionOut: validHashedToken()},
			&stubIDGenerator{},
			&stubSessionPolicy{},
			&stubPasswordManager{},
		)

		fp := validDeviceIdentity().Fingerprint()
		_, _, err := svc.RefreshSession(ctx, validRawToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("fingerprint_mismatch_propagated", func(t *testing.T) {
		user := newActiveUserWithSession()
		svc := NewAuthenticationService(
			&stubUserRepository{findByTokenResult: user},
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
