package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------

func TestNewUser(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		u, err := NewUser(validUserID(), validEmail(), validHashedPassword(), testNow)
		require.NoError(t, err)
		assert.True(t, u.IsActive(), "new users start active")
		assert.Empty(t, u.Roles())
		assert.Empty(t, u.Sessions())
		assert.False(t, u.IsDeleted())
		assert.Equal(t, testNow, u.RegisteredAt())

		events := u.CollectEvents()
		assertEventRecorded(t, events, "UserRegistered")
		assertEventCount(t, events, 1)
	})

	t.Run("missing_id", func(t *testing.T) {
		_, err := NewUser(ZeroUserID, validEmail(), validHashedPassword(), testNow)
		assert.ErrorIs(t, err, ErrUserIDRequired)
	})

	t.Run("missing_email", func(t *testing.T) {
		_, err := NewUser(validUserID(), ZeroEmail, validHashedPassword(), testNow)
		assert.ErrorIs(t, err, ErrUserEmailRequired)
	})

	t.Run("missing_password", func(t *testing.T) {
		_, err := NewUser(validUserID(), validEmail(), ZeroHashedPassword, testNow)
		assert.ErrorIs(t, err, ErrUserPasswordRequired)
	})
}

// ---------------------------------------------------------------
// Activate
// ---------------------------------------------------------------

func TestUser_Activate(t *testing.T) {
	t.Run("inactive_to_active", func(t *testing.T) {
		u := newInactiveUser()
		err := u.Activate(testNow)
		require.NoError(t, err)
		assert.True(t, u.IsActive())
		assertEventRecorded(t, u.CollectEvents(), "UserActivated")
	})

	t.Run("deleted_user", func(t *testing.T) {
		u := newDeletedUser()
		err := u.Activate(testNow)
		assert.ErrorIs(t, err, ErrUserDeleted)
	})

	t.Run("already_active_idempotent", func(t *testing.T) {
		u := newActiveUserWithSession()
		err := u.Activate(testNow)
		require.NoError(t, err)
		events := u.CollectEvents()
		assertEventNotRecorded(t, events, "UserActivated")
	})
}

// ---------------------------------------------------------------
// AssignRole
// ---------------------------------------------------------------

func TestUser_AssignRole(t *testing.T) {
	t.Run("assign_new_role", func(t *testing.T) {
		u := newActiveUserWithSession()
		err := u.AssignRole(RoleAdmin, testNow)
		require.NoError(t, err)
		assert.Len(t, u.Roles(), 2)
		assertEventRecorded(t, u.CollectEvents(), "RoleAssigned")
	})

	t.Run("deleted_user", func(t *testing.T) {
		u := newDeletedUser()
		err := u.AssignRole(RoleAdmin, testNow)
		assert.ErrorIs(t, err, ErrUserDeleted)
	})

	t.Run("duplicate_role_idempotent", func(t *testing.T) {
		u := newActiveUserWithSession()
		err := u.AssignRole(RoleMember, testNow) // already has Member
		require.NoError(t, err)
		assert.Len(t, u.Roles(), 1)
		events := u.CollectEvents()
		assertEventNotRecorded(t, events, "RoleAssigned")
	})
}

// ---------------------------------------------------------------
// EstablishSession
// ---------------------------------------------------------------

func TestUser_EstablishSession(t *testing.T) {
	t.Run("new_session", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents() // drain

		newSess, err := NewSession(
			ReconstituteSessionID("sess-new"),
			ReconstituteHashedToken("new-tok"),
			differentDeviceIdentity(),
			testFuture,
			testNow,
		)
		require.NoError(t, err)

		err = u.EstablishSession(newSess, 5)
		require.NoError(t, err)
		assert.Len(t, u.Sessions(), 2)
		assertEventRecorded(t, u.CollectEvents(), "SessionEstablished")
	})

	t.Run("deleted_user", func(t *testing.T) {
		u := newDeletedUser()
		sess, _ := NewSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow)
		err := u.EstablishSession(sess, 5)
		assert.ErrorIs(t, err, ErrUserDeleted)
	})

	t.Run("inactive_user", func(t *testing.T) {
		u := newInactiveUser()
		sess, _ := NewSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow)
		err := u.EstablishSession(sess, 5)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("matching_fingerprint_updates_existing", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents()

		// Same device identity -> same fingerprint
		sess, _ := NewSession(
			ReconstituteSessionID("sess-dup"),
			ReconstituteHashedToken("updated-tok"),
			validDeviceIdentity(),
			testFarFuture,
			testNow,
		)
		err := u.EstablishSession(sess, 5)
		require.NoError(t, err)
		// Should still have only 1 session (updated, not added)
		assert.Len(t, u.Sessions(), 1)
		assertEventRecorded(t, u.CollectEvents(), "SessionEstablished")
	})

	t.Run("session_limit_revokes_oldest", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents()

		// maxSessions = 1, so adding a new session should revoke the old one
		newSess, _ := NewSession(
			ReconstituteSessionID("sess-new"),
			ReconstituteHashedToken("new-tok"),
			differentDeviceIdentity(),
			testFuture,
			testNow,
		)
		err := u.EstablishSession(newSess, 1)
		require.NoError(t, err)

		events := u.CollectEvents()
		assertEventRecorded(t, events, "SessionRevoked")
		assertEventRecorded(t, events, "SessionEstablished")
	})

	t.Run("revoked_session_not_matched_by_fingerprint", func(t *testing.T) {
		// Create user with a revoked session
		u := ReconstituteUser(
			validUserID(), validEmail(), validHashedPassword(),
			true, []Role{RoleMember},
			[]Session{
				ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, true),
			},
			false,
			testNow,
		)
		_ = u.CollectEvents()

		// Same fingerprint but session is revoked -> should create new
		sess, _ := NewSession(
			ReconstituteSessionID("sess-new"),
			ReconstituteHashedToken("new-tok"),
			validDeviceIdentity(),
			testFuture,
			testNow,
		)
		err := u.EstablishSession(sess, 5)
		require.NoError(t, err)
		assert.Len(t, u.Sessions(), 2) // old revoked + new
	})
}

// ---------------------------------------------------------------
// RefreshSession
// ---------------------------------------------------------------

func TestUser_RefreshSession(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents()

		fp := validDeviceIdentity().Fingerprint()
		session, err := u.RefreshSession(validHashedToken(), fp, testNow)
		require.NoError(t, err)
		assert.Equal(t, validSessionID(), session.ID())
		assertEventRecorded(t, u.CollectEvents(), "SessionRefreshed")
	})

	t.Run("deleted_user", func(t *testing.T) {
		u := newDeletedUser()
		fp := validDeviceIdentity().Fingerprint()
		_, err := u.RefreshSession(validHashedToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("inactive_user", func(t *testing.T) {
		u := newInactiveUser()
		fp := validDeviceIdentity().Fingerprint()
		_, err := u.RefreshSession(validHashedToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("token_not_found", func(t *testing.T) {
		u := newActiveUserWithSession()
		fp := validDeviceIdentity().Fingerprint()
		_, err := u.RefreshSession(ReconstituteHashedToken("wrong"), fp, testNow)
		assert.ErrorIs(t, err, ErrTokenInvalid)
	})

	t.Run("fingerprint_mismatch_hijack", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents()

		differentFP := differentDeviceIdentity().Fingerprint()
		_, err := u.RefreshSession(validHashedToken(), differentFP, testNow)
		assert.ErrorIs(t, err, ErrSessionFingerprintMiss)

		events := u.CollectEvents()
		assertEventRecorded(t, events, "SessionHijackDetected")
		// Session should now be revoked
		assert.True(t, u.Sessions()[0].IsRevoked())
	})

	t.Run("expired_session", func(t *testing.T) {
		// Create user with an expired but not-revoked session
		u := ReconstituteUser(
			validUserID(), validEmail(), validHashedPassword(),
			true, []Role{RoleMember},
			[]Session{
				ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testPast, testPast, false),
			},
			false,
			testNow,
		)
		fp := validDeviceIdentity().Fingerprint()
		_, err := u.RefreshSession(validHashedToken(), fp, testNow)
		assert.ErrorIs(t, err, ErrSessionExpired)
	})
}

// ---------------------------------------------------------------
// RevokeSession
// ---------------------------------------------------------------

func TestUser_RevokeSession(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents()

		err := u.RevokeSession(validSessionID(), testNow)
		require.NoError(t, err)
		assertEventRecorded(t, u.CollectEvents(), "SessionRevoked")
	})

	t.Run("deleted_user", func(t *testing.T) {
		u := newDeletedUser()
		err := u.RevokeSession(validSessionID(), testNow)
		assert.ErrorIs(t, err, ErrUserDeleted)
	})

	t.Run("already_revoked", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.RevokeSession(validSessionID(), testNow)
		err := u.RevokeSession(validSessionID(), testNow)
		assert.ErrorIs(t, err, ErrSessionAlreadyRevoked)
	})

	t.Run("not_found", func(t *testing.T) {
		u := newActiveUserWithSession()
		err := u.RevokeSession(ReconstituteSessionID("nonexistent"), testNow)
		assert.ErrorIs(t, err, ErrSessionIDRequired)
	})
}

// ---------------------------------------------------------------
// ValidateIntegrity
// ---------------------------------------------------------------

func TestUser_ValidateIntegrity(t *testing.T) {
	t.Run("all_pass", func(t *testing.T) {
		u := newActiveUserWithSession()
		err := u.ValidateIntegrity(validSessionID(), testNow)
		require.NoError(t, err)
	})

	t.Run("deleted_user", func(t *testing.T) {
		u := newDeletedUser()
		err := u.ValidateIntegrity(validSessionID(), testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("inactive_user", func(t *testing.T) {
		u := newInactiveUser()
		err := u.ValidateIntegrity(validSessionID(), testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("revoked_session", func(t *testing.T) {
		u := ReconstituteUser(
			validUserID(), validEmail(), validHashedPassword(),
			true, []Role{RoleMember},
			[]Session{
				ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, true),
			},
			false,
			testNow,
		)
		err := u.ValidateIntegrity(validSessionID(), testNow)
		assert.ErrorIs(t, err, ErrSessionAlreadyRevoked)
	})

	t.Run("expired_session", func(t *testing.T) {
		u := ReconstituteUser(
			validUserID(), validEmail(), validHashedPassword(),
			true, []Role{RoleMember},
			[]Session{
				ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testPast, testPast, false),
			},
			false,
			testNow,
		)
		err := u.ValidateIntegrity(validSessionID(), testNow)
		assert.ErrorIs(t, err, ErrSessionExpired)
	})

	t.Run("session_not_found", func(t *testing.T) {
		u := newActiveUserWithSession()
		err := u.ValidateIntegrity(ReconstituteSessionID("missing"), testNow)
		assert.ErrorIs(t, err, ErrSessionIDRequired)
	})
}

// ---------------------------------------------------------------
// UpdateEmail
// ---------------------------------------------------------------

func TestUser_UpdateEmail(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents()

		newEmail := ReconstituteEmail("new@example.com")
		err := u.UpdateEmail(newEmail, testNow)
		require.NoError(t, err)
		assert.Equal(t, newEmail, u.Email())

		events := u.CollectEvents()
		assertEventRecorded(t, events, "EmailUpdated")
		ev := events[0].(EmailUpdated)
		assert.Equal(t, "test@example.com", ev.OldEmail())
		assert.Equal(t, "new@example.com", ev.NewEmail())
	})

	t.Run("deleted_user", func(t *testing.T) {
		u := newDeletedUser()
		err := u.UpdateEmail(ReconstituteEmail("new@example.com"), testNow)
		assert.ErrorIs(t, err, ErrUserDeleted)
	})

	t.Run("same_email_idempotent", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents()

		err := u.UpdateEmail(validEmail(), testNow) // same email
		require.NoError(t, err)
		events := u.CollectEvents()
		assertEventNotRecorded(t, events, "EmailUpdated")
	})
}

// ---------------------------------------------------------------
// UpdatePassword
// ---------------------------------------------------------------

func TestUser_UpdatePassword(t *testing.T) {
	t.Run("happy_path_revokes_sessions", func(t *testing.T) {
		u := newActiveUserWithSession()
		_ = u.CollectEvents()

		newHash := ReconstituteHashedPassword("new-hash")
		err := u.UpdatePassword(newHash, testNow)
		require.NoError(t, err)
		assert.Equal(t, newHash, u.HashedPassword())

		events := u.CollectEvents()
		assertEventRecorded(t, events, "SessionRevoked")
		assertEventRecorded(t, events, "PasswordChanged")
		// Session should be revoked
		assert.True(t, u.Sessions()[0].IsRevoked())
	})

	t.Run("deleted_user", func(t *testing.T) {
		u := newDeletedUser()
		err := u.UpdatePassword(ReconstituteHashedPassword("h"), testNow)
		assert.ErrorIs(t, err, ErrUserDeleted)
	})

	t.Run("inactive_user", func(t *testing.T) {
		u := newInactiveUser()
		err := u.UpdatePassword(ReconstituteHashedPassword("h"), testNow)
		assert.ErrorIs(t, err, ErrUserInactive)
	})

	t.Run("no_sessions_just_password_changed", func(t *testing.T) {
		u := ReconstituteUser(
			validUserID(), validEmail(), validHashedPassword(),
			true, []Role{RoleMember},
			nil, // no sessions
			false,
			testNow,
		)
		_ = u.CollectEvents()

		err := u.UpdatePassword(ReconstituteHashedPassword("new"), testNow)
		require.NoError(t, err)
		events := u.CollectEvents()
		assertEventCount(t, events, 1)
		assertEventRecorded(t, events, "PasswordChanged")
	})
}

// ---------------------------------------------------------------
// FindActiveSessionByFingerprint
// ---------------------------------------------------------------

func TestUser_FindActiveSessionByFingerprint(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		u := newActiveUserWithSession()
		fp := validDeviceIdentity().Fingerprint()
		sid, found := u.FindActiveSessionByFingerprint(fp)
		assert.True(t, found)
		assert.Equal(t, validSessionID(), sid)
	})

	t.Run("not_found", func(t *testing.T) {
		u := newActiveUserWithSession()
		fp := differentDeviceIdentity().Fingerprint()
		_, found := u.FindActiveSessionByFingerprint(fp)
		assert.False(t, found)
	})

	t.Run("revoked_not_found", func(t *testing.T) {
		u := ReconstituteUser(
			validUserID(), validEmail(), validHashedPassword(),
			true, []Role{RoleMember},
			[]Session{
				ReconstituteSession(validSessionID(), validHashedToken(), validDeviceIdentity(), testFuture, testNow, true),
			},
			false,
			testNow,
		)
		fp := validDeviceIdentity().Fingerprint()
		_, found := u.FindActiveSessionByFingerprint(fp)
		assert.False(t, found)
	})
}
