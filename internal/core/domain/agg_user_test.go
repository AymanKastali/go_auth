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
		u := newActiveUser()
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
		u := newActiveUser()
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
		u := newActiveUser()
		err := u.AssignRole(RoleMember, testNow) // already has Member
		require.NoError(t, err)
		assert.Len(t, u.Roles(), 1)
		events := u.CollectEvents()
		assertEventNotRecorded(t, events, "RoleAssigned")
	})
}

// ---------------------------------------------------------------
// UpdateEmail
// ---------------------------------------------------------------

func TestUser_UpdateEmail(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		u := newActiveUser()
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
		u := newActiveUser()
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
	t.Run("happy_path", func(t *testing.T) {
		u := newActiveUser()
		_ = u.CollectEvents()

		newHash := ReconstituteHashedPassword("new-hash")
		err := u.UpdatePassword(newHash, testNow)
		require.NoError(t, err)
		assert.Equal(t, newHash, u.HashedPassword())

		events := u.CollectEvents()
		assertEventRecorded(t, events, "PasswordChanged")
		assertEventCount(t, events, 1)
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
}
