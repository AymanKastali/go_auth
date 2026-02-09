package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRoleName(t *testing.T) {
	validRoles := []struct {
		input    string
		expected RoleName
	}{
		{"super_admin", RoleSuperAdmin},
		{"admin", RoleAdmin},
		{"editor", RoleEditor},
		{"moderator", RoleModerator},
		{"member", RoleMember},
		{"premium", RolePremium},
		{"guest", RoleGuest},
		{"partner", RolePartner},
	}
	for _, tt := range validRoles {
		t.Run("valid_"+tt.input, func(t *testing.T) {
			role, err := NewRoleName(tt.input)
			require.NoError(t, err)
			assert.True(t, role.Equal(tt.expected))
		})
	}

	t.Run("case_insensitive", func(t *testing.T) {
		role, err := NewRoleName("  ADMIN  ")
		require.NoError(t, err)
		assert.True(t, role.Equal(RoleAdmin))
	})

	t.Run("unrecognized", func(t *testing.T) {
		_, err := NewRoleName("wizard")
		assert.ErrorIs(t, err, ErrRoleNotRecognized)
	})
}

func TestRoleName_Equal(t *testing.T) {
	assert.True(t, RoleMember.Equal(RoleMember))
	assert.False(t, RoleMember.Equal(RoleAdmin))
}

func TestRoleName_Name(t *testing.T) {
	assert.Equal(t, "super_admin", RoleSuperAdmin.Name())
	assert.Equal(t, "member", RoleMember.Name())
}
