package domain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRoleName(t *testing.T) {
	t.Run("valid_known_roles", func(t *testing.T) {
		validRoles := []struct {
			input    string
			expected string
		}{
			{"super_admin", "super_admin"},
			{"admin", "admin"},
			{"editor", "editor"},
			{"moderator", "moderator"},
			{"member", "member"},
			{"premium", "premium"},
			{"guest", "guest"},
			{"partner", "partner"},
		}
		for _, tt := range validRoles {
			t.Run(tt.input, func(t *testing.T) {
				role, err := NewRoleName(tt.input)
				require.NoError(t, err)
				assert.Equal(t, tt.expected, role.Name())
			})
		}
	})

	t.Run("valid_dynamic_names", func(t *testing.T) {
		dynamicNames := []string{"content_reviewer", "analyst", "team_lead", "ab"}
		for _, name := range dynamicNames {
			t.Run(name, func(t *testing.T) {
				role, err := NewRoleName(name)
				require.NoError(t, err)
				assert.Equal(t, name, role.Name())
			})
		}
	})

	t.Run("case_normalization", func(t *testing.T) {
		role, err := NewRoleName("  ADMIN  ")
		require.NoError(t, err)
		assert.Equal(t, "admin", role.Name())
	})

	t.Run("invalid_empty", func(t *testing.T) {
		_, err := NewRoleName("")
		assert.ErrorIs(t, err, ErrRoleNameInvalid)
	})

	t.Run("invalid_starts_with_digit", func(t *testing.T) {
		_, err := NewRoleName("1bad")
		assert.ErrorIs(t, err, ErrRoleNameInvalid)
	})

	t.Run("invalid_contains_spaces", func(t *testing.T) {
		_, err := NewRoleName("bad role")
		assert.ErrorIs(t, err, ErrRoleNameInvalid)
	})

	t.Run("invalid_special_chars", func(t *testing.T) {
		_, err := NewRoleName("role-name!")
		assert.ErrorIs(t, err, ErrRoleNameInvalid)
	})

	t.Run("invalid_single_char", func(t *testing.T) {
		_, err := NewRoleName("a")
		assert.ErrorIs(t, err, ErrRoleNameInvalid)
	})

	t.Run("invalid_over_50_chars", func(t *testing.T) {
		_, err := NewRoleName(strings.Repeat("a", 51))
		assert.ErrorIs(t, err, ErrRoleNameInvalid)
	})
}

func TestRoleName_Equal(t *testing.T) {
	member := ReconstituteRoleName("member")
	admin := ReconstituteRoleName("admin")
	assert.True(t, member.Equal(ReconstituteRoleName("member")))
	assert.False(t, member.Equal(admin))
}

func TestRoleName_Name(t *testing.T) {
	assert.Equal(t, "super_admin", ReconstituteRoleName("super_admin").Name())
	assert.Equal(t, "member", ReconstituteRoleName("member").Name())
}
