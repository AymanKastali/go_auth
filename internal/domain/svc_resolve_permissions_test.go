package domain

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePermissions_Resolve(t *testing.T) {
	ctx := context.Background()

	t.Run("happy_path", func(t *testing.T) {
		memberRole := ReconstituteRole(
			ReconstituteRoleID("role-001"),
			ReconstituteRoleName("member"),
			"Standard member",
			[]Permission{ReconstitutePermission("users", "read_self"), ReconstitutePermission("content", "read")},
		)
		resolver := NewResolvePermissions(
			&stubRoleRepository{findByNameResult: memberRole},
		)

		perms, err := resolver.Resolve(ctx, []RoleName{ReconstituteRoleName("member")})
		require.NoError(t, err)
		assert.Len(t, perms, 2)
		assert.Equal(t, "users:read_self", perms[0].String())
		assert.Equal(t, "content:read", perms[1].String())
	})

	t.Run("role_repo_error", func(t *testing.T) {
		resolver := NewResolvePermissions(
			&stubRoleRepository{findByNameErr: errors.New("db error")},
		)

		_, err := resolver.Resolve(ctx, []RoleName{ReconstituteRoleName("member")})
		assert.Error(t, err)
	})
}
