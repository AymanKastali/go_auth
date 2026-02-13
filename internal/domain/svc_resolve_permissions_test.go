package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolvePermissions_Resolve(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		memberRole := ReconstituteRole(
			ReconstituteRoleID("role-001"),
			ReconstituteRoleName("member"),
			"Standard member",
			[]Permission{ReconstitutePermission("users", "read_self"), ReconstitutePermission("content", "read")},
		)
		resolver := NewResolvePermissions()

		perms := resolver.Resolve([]*Role{memberRole})
		assert.Len(t, perms, 2)
		assert.Equal(t, "users:read_self", perms[0].String())
		assert.Equal(t, "content:read", perms[1].String())
	})

	t.Run("deduplicates_permissions_across_roles", func(t *testing.T) {
		role1 := ReconstituteRole(
			ReconstituteRoleID("role-001"),
			ReconstituteRoleName("member"),
			"Member",
			[]Permission{ReconstitutePermission("users", "read_self"), ReconstitutePermission("content", "read")},
		)
		role2 := ReconstituteRole(
			ReconstituteRoleID("role-002"),
			ReconstituteRoleName("editor"),
			"Editor",
			[]Permission{ReconstitutePermission("content", "read"), ReconstitutePermission("content", "write")},
		)
		resolver := NewResolvePermissions()

		perms := resolver.Resolve([]*Role{role1, role2})
		assert.Len(t, perms, 3)
	})

	t.Run("nil_role_skipped", func(t *testing.T) {
		role := ReconstituteRole(
			ReconstituteRoleID("role-001"),
			ReconstituteRoleName("member"),
			"Member",
			[]Permission{ReconstitutePermission("users", "read_self")},
		)
		resolver := NewResolvePermissions()

		perms := resolver.Resolve([]*Role{nil, role})
		assert.Len(t, perms, 1)
	})

	t.Run("empty_roles", func(t *testing.T) {
		resolver := NewResolvePermissions()

		perms := resolver.Resolve([]*Role{})
		assert.Empty(t, perms)
	})
}
