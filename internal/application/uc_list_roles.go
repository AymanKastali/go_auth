package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type listRolesUseCase struct {
	roleRepo domain.IRoleRepository
}

func NewListRolesUseCase(roleRepo domain.IRoleRepository) IListRolesUseCase {
	return &listRolesUseCase{roleRepo: roleRepo}
}

func (uc *listRolesUseCase) Execute(ctx context.Context) ([]RoleReadModel, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "ListRoles"))

	roles, err := uc.roleRepo.FindAll(ctx)
	if err != nil {
		logger.Error("failed_to_list_roles", slog.Any("error", err))
		return nil, err
	}

	result := make([]RoleReadModel, len(roles))
	for i, r := range roles {
		result[i] = toRoleReadModel(r)
	}

	return result, nil
}

func toRoleReadModel(r *domain.Role) RoleReadModel {
	return RoleReadModel{
		ID:          r.ID().String(),
		Name:        r.Name().Name(),
		Description: r.Description(),
		Permissions: r.PermissionStrings(),
	}
}
