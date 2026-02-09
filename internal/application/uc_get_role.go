package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type getRoleUseCase struct {
	roleRepo domain.IRoleRepository
}

func NewGetRoleUseCase(roleRepo domain.IRoleRepository) IGetRoleUseCase {
	return &getRoleUseCase{roleRepo: roleRepo}
}

func (uc *getRoleUseCase) Execute(ctx context.Context, id string) (RoleReadModel, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "GetRole"))

	roleID, err := domain.NewRoleID(id)
	if err != nil {
		logger.Warn("invalid_role_id", slog.Any("error", err))
		return ZeroRoleReadModel, err
	}

	role, err := uc.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		logger.Error("role_lookup_failed", slog.Any("error", err))
		return ZeroRoleReadModel, err
	}
	if role == nil {
		return ZeroRoleReadModel, domain.ErrRoleNotFound
	}

	return toRoleReadModel(role), nil
}
