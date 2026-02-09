package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type createRoleUseCase struct {
	roleRepo   domain.IRoleRepository
	idGen      domain.IIDGenerator
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewCreateRoleUseCase(
	roleRepo domain.IRoleRepository,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) ICreateRoleUseCase {
	return &createRoleUseCase{
		roleRepo:   roleRepo,
		idGen:      idGen,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (uc *createRoleUseCase) Execute(ctx context.Context, cmd CreateRoleCommand) (RoleReadModel, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "CreateRole"))
	now := uc.clock.Now()

	// 1. Validate role name
	roleName, err := domain.NewRoleName(cmd.Name)
	if err != nil {
		logger.Warn("invalid_role_name", slog.Any("error", err))
		return ZeroRoleReadModel, err
	}

	// 2. Check for duplicate
	existing, err := uc.roleRepo.FindByName(ctx, roleName)
	if err != nil {
		logger.Error("role_lookup_failed", slog.Any("error", err))
		return ZeroRoleReadModel, err
	}
	if existing != nil {
		return ZeroRoleReadModel, domain.ErrRoleAlreadyExists
	}

	// 3. Parse permissions
	permissions := make([]domain.Permission, 0, len(cmd.Permissions))
	for _, ps := range cmd.Permissions {
		p, err := domain.NewPermission(ps)
		if err != nil {
			logger.Warn("invalid_permission", slog.String("permission", ps), slog.Any("error", err))
			return ZeroRoleReadModel, err
		}
		permissions = append(permissions, p)
	}

	// 4. Generate ID and create aggregate
	roleID, err := uc.idGen.GenerateRoleID()
	if err != nil {
		logger.Error("id_generation_failed", slog.Any("error", err))
		return ZeroRoleReadModel, ErrInternal
	}

	role, err := domain.NewRole(roleID, roleName, cmd.Description, permissions, now)
	if err != nil {
		return ZeroRoleReadModel, err
	}

	// 5. Persist
	if err := uc.roleRepo.Save(ctx, role); err != nil {
		logger.Error("role_save_failed", slog.Any("error", err))
		return ZeroRoleReadModel, err
	}

	uc.dispatcher.Dispatch(ctx, role.CollectEvents())
	logger.Info("role_created", slog.String("role", roleName.Name()))

	return toRoleReadModel(role), nil
}
