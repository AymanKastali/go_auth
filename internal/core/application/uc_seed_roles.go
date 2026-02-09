package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

type ISeedRolesUseCase interface {
	Execute(ctx context.Context) error
}

type seedRolesUseCase struct {
	roleRepo   domain.IRoleRepository
	idGen      domain.IIDGenerator
	clock      domain.IClock
	dispatcher IEventDispatcher
	seedLoader IRoleSeedLoader
}

func NewSeedRolesUseCase(
	roleRepo domain.IRoleRepository,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
	seedLoader IRoleSeedLoader,
) ISeedRolesUseCase {
	return &seedRolesUseCase{
		roleRepo:   roleRepo,
		idGen:      idGen,
		clock:      clock,
		dispatcher: dispatcher,
		seedLoader: seedLoader,
	}
}

func (uc *seedRolesUseCase) Execute(ctx context.Context) error {
	logger := slog.Default().With(slog.String("use_case", "SeedRoles"))
	now := uc.clock.Now()

	definitions, err := uc.seedLoader.Load()
	if err != nil {
		logger.Error("seed_file_load_failed", slog.Any("error", err))
		return err
	}

	for _, def := range definitions {
		roleName, err := domain.NewRoleName(def.Name)
		if err != nil {
			logger.Error("invalid_role_name", slog.String("name", def.Name), slog.Any("error", err))
			return err
		}

		existing, err := uc.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			logger.Error("role_lookup_failed", slog.String("role", roleName.Name()), slog.Any("error", err))
			return err
		}
		if existing != nil {
			continue
		}

		roleID, err := uc.idGen.GenerateRoleID()
		if err != nil {
			return err
		}

		permissions := make([]domain.Permission, 0, len(def.Permissions))
		for _, ps := range def.Permissions {
			p, err := domain.NewPermission(ps)
			if err != nil {
				logger.Error("invalid_permission", slog.String("role", def.Name), slog.String("permission", ps), slog.Any("error", err))
				return err
			}
			permissions = append(permissions, p)
		}

		role, err := domain.NewRole(roleID, roleName, def.Description, permissions, now)
		if err != nil {
			return err
		}

		if err := uc.roleRepo.Save(ctx, role); err != nil {
			return err
		}

		uc.dispatcher.Dispatch(ctx, role.CollectEvents())
		logger.Info("role_seeded", slog.String("role", roleName.Name()))
	}

	return nil
}
