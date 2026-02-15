package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type ISeedRolesHandler interface {
	Handle(ctx context.Context) error
}

type seedRolesHandler struct {
	roleRepo   domain.IRoleRepository
	idGen      domain.IIDGenerator
	clock      domain.IClock
	dispatcher IEventDispatcher
	seedLoader IRoleSeedLoader
}

func NewSeedRolesHandler(
	roleRepo domain.IRoleRepository,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
	seedLoader IRoleSeedLoader,
) ISeedRolesHandler {
	return &seedRolesHandler{
		roleRepo:   roleRepo,
		idGen:      idGen,
		clock:      clock,
		dispatcher: dispatcher,
		seedLoader: seedLoader,
	}
}

func (h *seedRolesHandler) Handle(ctx context.Context) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "SeedRoles"))
	now := h.clock.Now()

	definitions, err := h.seedLoader.Load()
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

		existing, err := h.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			logger.Error("role_lookup_failed", slog.String("role", roleName.Name()), slog.Any("error", err))
			return err
		}
		if existing != nil {
			continue
		}

		roleID, err := h.idGen.GenerateRoleID()
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

		if err := h.roleRepo.Save(ctx, role); err != nil {
			return err
		}

		h.dispatcher.Dispatch(ctx, role.CollectEvents())
		logger.Info("role_seeded", slog.String("role", roleName.Name()))
	}

	return nil
}
