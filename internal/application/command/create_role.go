package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type ICreateRoleHandler interface {
	Handle(ctx context.Context, cmd CreateRoleCommand) (application.RoleReadModel, error)
}

type createRoleHandler struct {
	roleRepo   domain.IRoleRepository
	idGen      domain.IIDGenerator
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewCreateRoleHandler(
	roleRepo domain.IRoleRepository,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) ICreateRoleHandler {
	return &createRoleHandler{
		roleRepo:   roleRepo,
		idGen:      idGen,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (h *createRoleHandler) Handle(ctx context.Context, cmd CreateRoleCommand) (application.RoleReadModel, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "CreateRole"))
	now := h.clock.Now()

	roleName, err := domain.NewRoleName(cmd.Name)
	if err != nil {
		return ZeroRoleReadModel, err
	}

	existing, err := h.roleRepo.FindByName(ctx, roleName)
	if err != nil {
		logger.Error("role_lookup_failed", slog.Any("error", err))
		return ZeroRoleReadModel, err
	}
	if existing != nil {
		return ZeroRoleReadModel, domain.ErrRoleAlreadyExists
	}

	permissions := make([]domain.Permission, 0, len(cmd.Permissions))
	for _, ps := range cmd.Permissions {
		p, err := domain.NewPermission(ps)
		if err != nil {
			return ZeroRoleReadModel, err
		}
		permissions = append(permissions, p)
	}

	roleID, err := h.idGen.GenerateRoleID()
	if err != nil {
		logger.Error("id_generation_failed", slog.Any("error", err))
		return ZeroRoleReadModel, application.ErrInternal
	}

	role, err := domain.NewRole(roleID, roleName, cmd.Description, permissions, now)
	if err != nil {
		return ZeroRoleReadModel, err
	}

	if err := h.roleRepo.Save(ctx, role); err != nil {
		logger.Error("role_save_failed", slog.Any("error", err))
		return ZeroRoleReadModel, err
	}

	h.dispatcher.Dispatch(ctx, role.CollectEvents())
	logger.Info("role_created", slog.String("role", roleName.Name()))

	return toRoleReadModel(role), nil
}

func toRoleReadModel(r *domain.Role) application.RoleReadModel {
	return application.RoleReadModel{
		ID:          r.ID().String(),
		Name:        r.Name().Name(),
		Description: r.Description(),
		Permissions: r.PermissionStrings(),
	}
}
