package query

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
)

type IGetRoleHandler interface {
	Handle(ctx context.Context, id string) (application.RoleReadModel, error)
}

type getRoleHandler struct {
	roleQuery application.IRoleQueryPort
}

func NewGetRoleHandler(roleQuery application.IRoleQueryPort) IGetRoleHandler {
	return &getRoleHandler{roleQuery: roleQuery}
}

func (h *getRoleHandler) Handle(ctx context.Context, id string) (application.RoleReadModel, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "GetRole"))

	if id == "" {
		logger.Warn("empty_role_id")
		return application.ZeroRoleReadModel, application.ErrResourceNotFound
	}

	role, err := h.roleQuery.FindByID(ctx, id)
	if err != nil {
		logger.Error("role_lookup_failed", slog.Any("error", err))
		return application.ZeroRoleReadModel, err
	}

	return role, nil
}
