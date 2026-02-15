package query

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
)

type IListRolesHandler interface {
	Handle(ctx context.Context) ([]application.RoleReadModel, error)
}

type listRolesHandler struct {
	roleQuery application.IRoleQueryPort
}

func NewListRolesHandler(roleQuery application.IRoleQueryPort) IListRolesHandler {
	return &listRolesHandler{roleQuery: roleQuery}
}

func (h *listRolesHandler) Handle(ctx context.Context) ([]application.RoleReadModel, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "ListRoles"))

	roles, err := h.roleQuery.FindAll(ctx)
	if err != nil {
		logger.Error("failed_to_list_roles", slog.Any("error", err))
		return nil, err
	}

	return roles, nil
}
