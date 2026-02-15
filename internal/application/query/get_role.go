package query

import (
	"context"

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
	if id == "" {
		return application.ZeroRoleReadModel, application.ErrResourceNotFound
	}

	role, err := h.roleQuery.FindByID(ctx, id)
	if err != nil {
		return application.ZeroRoleReadModel, err
	}

	return role, nil
}
