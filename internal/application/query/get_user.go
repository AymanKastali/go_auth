package query

import (
	"context"

	"go_auth/internal/application"
)

type IGetUserByIDHandler interface {
	Handle(ctx context.Context, id string) (application.UserReadModel, error)
}

type getUserByIDHandler struct {
	queryPort application.IUserQueryPort
}

func NewGetUserByIDHandler(queryPort application.IUserQueryPort) IGetUserByIDHandler {
	return &getUserByIDHandler{queryPort: queryPort}
}

func (h *getUserByIDHandler) Handle(ctx context.Context, id string) (application.UserReadModel, error) {
	if id == "" {
		return application.ZeroUserReadModel, application.ErrResourceNotFound
	}

	result, err := h.queryPort.FindByID(ctx, id)
	if err != nil {
		return application.ZeroUserReadModel, err
	}

	return result, nil
}
