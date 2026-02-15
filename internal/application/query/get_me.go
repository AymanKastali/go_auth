package query

import (
	"context"

	"go_auth/internal/application"
)

type IGetMeHandler interface {
	Handle(ctx context.Context, id string) (application.UserReadModel, error)
}

type getMeHandler struct {
	queryPort application.IUserQueryPort
}

func NewGetMeHandler(queryPort application.IUserQueryPort) IGetMeHandler {
	return &getMeHandler{queryPort: queryPort}
}

func (h *getMeHandler) Handle(ctx context.Context, id string) (application.UserReadModel, error) {
	if id == "" {
		return application.ZeroUserReadModel, application.ErrResourceNotFound
	}

	result, err := h.queryPort.FindByID(ctx, id)
	if err != nil {
		return application.ZeroUserReadModel, err
	}

	return result, nil
}
