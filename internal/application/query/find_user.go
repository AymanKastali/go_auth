package query

import (
	"context"

	"go_auth/internal/application"
)

type IFindUserByEmailHandler interface {
	Handle(ctx context.Context, email string) (application.UserReadModel, error)
}

type findUserByEmailHandler struct {
	queryPort application.IUserQueryPort
}

func NewFindUserByEmailHandler(queryPort application.IUserQueryPort) IFindUserByEmailHandler {
	return &findUserByEmailHandler{queryPort: queryPort}
}

func (h *findUserByEmailHandler) Handle(ctx context.Context, email string) (application.UserReadModel, error) {
	if email == "" {
		return application.ZeroUserReadModel, application.ErrResourceNotFound
	}

	result, err := h.queryPort.FindByEmail(ctx, email)
	if err != nil {
		return application.ZeroUserReadModel, err
	}

	return result, nil
}
