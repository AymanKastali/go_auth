package query

import (
	"context"
	"log/slog"

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
	logger := application.GetLogger(ctx).With(slog.String("handler", "GetUserByID"))

	if id == "" {
		logger.Warn("empty_user_id")
		return application.ZeroUserReadModel, application.ErrResourceNotFound
	}

	result, err := h.queryPort.FindByID(ctx, id)
	if err != nil {
		logger.Error("user_lookup_failed", slog.String("target_id", id), slog.Any("error", err))
		return application.ZeroUserReadModel, err
	}

	return result, nil
}
