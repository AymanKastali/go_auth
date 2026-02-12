package query

import (
	"context"
	"log/slog"

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
	logger := application.GetLogger(ctx).With(slog.String("handler", "GetMe"))

	if id == "" {
		logger.Warn("empty_user_id")
		return application.ZeroUserReadModel, application.ErrResourceNotFound
	}

	result, err := h.queryPort.FindByID(ctx, id)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return application.ZeroUserReadModel, err
	}

	return result, nil
}
