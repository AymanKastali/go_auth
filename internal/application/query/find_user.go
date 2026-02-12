package query

import (
	"context"
	"log/slog"

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
	logger := application.GetLogger(ctx).With(
		slog.String("email", email),
		slog.String("handler", "FindUserByEmail"),
	)

	if email == "" {
		logger.Warn("empty_email")
		return application.ZeroUserReadModel, application.ErrResourceNotFound
	}

	result, err := h.queryPort.FindByEmail(ctx, email)
	if err != nil {
		logger.Warn("user_lookup_failed", slog.Any("error", err))
		return application.ZeroUserReadModel, err
	}

	return result, nil
}
