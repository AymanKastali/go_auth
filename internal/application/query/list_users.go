package query

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
)

type IListUsersHandler interface {
	Handle(ctx context.Context, query ListUsersQuery) (ListUsersResponse, error)
}

type listUsersHandler struct {
	userQuery application.IUserQueryPort
}

func NewListUsersHandler(userQuery application.IUserQueryPort) IListUsersHandler {
	return &listUsersHandler{userQuery: userQuery}
}

func (h *listUsersHandler) Handle(ctx context.Context, query ListUsersQuery) (ListUsersResponse, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "ListUsers"))

	users, total, err := h.userQuery.FindAll(ctx, query.Offset, query.Limit)
	if err != nil {
		logger.Error("failed_to_list_users", slog.Any("error", err))
		return ZeroListUsersResponse, err
	}

	return ListUsersResponse{
		Users: users,
		Total: total,
	}, nil
}
