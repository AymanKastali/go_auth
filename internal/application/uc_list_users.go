package application

import (
	"context"
	"log/slog"
)

type listUsersUseCase struct {
	userQuery IUserQueryPort
}

func NewListUsersUseCase(userQuery IUserQueryPort) IListUsersUseCase {
	return &listUsersUseCase{userQuery: userQuery}
}

func (uc *listUsersUseCase) Execute(ctx context.Context, query ListUsersQuery) (ListUsersResponse, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "ListUsers"))

	users, total, err := uc.userQuery.FindAll(ctx, query.Offset, query.Limit)
	if err != nil {
		logger.Error("failed_to_list_users", slog.Any("error", err))
		return ZeroListUsersResponse, err
	}

	return ListUsersResponse{
		Users: users,
		Total: total,
	}, nil
}
