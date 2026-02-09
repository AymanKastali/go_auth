package application

import (
	"context"
	"log/slog"
)

// --- Find User By Email Use Case ---
type findUserByEmailUseCase struct {
	queryPort IUserQueryPort
}

func NewFindUserByEmailUseCase(queryPort IUserQueryPort) IFindUserByEmailUseCase {
	return &findUserByEmailUseCase{queryPort: queryPort}
}

func (uc *findUserByEmailUseCase) Execute(ctx context.Context, email string) (UserReadModel, error) {
	logger := GetLogger(ctx).With(
		slog.String("email", email),
		slog.String("use_case", "FindUserByEmail"),
	)

	if email == "" {
		logger.Warn("empty_email")
		return ZeroUserReadModel, ErrResourceNotFound
	}

	result, err := uc.queryPort.FindByEmail(ctx, email)
	if err != nil {
		logger.Warn("user_lookup_failed", slog.Any("error", err))
		return ZeroUserReadModel, err
	}

	return result, nil
}

// --- Get User By ID Use Case ---
type getUserByIDUseCase struct {
	queryPort IUserQueryPort
}

func NewGetUserByIDUseCase(queryPort IUserQueryPort) IGetUserByIDUseCase {
	return &getUserByIDUseCase{queryPort: queryPort}
}

func (uc *getUserByIDUseCase) Execute(ctx context.Context, id string) (UserReadModel, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "GetUserByID"))

	if id == "" {
		logger.Warn("empty_user_id")
		return ZeroUserReadModel, ErrResourceNotFound
	}

	result, err := uc.queryPort.FindByID(ctx, id)
	if err != nil {
		logger.Error("user_lookup_failed", slog.String("target_id", id), slog.Any("error", err))
		return ZeroUserReadModel, err
	}

	return result, nil
}

// --- Get Me Use Case ---
type getMeUseCase struct {
	queryPort IUserQueryPort
}

func NewGetMeUseCase(queryPort IUserQueryPort) IGetMeUseCase {
	return &getMeUseCase{queryPort: queryPort}
}

func (uc *getMeUseCase) Execute(ctx context.Context, id string) (UserReadModel, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "GetMe"))

	if id == "" {
		logger.Warn("empty_user_id")
		return ZeroUserReadModel, ErrResourceNotFound
	}

	result, err := uc.queryPort.FindByID(ctx, id)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return ZeroUserReadModel, err
	}

	return result, nil
}
