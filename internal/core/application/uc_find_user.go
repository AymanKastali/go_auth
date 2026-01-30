package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// --- Find User By Email Use Case ---
type findUserByEmailUseCase struct {
	userRepo domain.IUserRepository
}

func NewFindUserByEmailUseCase(repo domain.IUserRepository) IFindUserByEmailUseCase {
	return &findUserByEmailUseCase{userRepo: repo}
}

func (uc *findUserByEmailUseCase) Execute(ctx context.Context, email string) (UserResponse, error) {
	logger := GetLogger(ctx).With(
		slog.String("email", email),
		slog.String("use_case", "FindUserByEmail"),
	)

	// 1. Convert primitive string to Domain Value Object
	emailVO, err := domain.NewEmail(email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return ZeroUserResponse, err
	}

	// 2. Query Repository
	user, err := uc.userRepo.FindByEmail(ctx, emailVO)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return ZeroUserResponse, err
	}

	if user == nil {
		logger.Warn("user_not_found")
		return ZeroUserResponse, ErrResourceNotFound
	}

	return UserResponse{
		ID:    user.ID().String(),
		Email: user.Email().String(),
	}, nil
}

// --- Get User By ID Use Case ---
type getUserByIDUseCase struct {
	userRepo domain.IUserRepository
}

func NewGetUserByIDUseCase(repo domain.IUserRepository) IGetUserByIDUseCase {
	return &getUserByIDUseCase{userRepo: repo}
}

func (uc *getUserByIDUseCase) Execute(ctx context.Context, id string) (UserResponse, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "GetUserByID"))

	// 1. Domain-level ID validation
	userID, err := domain.NewUserID(id)
	if err != nil {
		logger.Warn("invalid_user_id", slog.Any("error", err))
		return ZeroUserResponse, err
	}

	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		logger.Error("user_lookup_failed", slog.String("target_id", id), slog.Any("error", err))
		return ZeroUserResponse, err
	}

	if user == nil {
		logger.Warn("user_not_found", slog.String("target_id", id))
		return ZeroUserResponse, ErrResourceNotFound
	}

	return UserResponse{
		ID:    user.ID().String(),
		Email: user.Email().String(),
	}, nil
}

// --- Get Me Use Case ---
type getMeUseCase struct {
	userRepo domain.IUserRepository
}

func NewGetMeUseCase(repo domain.IUserRepository) IGetMeUseCase {
	return &getMeUseCase{userRepo: repo}
}

func (uc *getMeUseCase) Execute(ctx context.Context, id string) (UserResponse, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "GetMe"))

	userID, err := domain.NewUserID(id)
	if err != nil {
		logger.Warn("invalid_user_id", slog.Any("error", err))
		return ZeroUserResponse, err
	}

	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return ZeroUserResponse, err
	}

	if user == nil {
		logger.Warn("user_not_found")
		return ZeroUserResponse, ErrResourceNotFound
	}

	return UserResponse{
		ID:    user.ID().String(),
		Email: user.Email().String(),
	}, nil
}
