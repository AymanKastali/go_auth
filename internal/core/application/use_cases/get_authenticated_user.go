package use_cases

import (
	"go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/use_cases"
	"go_auth/internal/core/domain/ports/repositories"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type AuthenticatedUserUseCase struct {
	userRepository repositories.UserRepositoryPort
	logger         *slog.Logger
}

var _ use_cases.AuthenticatedUserUseCasePort = (*AuthenticatedUserUseCase)(nil)

func NewAuthenticatedUserUseCase(
	userRepo repositories.UserRepositoryPort,
	logger *slog.Logger,
) *AuthenticatedUserUseCase {
	return &AuthenticatedUserUseCase{
		userRepository: userRepo,
		logger:         logger,
	}
}

func (h *AuthenticatedUserUseCase) GetAuthUser(userID string) (*dto.AuthenticatedUser, error) {
	userIDVO, err := valueobjects.UserIDFromString(userID)
	if err != nil {
		return nil, err
	}

	user, err := h.userRepository.GetByID(userIDVO)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	userRoles := user.Roles()
	roles := make([]string, len(userRoles))
	for i, r := range userRoles {
		roles[i] = string(r)
	}

	return &dto.AuthenticatedUser{
		ID:        user.ID().String(),
		Email:     user.Email().String(),
		Status:    string(user.Status()),
		Roles:     roles,
		CreatedAt: user.CreatedAt(),
		UpdatedAt: user.UpdatedAt(),
	}, nil
}
