package use_cases

import (
	"go_auth/internal/adapters/mappers"
	"go_auth/internal/application/dto"
	"go_auth/internal/application/ports/use_cases"
	"go_auth/internal/domain/ports/repositories"
	"log/slog"
)

type AuthenticatedUserUseCase struct {
	userRepository repositories.UserRepositoryPort
	uuidMapper     *mappers.UUIDMapper
	logger         *slog.Logger
}

var _ use_cases.AuthenticatedUserUseCasePort = (*AuthenticatedUserUseCase)(nil)

func NewAuthenticatedUserUseCase(
	userRepo repositories.UserRepositoryPort,
	uuidMapper *mappers.UUIDMapper,
	logger *slog.Logger,
) *AuthenticatedUserUseCase {
	return &AuthenticatedUserUseCase{
		userRepository: userRepo,
		uuidMapper:     uuidMapper,
		logger:         logger,
	}
}

func (h *AuthenticatedUserUseCase) GetAuthUser(userID string) (*dto.AuthenticatedUser, error) {
	userIDVO, err := h.uuidMapper.UserIdFromString(userID)
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

	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = string(r)
	}

	return &dto.AuthenticatedUser{
		ID:        user.ID.Value.String(),
		Email:     user.Email.Value,
		Status:    string(user.Status),
		Roles:     roles,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}
