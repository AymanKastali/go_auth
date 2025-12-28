package use_cases

import (
	"go_auth/src/adapters/mappers"
	"go_auth/src/application/dto"
	"go_auth/src/domain/ports/repositories"
)

type AuthenticatedUserUseCase struct {
	userRepository repositories.UserRepositoryPort
	uuidMapper     *mappers.UUIDMapper
}

func NewAuthenticatedUserUseCase(
	userRepo repositories.UserRepositoryPort,
	uuidMapper *mappers.UUIDMapper,
) *AuthenticatedUserUseCase {
	return &AuthenticatedUserUseCase{
		userRepository: userRepo,
		uuidMapper:     uuidMapper,
	}
}

func (h *AuthenticatedUserUseCase) Execute(userId string) (*dto.AuthenticatedUser, error) {
	userIDVO, err := h.uuidMapper.UserIdFromString(userId)
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
