package handlers

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/ports/repositories"
	"go_auth/src/infra/mappers"
)

type AuthenticatedUserHandler struct {
	userRepository repositories.UserRepositoryPort
	uuidMapper     *mappers.UUIDMapper
}

func NewUserHandler(
	userRepo repositories.UserRepositoryPort,
	uuidMapper *mappers.UUIDMapper,
) *AuthenticatedUserHandler {
	return &AuthenticatedUserHandler{
		userRepository: userRepo,
		uuidMapper:     uuidMapper,
	}
}

func (h *AuthenticatedUserHandler) GetAuthenticatedUser(userId string) (*dto.AuthenticatedUser, error) {
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
