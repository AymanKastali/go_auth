package usecases

import (
	"go_auth/src/application/dto"
	"go_auth/src/domain/ports/repositories"
	"go_auth/src/infra/mappers"
)

type UserUseCase struct {
	userRepository repositories.UserRepositoryPort
	uuidMapper     mappers.UUIDMapper
}

func NewUserUseCase(userRepo repositories.UserRepositoryPort, uuidMapper mappers.UUIDMapper) *UserUseCase {
	return &UserUseCase{
		userRepository: userRepo,
		uuidMapper:     uuidMapper,
	}
}

func (uc *UserUseCase) GetAuthenticatedUser(userID string) (*dto.AuthenticatedUser, error) {
	userIDVO, err := uc.uuidMapper.FromString(userID)
	if err != nil {
		return nil, err
	}

	user, err := uc.userRepository.GetByID(userIDVO)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}

	return &dto.AuthenticatedUser{
		ID:        user.ID.Value.String(),
		Email:     user.Email.Value,
		Status:    string(user.Status),
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}, nil
}
